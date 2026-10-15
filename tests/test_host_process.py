"""Physical timeout evidence: real PIDs, sessions, parent death, and pipe floods."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from universal.host_process import run_bounded


class HostProcessTests(unittest.TestCase):
    def reader(self, source, data=b'', timeout=0.6, limit=32768):
        return run_bounded([sys.executable, '-B', '-c', source], data,
                           timeout_seconds=timeout, max_output_bytes=limit)

    def assert_absent(self, pid):
        self.assertGreater(pid, 1)
        self.assertFalse(Path(f'/proc/{pid}').exists(), f'PID {pid} was not reaped')

    def wait_file(self, path, process=None):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if path.exists() and path.stat().st_size:
                return path.read_text()
            if process is not None and process.poll() is not None:
                self.fail('host exited before reader announced itself')
            time.sleep(0.01)
        self.fail('reader did not announce itself within bounded startup')

    def test_success_bounded_input_and_same_cwd(self):
        result = self.reader("import os,sys;sys.stdout.buffer.write(sys.stdin.buffer.read()+b'|'+os.getcwd().encode())",
                             b'{"synthetic":true}')
        self.assertEqual(result.state, 'OK')
        self.assertEqual(result.stdout, b'{"synthetic":true}|' + os.getcwd().encode())
        self.assertTrue(result.cleanup_verified)
        self.assertEqual(result.returncode, 0)
        self.assert_absent(result.child_pid)

    def test_blocked_reader_is_physically_dead_under_hard_bound(self):
        result = self.reader('import time;time.sleep(3600)', timeout=0.3)
        self.assertEqual(result.state, 'TIMEOUT')
        self.assertTrue(result.cleanup_verified)
        self.assertLess(result.elapsed_seconds, 3.0)
        self.assertLess(result.returncode, 0)
        self.assert_absent(result.child_pid)

    def test_term_ignoring_detached_descendant_is_killed_and_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'descendant'
            source = f'''import os,signal,time
pid=os.fork()
if pid==0:
 os.setsid()
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 open({str(marker)!r},'w').write(str(os.getpid()))
 while True:time.sleep(1)
while True:time.sleep(1)
'''
            result = self.reader(source, timeout=0.5)
            descendant = int(marker.read_text())
            self.assertEqual(result.state, 'TIMEOUT')
            self.assertTrue(result.cleanup_verified)
            self.assertLess(result.elapsed_seconds, 3)
            self.assert_absent(result.child_pid)
            self.assert_absent(descendant)

    def test_double_fork_orphan_after_success_is_not_qualified_ok(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'orphan'
            source = f'''import os,signal,time
pid=os.fork()
if pid==0:
 os.setsid()
 if os.fork():os._exit(0)
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 open({str(marker)!r},'w').write(str(os.getpid()))
 while True:time.sleep(1)
os.waitpid(pid,0)
while not os.path.exists({str(marker)!r}):time.sleep(.005)
'''
            result = self.reader(source)
            self.assertEqual(result.state, 'FAILED')
            self.assertTrue(result.cleanup_verified)
            self.assert_absent(int(marker.read_text()))
            self.assert_absent(result.child_pid)

    def test_stdout_flood_is_bounded_and_killed(self):
        result = self.reader("import os\nwhile True:os.write(1,b'x'*65536)", limit=4096)
        self.assertEqual(result.state, 'OUTPUT_LIMIT')
        self.assertEqual(len(result.stdout), 4096)
        self.assertTrue(result.cleanup_verified)
        self.assert_absent(result.child_pid)

    def test_stderr_flood_cannot_deadlock_or_escape_output_budget(self):
        result = self.reader("import os\nwhile True:os.write(2,b'x'*65536)", limit=4096)
        self.assertEqual(result.state, 'OUTPUT_LIMIT')
        self.assertEqual(result.stdout, b'')
        self.assertTrue(result.cleanup_verified)
        self.assert_absent(result.child_pid)

    def test_nonzero_exit_and_trailing_output_are_preserved(self):
        result = self.reader("import os;os.write(1,b'diagnostic');os._exit(7)")
        self.assertEqual(result.state, 'FAILED')
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b'diagnostic')
        self.assertTrue(result.cleanup_verified)

    def test_unread_input_cannot_block_parent(self):
        result = self.reader('import time;time.sleep(99)', data=b'x'*65536, timeout=0.3)
        self.assertEqual(result.state, 'TIMEOUT')
        self.assertTrue(result.cleanup_verified)
        self.assertLess(result.elapsed_seconds, 3)

    def test_credentials_and_even_inheritable_owner_fd_are_not_inherited(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / 'owner-private.sqlite'
            with private.open('w') as stream:
                os.set_inheritable(stream.fileno(), True)
                with patch.dict(os.environ, {'GITHUB_TOKEN': 'never-reader', 'GH_TOKEN': 'never-reader',
                                              'HOST_PRIVATE_SECRET': 'never-reader',
                                              'HTTPS_PROXY': 'http://proxy.example.invalid:3128'}):
                    result = self.reader('''import os,json
paths=[]
for name in os.listdir('/proc/self/fd'):
 try:paths.append(os.readlink('/proc/self/fd/'+name))
 except FileNotFoundError:pass
print(json.dumps({'paths':paths,'token':os.getenv('GITHUB_TOKEN'),'gh':os.getenv('GH_TOKEN'),
'secret':os.getenv('HOST_PRIVATE_SECRET'),'proxy':os.getenv('HTTPS_PROXY')}))''')
            self.assertEqual(result.state, 'OK')
            observed = json.loads(result.stdout)
            self.assertNotIn(str(private), observed['paths'])
            self.assertIsNone(observed['token'])
            self.assertIsNone(observed['gh'])
            self.assertIsNone(observed['secret'])
            self.assertEqual(observed['proxy'], 'http://proxy.example.invalid:3128')

    def test_poisoned_cwd_and_pythonpath_cannot_substitute_guardian(self):
        with tempfile.TemporaryDirectory() as directory:
            poisoned = Path(directory)
            package = poisoned / 'universal'
            package.mkdir()
            (package / '__init__.py').write_text('')
            marker = poisoned / 'malicious-guardian-executed'
            fake = json.dumps({'state': 'OK', 'stdout': 'ZmFrZQ==',
                               'cleanup_verified': True, 'child_pid': 1, 'returncode': 0})
            (package / 'host_process.py').write_text(
                f"from pathlib import Path;Path({str(marker)!r}).write_text('executed')\n"
                f"print({fake!r})\n")
            previous = os.getcwd()
            try:
                os.chdir(poisoned)
                with patch.dict(os.environ, {'PYTHONPATH': str(poisoned)}):
                    result = self.reader("print('real-reader')")
            finally:
                os.chdir(previous)
            self.assertEqual(result.state, 'OK')
            self.assertEqual(result.stdout, b'real-reader\n')
            self.assertTrue(result.cleanup_verified)
            self.assert_absent(result.child_pid)
            self.assertFalse(marker.exists())

    def test_invalid_input_refused_before_spawn(self):
        invalid = [([], b'', 1, 100), (['python'], b'', 1, 100),
                   ([sys.executable, '\0'], b'', 1, 100),
                   ([sys.executable], 'not bytes', 1, 100),
                   ([sys.executable], b'x'*65537, 1, 100),
                   ([sys.executable], b'', float('nan'), 100),
                   ([sys.executable], b'', 0, 100),
                   ([sys.executable], b'', True, 100),
                   ([sys.executable], b'', 1, 1048577)]
        for argv, data, timeout, limit in invalid:
            with self.subTest(argv=repr(argv)[:60], timeout=timeout, limit=limit):
                with self.assertRaises(ValueError):
                    run_bounded(argv, data, timeout_seconds=timeout, max_output_bytes=limit)

    def test_unsupported_platform_fails_closed(self):
        with patch('universal.host_process.sys.platform', 'unsupported'):
            result = self.reader('print(1)')
        self.assertEqual(result.state, 'FAILED')
        self.assertFalse(result.cleanup_verified)
        self.assertEqual(result.child_pid, 0)

    def _parent_death(self, signum):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'reader'
            reader = f'''import os,signal,time
signal.signal(signal.SIGTERM,signal.SIG_IGN)
pid=os.fork()
if pid==0:
 os.setsid()
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 open({str(marker)!r}+'.child','w').write(str(os.getpid()))
 while True:time.sleep(1)
open({str(marker)!r},'w').write(str(os.getpid()))
while True:time.sleep(1)
'''
            parent_source = ('import sys\nfrom universal.host_process import run_bounded\n'
                             f'run_bounded([sys.executable,"-B","-c",{reader!r}],b"",timeout_seconds=30)')
            # Dedicated fixture reaper, never pytest/the full test runner.  It
            # acts as Linux init when this container's PID1 does not reap the
            # guardian orphan after the host's deliberately injected SIGKILL.
            coordinator_source = f'''import ctypes,os,subprocess,sys,time,json
assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
with subprocess.Popen([sys.executable,'-B','-c',{parent_source!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL) as host:
 print(host.pid,flush=True)
 code=host.wait(timeout=10)
deadline=time.monotonic()+4
reaped=False
while time.monotonic()<deadline:
 try:
  pid,status=os.waitpid(-1,os.WNOHANG)
 except ChildProcessError:
  reaped=True
  break
 if not pid:time.sleep(.01)
print(json.dumps({{'host_returncode':code,'reaped':reaped}}),flush=True)
'''
            with subprocess.Popen([sys.executable, '-B', '-c', coordinator_source],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as host:
                host_pid = int(host.stdout.readline())
                try:
                    reader_pid = int(self.wait_file(marker, host))
                    descendant_pid = int(self.wait_file(Path(str(marker) + '.child'), host))
                    os.kill(host_pid, signum)
                    report = json.loads(host.stdout.readline())
                    host.wait(timeout=5)
                    deadline = time.monotonic() + 4
                    while time.monotonic() < deadline and any(
                            Path(f'/proc/{pid}').exists() for pid in (reader_pid, descendant_pid)):
                        time.sleep(0.01)
                    self.assert_absent(reader_pid)
                    self.assert_absent(descendant_pid)
                    self.assertEqual(host.returncode, 0)
                    self.assertEqual(report['host_returncode'], -signum)
                    self.assertTrue(report['reaped'])
                finally:
                    if host.poll() is None:
                        try:
                            os.kill(host_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        host.kill()
                        host.wait(timeout=5)

    def test_sigterm_host_cleans_reader_and_detached_descendant(self):
        self._parent_death(signal.SIGTERM)

    def test_sigkill_host_life_pipe_still_cleans_reader_and_orphan(self):
        self._parent_death(signal.SIGKILL)


if __name__ == '__main__':
    unittest.main()
