"""Actual namespace/seccomp probes: no external packet or paid model call."""
from pathlib import Path
import json
import os
import platform
import resource
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from universal.isolation import IsolationUnavailable, TMPFS_BYTES, build_command


PROBE = r'''
import argparse, ctypes, errno, json, os, resource, socket, sys
sys.path.insert(0, "/app")
from universal.isolation import inside_child_limits
parser = argparse.ArgumentParser()
parser.add_argument("--fd", type=int, required=True)
parser.add_argument("--role", required=True)
parser.add_argument("--canary", required=True)
parser.add_argument("--host-db", required=True)
parser.add_argument("--host-pid", type=int, required=True)
args = parser.parse_args()
channel = socket.socket(fileno=args.fd)
# This unused AF_INET descriptor is created inside the private network
# namespace before filtering only to test that connect itself is rejected.
# No connect can execute and no external packet is sent.
pre_filter_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
libc = ctypes.CDLL(None, use_errno=True)
inside_child_limits()
result = {"uid": os.getuid(), "gid": os.getgid(), "environment": dict(os.environ)}
for label, operation in {
    "canary_read": lambda: open(args.canary).read(),
    "host_db_write": lambda: open(args.host_db, "w").write("CORRUPTED"),
    "host_parent_read": lambda: open("/proc/%d/environ" % args.host_pid).read(),
    "new_socket": lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
    "new_unix_socket": lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM),
    "connect": lambda: pre_filter_socket.connect(("192.0.2.1", 443)),
    "fork": os.fork,
    "exec": lambda: os.execv(sys.executable, [sys.executable, "-c", "pass"]),
    "relax_memory": lambda: resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024)),
    "package_write": lambda: open("/app/universal/owned", "w").write("x"),
}.items():
    try:
        operation()
        result[label] = {"blocked": False}
    except (OSError, ValueError) as error:
        result[label] = {"blocked": True, "errno": getattr(error, "errno", None)}
pre_filter_socket.close()
for label, number in (("io_uring", 425), ("clone3", 435), ("pidfd_getfd", 438)):
    ctypes.set_errno(0)
    value = libc.syscall(number, 0, 0, 0, 0, 0, 0)
    result[label] = {"blocked": value == -1, "errno": ctypes.get_errno()}
try:
    impossible = bytearray(384 * 1024 * 1024)
    result["memory_enforced"] = False
except MemoryError:
    result["memory_enforced"] = True
try:
    with open("/tmp/oversized", "wb") as file:
        file.truncate(8 * 1024 * 1024)
    result["file_limit_enforced"] = False
except OSError as error:
    result["file_limit_enforced"] = error.errno == errno.EFBIG
result["memory_limit"] = list(resource.getrlimit(resource.RLIMIT_AS))
result["cpu_limit"] = list(resource.getrlimit(resource.RLIMIT_CPU))
result["nproc_limit"] = list(resource.getrlimit(resource.RLIMIT_NPROC))
status = open("/proc/self/status").read()
result["no_new_privs"] = "NoNewPrivs:\t1" in status
result["seccomp"] = "Seccomp:\t2" in status
result["capabilities"] = {name: int(next(line.split(":", 1)[1].strip() for line in status.splitlines() if line.startswith(name + ":")), 16)
                          for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
result["tmpfs_bytes"] = os.statvfs("/tmp").f_blocks * os.statvfs("/tmp").f_frsize
result["visible_pids"] = sorted(int(name) for name in os.listdir("/proc") if name.isdecimal())
result["namespaces"] = {name: os.readlink("/proc/self/ns/" + name) for name in ("pid", "net", "mnt", "user", "ipc", "uts")}
result["fds"] = sorted(int(name) for name in os.listdir("/proc/self/fd") if name.isdecimal())
open("/tmp/local", "w").write("temporary")
result["tmp_write"] = open("/tmp/local").read()
channel.sendall(json.dumps(result, sort_keys=True).encode())
channel.close()
'''


CPU_PROBE = r'''
import argparse, resource, socket, sys, time
sys.path.insert(0, "/app")
from universal.isolation import inside_child_limits
parser = argparse.ArgumentParser()
parser.add_argument("--fd", type=int, required=True)
parser.add_argument("--role", required=True)
args = parser.parse_args()
channel = socket.socket(fileno=args.fd)
inside_child_limits(cpu_seconds=1)
channel.sendall(b"CPU_LIMIT_INSTALLED\n")
# No sleep, socket creation, external effect or process spawning. RLIMIT_CPU
# must stop this computation; the parent's wall deadline is a separate guard.
progress_sent = False
while True:
    if not progress_sent and time.process_time() >= 0.8:
        channel.sendall(("CPU_PROGRESS " + repr(time.process_time()) + "\n").encode())
        progress_sent = True
'''


class TestIsolationV6(unittest.TestCase):
    cpu_observation = None

    def test_missing_bubblewrap_never_returns_unconfined_command(self):
        with patch("universal.isolation.shutil.which", return_value=None):
            with self.assertRaises(IsolationUnavailable):
                build_command(Path("/missing"), 3, "worker")

    def test_actual_child_os_boundary_and_inherited_ipc(self):
        if not shutil.which("bwrap"):
            self.skipTest("bubblewrap unavailable: execution must remain blocked")
        with tempfile.TemporaryDirectory(prefix="cup_v6_isolation_") as root:
            root = Path(root)
            package = root / "universal"
            package.mkdir()
            (package / "__init__.py").write_text("")
            shutil.copyfile(Path(__file__).parents[1] / "universal/isolation.py", package / "isolation.py")
            (package / "child.py").write_text(PROBE)
            canary = root / "private-canary"
            canary.write_text("DO-NOT-EXPOSE-CANARY")
            host_db = root / "controller.sqlite"
            host_db.write_text("UNCHANGED-HOST-DATABASE")
            parent, child = socket.socketpair()
            process = None
            try:
                command = build_command(package, child.fileno(), "probe", ["--canary", str(canary), "--host-db", str(host_db), "--host-pid", str(os.getpid())])
                process = subprocess.Popen(command, pass_fds=(child.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           env={**os.environ, "CUP_PRIVATE_SECRET": "NEVER-IN-CHILD", "HOST_PID": str(os.getpid())})
                child.close()
                parent.settimeout(10)
                raw = bytearray()
                while chunk := parent.recv(16384):
                    raw.extend(chunk)
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
                observed = json.loads(raw)
                self.assertEqual(observed["uid"], 65534)
                self.assertEqual(observed["gid"], 65534)
                for action in ("canary_read", "host_db_write", "host_parent_read", "new_socket", "new_unix_socket", "connect", "fork", "exec", "relax_memory", "package_write", "io_uring", "clone3", "pidfd_getfd"):
                    self.assertTrue(observed[action]["blocked"], (action, observed))
                for action in ("new_socket", "new_unix_socket", "connect", "fork", "exec", "io_uring", "clone3", "pidfd_getfd"):
                    self.assertEqual(observed[action]["errno"], 1, (action, observed))
                self.assertEqual(host_db.read_text(), "UNCHANGED-HOST-DATABASE")
                self.assertEqual(canary.read_text(), "DO-NOT-EXPOSE-CANARY")
                self.assertNotIn("CUP_PRIVATE_SECRET", observed["environment"])
                self.assertNotIn("HOST_PID", observed["environment"])
                self.assertEqual(observed["memory_limit"], [256 * 1024 * 1024] * 2)
                self.assertEqual(observed["cpu_limit"], [3, 3])
                self.assertEqual(observed["nproc_limit"], [0, 0])
                self.assertTrue(observed["no_new_privs"])
                self.assertTrue(observed["seccomp"])
                self.assertEqual(observed["capabilities"], {name: 0 for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")})
                self.assertTrue(observed["memory_enforced"])
                self.assertTrue(observed["file_limit_enforced"])
                self.assertLessEqual(observed["tmpfs_bytes"], TMPFS_BYTES)
                self.assertLessEqual(len(observed["visible_pids"]), 3)
                for namespace, value in observed["namespaces"].items():
                    self.assertNotEqual(value, os.readlink("/proc/self/ns/" + namespace), namespace)
                self.assertEqual(observed["tmp_write"], "temporary")
                # stdio, single IPC and the transient listdir descriptor only.
                self.assertLessEqual(len(observed["fds"]), 5, observed["fds"])
                self.assertNotIn(b"DO-NOT-EXPOSE-CANARY", raw)
            finally:
                child.close()
                parent.close()
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)

    def test_effective_cpu_limit_stops_busy_child_before_parent_deadline(self):
        if not shutil.which("bwrap"):
            self.skipTest("bubblewrap unavailable: execution must remain blocked")
        with tempfile.TemporaryDirectory(prefix="cup_v6_cpu_") as root:
            package = Path(root) / "universal"
            package.mkdir()
            (package / "__init__.py").write_text("")
            shutil.copyfile(Path(__file__).parents[1] / "universal/isolation.py", package / "isolation.py")
            (package / "child.py").write_text(CPU_PROBE)
            parent, child = socket.socketpair()
            process = None
            reader = None
            started = time.monotonic()
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            try:
                command = build_command(package, child.fileno(), "probe")
                process = subprocess.Popen(command, pass_fds=(child.fileno(),), stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                child.close()
                parent.settimeout(10)
                reader = parent.makefile("rb")
                self.assertEqual(reader.readline(1024), b"CPU_LIMIT_INSTALLED\n")
                marker_at = time.monotonic()
                progress = reader.readline(1024)
                self.assertTrue(progress.startswith(b"CPU_PROGRESS "), progress)
                child_cpu_progress = float(progress.split()[1])
                # EOF must come from the kernel-enforced child exit, not from
                # a termination request issued by this parent.
                self.assertEqual(reader.readline(1024), b"")
                stdout, stderr = process.communicate(timeout=max(0.01, 10 - (time.monotonic() - started)))
                finished = time.monotonic()
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                observed = {
                    "architecture": platform.machine(),
                    "limit_cpu_seconds": 1,
                    "parent_wall_deadline_seconds": 10,
                    "elapsed_wall_seconds": round(finished - started, 6),
                    "wall_seconds_after_marker": round(finished - marker_at, 6),
                    "child_last_reported_cpu_seconds": round(child_cpu_progress, 6),
                    "reaped_wrapper_cpu_seconds": round((after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime), 6),
                    "returncode": process.returncode,
                    "marker_received": True,
                    "parent_termination_requested": False,
                    "stdout_bytes": len(stdout),
                    "stderr": stderr.decode(errors="replace"),
                    "network_used": False,
                    "interpretation": "RLIMIT_CPU counts child CPU time; elapsed wall time is a distinct observation, not an equivalent guarantee.",
                }
                type(self).cpu_observation = observed
                self.assertNotEqual(process.returncode, 0, observed)
                self.assertLess(finished - started, 10, observed)
                self.assertGreaterEqual(observed["child_last_reported_cpu_seconds"], 0.8, observed)
                self.assertEqual(process.returncode, 137, observed)
            finally:
                if reader is not None:
                    reader.close()
                child.close()
                parent.close()
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
