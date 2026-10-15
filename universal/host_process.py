"""Finite Linux subprocess boundary for the *trusted* read-only host reader.

This is not a worker sandbox.  ``argv`` must come from reviewed host code, never
from a mission, configuration command, or provider response.  A private guardian
is a Linux child subreaper, so even double-forked/session-detached grandchildren
are cleaned and reaped.  Closing the parent's life pipe (also on SIGKILL) asks
the guardian to clean up.  Killing the guardian itself, kernel-uninterruptible
tasks, or a hostile kernel cannot be given a cleanup guarantee.
"""
from __future__ import annotations

import base64
import ctypes
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import selectors
import signal
import struct
import subprocess
import sys
import time


_CLEANUP_SECONDS = 1.5
_TERM_SECONDS = 0.15
_MAX_INPUT = 65536
_MAX_OUTPUT = 1048576
# Reader allowance + guardian cleanup/startup/forced-exit budget.  The host can
# reserve this overhead when enforcing its own whole-program duration limit.
HARD_OVERHEAD_SECONDS = 3.0
_ACTIVE = False
_ENV_KEYS = {
    'PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ',
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
    'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
}


@dataclass(frozen=True)
class ProcessResult:
    state: str
    stdout: bytes
    elapsed_seconds: float
    cleanup_verified: bool
    child_pid: int
    returncode: int | None


def _environment():
    # No HOME, tokens, session credentials, SSH agent, or inherited Python hooks.
    result = {key: value for key, value in os.environ.items() if key in _ENV_KEYS}
    # Pin imports to this inspected source, not caller cwd or PYTHONPATH.
    result['PYTHONPATH'] = str(Path(__file__).resolve().parents[1])
    result['PYTHONDONTWRITEBYTECODE'] = '1'
    result['PYTHONNOUSERSITE'] = '1'
    return result


def _validate(argv, input_bytes, timeout_seconds, max_output_bytes):
    if (not isinstance(argv, (list, tuple)) or not 1 <= len(argv) <= 32
            or any(not isinstance(arg, str) or '\0' in arg for arg in argv)
            or not os.path.isabs(argv[0])
            or sum(len(arg.encode('utf-8')) for arg in argv) > 8192):
        raise ValueError('reviewed absolute executable argv required')
    if not isinstance(input_bytes, bytes) or len(input_bytes) > _MAX_INPUT:
        raise ValueError('bounded bytes input required')
    if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300):
        raise ValueError('finite timeout in (0, 300] required')
    if (type(max_output_bytes) is not int or not 1 <= max_output_bytes <= _MAX_OUTPUT):
        raise ValueError('bounded output limit required')


def run_bounded(argv, input_bytes, *, timeout_seconds, max_output_bytes=32768):
    """Run a reviewed reader with bounded input/output and a physical deadline.

    Linux/main-thread only; other platforms fail closed.  The elapsed bound
    includes up to HARD_OVERHEAD_SECONDS of guardian cleanup/startup/forced-exit
    allowance.  SIGTERM/SIGINT trigger cleanup before being propagated.  ``OK``
    always means the direct reader exited zero AND its entire adopted tree was
    verified absent.  CWD is retained, SQLite/file descriptors are not inherited.
    """
    global _ACTIVE
    _validate(argv, input_bytes, timeout_seconds, max_output_bytes)
    if sys.platform != 'linux' or not os.path.isdir('/proc/self/task'):
        return ProcessResult('FAILED', b'', 0.0, False, 0, None)
    if _ACTIVE:
        raise RuntimeError('nested or concurrent host process boundary')
    previous = {}
    interrupted = []

    def on_signal(signum, _frame):
        interrupted.append(signum)

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, on_signal)
    except ValueError as exc:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        raise ValueError('host process boundary requires the main thread') from exc
    _ACTIVE = True
    started = time.monotonic()
    outer_deadline = started + timeout_seconds + _CLEANUP_SECONDS + 1.0
    guardian = None
    result = ProcessResult('FAILED', b'', 0.0, False, 0, None)
    try:
        deadline = started + timeout_seconds
        wire = json.dumps({'argv': list(argv), 'input': base64.b64encode(input_bytes).decode('ascii'),
                           'deadline': deadline, 'limit': max_output_bytes},
                          separators=(',', ':')).encode('utf-8')
        request = struct.pack('!I', len(wire)) + wire
        guardian = subprocess.Popen(
            [sys.executable, '-B', '-P', '-m', 'universal.host_process', '--guardian'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=_environment(), close_fds=True, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            for stream in (guardian.stdin, guardian.stdout):
                os.set_blocking(stream.fileno(), False)
            selector.register(guardian.stdin, selectors.EVENT_WRITE, 'input')
            selector.register(guardian.stdout, selectors.EVENT_READ, 'output')
            sent = 0
            response = bytearray()
            response_cap = ((max_output_bytes + 2) // 3) * 4 + 2048
            output_closed = False
            life_closed = False
            while not output_closed and time.monotonic() < outer_deadline:
                if interrupted and not life_closed:
                    try:
                        selector.unregister(guardian.stdin)
                    except KeyError:
                        pass
                    guardian.stdin.close()
                    life_closed = True
                for key, _ in selector.select(min(0.05, max(0, outer_deadline - time.monotonic()))):
                    if key.data == 'input':
                        try:
                            count = os.write(key.fd, request[sent:])
                        except (BrokenPipeError, OSError):
                            count = 0
                            selector.unregister(key.fileobj)
                        sent += count
                        if sent == len(request):
                            # Keep the pipe open after framing: EOF is the life signal.
                            selector.unregister(key.fileobj)
                    else:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            output_closed = True
                        elif len(response) + len(chunk) <= response_cap:
                            response.extend(chunk)
                        else:
                            output_closed = True
                            guardian.stdin.close()
                if guardian.poll() is not None and not selector.get_map():
                    break
            if guardian.poll() is None:
                if not guardian.stdin.closed:
                    guardian.stdin.close()
                try:
                    guardian.wait(timeout=max(0.001, outer_deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    # We cannot prove cleanup after a dead/unresponsive guardian.
                    guardian.kill()
                    guardian.wait(timeout=0.5)
            if guardian.returncode == 0 and response:
                data = json.loads(response)
                out = base64.b64decode(data['stdout'], validate=True)
                if (data['state'] in ('OK', 'TIMEOUT', 'FAILED', 'OUTPUT_LIMIT')
                        and type(data['cleanup_verified']) is bool and len(out) <= max_output_bytes
                        and type(data['child_pid']) is int
                        and (data['returncode'] is None or type(data['returncode']) is int)):
                    state = data['state'] if data['cleanup_verified'] else 'FAILED'
                    result = ProcessResult(state, out, time.monotonic() - started,
                                           data['cleanup_verified'], data['child_pid'], data['returncode'])
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        result = ProcessResult('FAILED', b'', time.monotonic() - started, False, 0, None)
    finally:
        if guardian is not None:
            if guardian.stdin and not guardian.stdin.closed:
                guardian.stdin.close()
            if guardian.poll() is None:
                try:
                    guardian.wait(timeout=min(_CLEANUP_SECONDS + 0.2,
                                              max(0.001, outer_deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    guardian.kill()
                    guardian.wait(timeout=0.5)
            if guardian.stdout:
                guardian.stdout.close()
        _ACTIVE = False
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    if interrupted:
        signum = interrupted[0]
        handler = previous[signum]
        if callable(handler):
            handler(signum, None)
        elif handler != signal.SIG_IGN:
            os.kill(os.getpid(), signum)
            raise SystemExit(128 + signum)
    return ProcessResult(result.state, result.stdout, time.monotonic() - started,
                         result.cleanup_verified, result.child_pid, result.returncode)


def _children(pid):
    try:
        with open(f'/proc/{pid}/task/{pid}/children', encoding='ascii') as source:
            return [int(item) for item in source.read().split()]
    except FileNotFoundError:
        # CONFIG_CHECKPOINT_RESTORE is optional: Linux may provide /proc/stat
        # but no per-task children file.  Missing children file is NOT proof
        # that the process has no children.
        return [child for child, parent in _parents().items() if parent == pid]


def _parents():
    parents = {}
    for name in os.listdir('/proc'):
        if not name.isdecimal():
            continue
        try:
            with open('/proc/' + name + '/stat', 'rb') as source:
                # comm can contain spaces and parentheses; split after its last ).
                fields = source.read(8192).rsplit(b')', 1)[1].split()
            parents[int(name)] = int(fields[1])
        except (FileNotFoundError, ProcessLookupError):
            continue
    if os.getpid() not in parents:
        raise RuntimeError('cannot verify guardian in procfs namespace')
    return parents


def _tree():
    seen = set()
    parents = _parents()
    todo = [pid for pid, parent in parents.items() if parent == os.getpid()]
    while todo:
        pid = todo.pop()
        if pid not in seen:
            seen.add(pid)
            if len(seen) > 4096:
                raise RuntimeError('reader process tree exceeded bound')
            todo.extend(child for child, parent in parents.items() if parent == pid)
    return seen


def _send(pid, signum):
    try:
        os.kill(pid, signum)
    except ProcessLookupError:
        pass


def _cleanup(child):
    """Only this dedicated subreaper's children are ever reaped/signalled."""
    started = time.monotonic()
    try:
        while time.monotonic() - started < _CLEANUP_SECONDS:
            signum = signal.SIGTERM if time.monotonic() - started < _TERM_SECONDS else signal.SIGKILL
            # The original session handles ordinary children; the subreaper tree
            # catches new sessions and double-forked orphans independently.
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signum)
                except ProcessLookupError:
                    pass
            for pid in _tree():
                _send(pid, signum)
            child.poll()
            while True:
                try:
                    pid, status = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                if pid == 0:
                    break
                if pid == child.pid:
                    child.returncode = os.waitstatus_to_exitcode(status)
            child.poll()
            if not _children(os.getpid()) and child.returncode is not None:
                return True
            # No threads and no long sleeps; next iteration observes adoption.
            time.sleep(0.01)
    except (OSError, RuntimeError):
        return False
    return False


def _request():
    os.set_blocking(0, False)
    data = bytearray()
    size = None
    deadline = time.monotonic() + 2.0
    with selectors.DefaultSelector() as selector:
        selector.register(0, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(0.05):
                continue
            chunk = os.read(0, 65536)
            if not chunk:
                raise ValueError('parent disappeared before request')
            data.extend(chunk)
            if len(data) >= 4 and size is None:
                size = struct.unpack('!I', data[:4])[0]
                if size > 120000:
                    raise ValueError('request exceeds bound')
            if size is not None and len(data) >= size + 4:
                if len(data) != size + 4:
                    raise ValueError('unexpected request trailing data')
                return json.loads(data[4:])
    raise ValueError('request framing deadline')


def _guardian():
    import resource  # Linux-only; importing this module elsewhere still fails closed.
    # Subreaper is scoped to this new executable, never the host or pytest.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'subreaper unavailable')
    request = _request()
    argv = request['argv']
    payload = base64.b64decode(request['input'], validate=True)
    remaining = max(0.001, request['deadline'] - time.monotonic())
    _validate(argv, payload, remaining, request['limit'])
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    cpu = max(2, math.ceil(remaining) + 2)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    # Signals to a guardian ask for cleanup rather than abandoning descendants.
    stopped = []
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda signum, _frame: stopped.append(signum))
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=_environment(),
                             close_fds=True, start_new_session=True)
    stdout = bytearray()
    total = 0
    state = 'FAILED'
    cleanup_verified = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(0, selectors.EVENT_READ, 'life')
            for stream, label in ((child.stdout, 'stdout'), (child.stderr, 'stderr')):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            if payload:
                os.set_blocking(child.stdin.fileno(), False)
                selector.register(child.stdin, selectors.EVENT_WRITE, 'input')
            else:
                child.stdin.close()
            sent = 0
            while True:
                if stopped:
                    state = 'FAILED'
                    break
                if time.monotonic() >= request['deadline']:
                    state = 'TIMEOUT'
                    break
                if child.poll() is not None:
                    state = 'OK' if child.returncode == 0 else 'FAILED'
                    break
                for key, _ in selector.select(min(0.03, max(0, request['deadline'] - time.monotonic()))):
                    if key.data == 'life':
                        # EOF means parent exited/SIGKILL; extra bytes are invalid.
                        os.read(0, 1)
                        stopped.append(signal.SIGTERM)
                    elif key.data == 'input':
                        try:
                            sent += os.write(key.fd, payload[sent:])
                        except BrokenPipeError:
                            sent = len(payload)
                        if sent == len(payload):
                            selector.unregister(key.fileobj)
                            child.stdin.close()
                    else:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            total += len(chunk)
                            if key.data == 'stdout':
                                stdout.extend(chunk[:max(0, request['limit'] - len(stdout))])
                            if total > request['limit']:
                                state = 'OUTPUT_LIMIT'
                                stopped.append(signal.SIGTERM)
                if state == 'OUTPUT_LIMIT':
                    break
        # A detached descendant after a supposedly successful reader is failure,
        # even if its cleanup succeeds.  Never silently qualify leaked work.
        if state == 'OK' and _children(os.getpid()):
            state = 'FAILED'
    finally:
        cleanup_verified = _cleanup(child)
        # Reap first, then drain finite pipe contents without waiting on writers.
        for stream in (child.stdout, child.stderr):
            while True:
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                total += len(chunk)
                if stream is child.stdout:
                    stdout.extend(chunk[:max(0, request['limit'] - len(stdout))])
                if total > request['limit']:
                    state = 'OUTPUT_LIMIT'
            stream.close()
        child.stdin.close()
    if not cleanup_verified:
        state = 'FAILED'
    response = {'state': state, 'stdout': base64.b64encode(stdout).decode('ascii'),
                'cleanup_verified': cleanup_verified, 'child_pid': child.pid,
                'returncode': child.returncode}
    sys.stdout.write(json.dumps(response, separators=(',', ':')))
    sys.stdout.flush()


if __name__ == '__main__':
    if sys.argv[1:] != ['--guardian'] or sys.platform != 'linux':
        raise SystemExit(2)
    try:
        _guardian()
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        raise SystemExit(2)
