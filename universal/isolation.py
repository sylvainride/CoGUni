"""Fail-closed Linux confinement for controller-owned child entrypoints.

The parent must use ``Popen(..., pass_fds=(fd,))`` and a wall-clock deadline.
Only the inherited IPC endpoint and stdio are passed. The trusted child must
import its dependencies and apply ``inside_child_limits`` before dispatching
any payload. This is an OS boundary, not a claim against kernel vulnerabilities.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import platform
try:
    import resource
except ImportError:
    resource = None
import shutil
import sys


class IsolationUnavailable(RuntimeError):
    """The required confinement could not be established; do not run a child."""


TMPFS_BYTES = 16 * 1024 * 1024
FILE_BYTES = 4 * 1024 * 1024
MEMORY_BYTES = 256 * 1024 * 1024


def build_command(package_dir: Path, fd: int, role: str, extra_args=()) -> list[str]:
    """Build a mandatory bubblewrap command with a minimal read-only root.

    No host workspace, home, database, credentials or host /proc are mounted.
    Bubblewrap retains the descriptor supplied through Popen's ``pass_fds``;
    no broad descriptor-preservation option or unconfined fallback is used.
    """
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise IsolationUnavailable("bubblewrap is required; unconfined fallback refused")
    if sys.platform != "linux":
        raise IsolationUnavailable("Linux namespaces and seccomp are required")
    if type(fd) is not int or fd < 3:
        raise ValueError("IPC descriptor must be an integer >= 3")
    os.fstat(fd)
    if role not in {"worker", "verifier", "probe"}:
        raise ValueError("unregistered child role")
    if not isinstance(extra_args, (tuple, list)) or any(type(arg) is not str or "\0" in arg for arg in extra_args):
        raise ValueError("child arguments must be strings without NUL")
    package = Path(package_dir).resolve(strict=True)
    child = package / "child.py"
    if not package.is_dir() or not child.is_file() or child.is_symlink():
        raise IsolationUnavailable("trusted child.py is missing or is a symlink")
    prefix = Path(sys.base_prefix).resolve(strict=True)
    interpreter = Path(sys.executable).resolve(strict=True)
    if not interpreter.is_relative_to(prefix):
        raise IsolationUnavailable("interpreter must be inside the read-only Python prefix")
    command = [
        bwrap,
        "--unshare-all", "--unshare-user", "--disable-userns",
        "--die-with-parent", "--new-session",
        "--uid", "65534", "--gid", "65534", "--cap-drop", "ALL",
        "--clearenv", "--setenv", "LANG", "C.UTF-8",
        "--ro-bind", str(prefix), str(prefix),
    ]
    # Standard dynamic-loader/runtime directories, never the host root.
    for library in ("/usr/lib", "/lib", "/lib64"):
        if Path(library).exists():
            command.extend(("--ro-bind", library, library))
    command.extend((
        "--dir", "/app", "--ro-bind", str(package), "/app/universal",
        "--proc", "/proc", "--remount-ro", "/proc", "--dev", "/dev",
        "--size", str(TMPFS_BYTES), "--tmpfs", "/tmp",
        "--chdir", "/tmp", "--remount-ro", "/",
        "--", str(interpreter), "-I", "-S", "-B",
        "/app/universal/child.py", "--fd", str(fd), "--role", role,
    ))
    command.extend(extra_args)
    return command


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _syscall_policy():
    # Deny process creation/execution, foreign-process access, new sockets,
    # namespace changes and alternate kernel APIs that can bypass socket rules.
    architecture = platform.machine().lower()
    if architecture in {"x86_64", "amd64"}:
        return 0xC000003E, (
            41, 42, 43, 49, 50, 53, 288,  # socket/connect/accept/bind/listen/socketpair/accept4
            56, 57, 58, 59, 322, 435,    # clone/fork/vfork/execve/execveat/clone3
            62, 200, 234, 424,           # kill/tkill/tgkill/pidfd_send_signal
            101, 310, 311, 312, 438,     # ptrace/process_vm_readv/writev/kcmp/pidfd_getfd
            155, 161, 165, 166, 272, 308,  # pivot_root/chroot/mount/umount/unshare/setns
            248, 249, 250, 298, 300, 303, 304, 321, 323,  # keys/perf/fanotify/handles/bpf/userfaultfd
            425, 426, 427,              # io_uring setup/enter/register
            428, 429, 430, 431, 432, 433, 434, 442, 448,  # new mounts/pidfd_open/mount_setattr/process_mrelease
        )
    if architecture in {"aarch64", "arm64"}:
        return 0xC00000B7, (
            198, 199, 200, 201, 202, 203, 242,
            220, 221, 281, 435,
            129, 130, 131, 424,
            117, 270, 271, 272, 438,
            41, 51, 40, 39, 97, 268,
            217, 218, 219, 241, 262, 264, 265, 280, 282,
            425, 426, 427,
            428, 429, 430, 431, 432, 433, 434, 442, 448,
        )
    raise IsolationUnavailable("seccomp syscall policy is unavailable for " + architecture)


def inside_child_limits(memory_bytes=MEMORY_BYTES, cpu_seconds=3) -> None:
    """Irreversibly restrict a trusted bootstrap before executing payload code.

    New socket creation and process spawning return EPERM. An inherited Unix
    IPC socket keeps ordinary send/recv functionality. Limits are per child;
    the parent still enforces wall time and bounded protocol/output sizes.
    """
    if sys.platform != "linux" or resource is None:
        raise IsolationUnavailable("Linux seccomp is required")
    if type(memory_bytes) is not int or memory_bytes < 32 * 1024 * 1024:
        raise ValueError("memory budget must be at least 32 MiB")
    if type(cpu_seconds) is not int or cpu_seconds < 1:
        raise ValueError("CPU budget must be a positive integer")
    audit_arch, denied = _syscall_policy()
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    # Native audit architecture must match. Unknown architectures (including
    # i386) are killed, and x32 syscall-number aliases are rejected explicitly.
    rules = [
        _SockFilter(0x20, 0, 0, 4),               # load seccomp_data.arch
        _SockFilter(0x15, 1, 0, audit_arch),
        _SockFilter(0x06, 0, 0, 0x80000000),      # KILL_PROCESS
        _SockFilter(0x20, 0, 0, 0),               # load syscall number
        _SockFilter(0x35, 0, 1, 0x40000000),      # x32/invalid high numbers
        _SockFilter(0x06, 0, 0, 0x00050000 | errno.EPERM),
    ]
    for number in sorted(set(denied)):
        rules.extend((_SockFilter(0x15, 0, 1, number),
                      _SockFilter(0x06, 0, 0, 0x00050000 | errno.EPERM)))
    rules.append(_SockFilter(0x06, 0, 0, 0x7FFF0000))  # ALLOW
    array = (_SockFilter * len(rules))(*rules)
    program = _SockFprog(len(rules), array)
    # Set hard limits, so payloads cannot increase their own budgets afterward.
    for kind, limit in (
        (resource.RLIMIT_AS, memory_bytes),
        (resource.RLIMIT_CPU, cpu_seconds),
        (resource.RLIMIT_FSIZE, FILE_BYTES),
        (resource.RLIMIT_NPROC, 0),
        (resource.RLIMIT_NOFILE, 64),
        (resource.RLIMIT_CORE, 0),
    ):
        soft, hard = resource.getrlimit(kind)
        actual = min(limit, hard) if hard != resource.RLIM_INFINITY else limit
        resource.setrlimit(kind, (actual, actual))
    if prctl(38, 1, 0, 0, 0) != 0:              # PR_SET_NO_NEW_PRIVS
        raise IsolationUnavailable("PR_SET_NO_NEW_PRIVS failed: " + str(ctypes.get_errno()))
    if prctl(22, 2, ctypes.byref(program), 0, 0) != 0:  # PR_SET_SECCOMP FILTER
        raise IsolationUnavailable("seccomp filter failed: " + str(ctypes.get_errno()))
