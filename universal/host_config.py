"""Private owner configuration, not worker/mission input or a new authority."""
import hashlib
import math
import os
from pathlib import Path
import re
import stat

from .core import GuardError, canonical
from .host_github import validate_binding
from .mission_contracts import _read
from .parallel_policy import select_ready

ROOT = Path(__file__).resolve().parents[1]
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z')
_FIELDS = {'schema', 'mode', 'journal_path', 'journal_id', 'implementation_sha256',
           'scheduler', 'tasks', 'limits'}
_POLICY = {'max_parallel', 'run_budget', 'duration_budget', 'poll_budget',
           'max_backlog', 'resource_aliases', 'case_insensitive_targets'}


def implementation_sha256():
    # Works from an inspected source snapshot without requiring .git on host.
    paths = sorted((ROOT / 'universal').glob('*.py'))
    rows = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise GuardError('implementation is not ordinary source')
        rows[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(canonical(rows).encode()).hexdigest()


def private_path(value, *, existing=True):
    if type(value) is not str or not 1 <= len(value) <= 1024:
        raise GuardError('invalid private path')
    path = Path(value)
    if not path.is_absolute() or str(path.resolve()) != value or path.is_relative_to(ROOT):
        raise GuardError('private data must use a canonical path outside source')
    # The immediate private directory is the trusted host boundary. Reject
    # symlink ancestry as well, even if it currently resolves to the same file.
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise GuardError('private path must not use symlinks')
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077:
        raise GuardError('private parent must be owner-only')
    if existing or path.exists():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise GuardError('private file must be owner-only ordinary file')
    return path


def read_private(value):
    path = private_path(value)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or before.st_nlink != 1):
            raise GuardError('private input permissions changed')
        data = os.read(fd, 16385)
        after = path.lstat()
        if ((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size, before.st_mode)
                != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size, after.st_mode)
                or len(data) > 16384):
            raise GuardError('private input changed or exceeded bound')
        return data
    finally:
        os.close(fd)


def validate_config(value):
    if type(value) is not dict or set(value) != _FIELDS or type(value['schema']) is not int or value['schema'] != 1:
        raise GuardError('exact private host schema required')
    if value['mode'] != 'READ_ONLY_PUBLIC_SYNTHETIC':
        raise GuardError('host is read-only public synthetic only')
    for key in ('journal_id', 'implementation_sha256'):
        if type(value[key]) is not str or not _SHA.fullmatch(value[key]):
            raise GuardError('immutable owner/source pin required')
    private_path(value['journal_path'])
    policy = value['scheduler']
    if type(policy) is not dict or set(policy) != _POLICY:
        raise GuardError('exact existing scheduler policy required')
    for key, low, high in [('max_parallel', 1, 2), ('run_budget', 1, 16),
                           ('duration_budget', 1, 14400), ('poll_budget', 1, 128), ('max_backlog', 1, 32)]:
        if type(policy[key]) is not int or not low <= policy[key] <= high:
            raise GuardError('invalid existing scheduler budget')
    if (type(policy['resource_aliases']) is not list or any(type(x) is not list for x in policy['resource_aliases'])
            or type(policy['case_insensitive_targets']) is not list):
        raise GuardError('invalid existing scheduler resource policy')
    select_ready([], resource_aliases=tuple(tuple(x) for x in policy['resource_aliases']),
                 case_insensitive_targets=tuple(policy['case_insensitive_targets']))
    tasks = value['tasks']
    if type(tasks) is not list or not 1 <= len(tasks) <= 16:
        raise GuardError('bounded explicit owner task selection required')
    seen = set()
    for task in tasks:
        if type(task) is not dict or set(task) != {'task_id', 'binding'}:
            raise GuardError('exact task observation pin required')
        name = task['task_id']
        if type(name) is not str or not _ID.fullmatch(name) or name in seen:
            raise GuardError('invalid or duplicate owner task')
        seen.add(name)
        validate_binding(task['binding'])
    limits = value['limits']
    if type(limits) is not dict or set(limits) != {'hard_timeout_seconds', 'max_ticks', 'max_seconds', 'interval_seconds'}:
        raise GuardError('exact host limits required')
    for key, low, high in [('hard_timeout_seconds', 0.1, 30), ('max_seconds', 1, 300), ('interval_seconds', 1, 60)]:
        number = limits[key]
        if type(number) not in (int, float) or not math.isfinite(number) or not low <= number <= high:
            raise GuardError('invalid finite host duration')
    if type(limits['max_ticks']) is not int or not 1 <= limits['max_ticks'] <= 16:
        raise GuardError('invalid finite host tick count')
    if value['implementation_sha256'] != implementation_sha256():
        raise GuardError('host implementation source changed')
    return value


def load_config(path):
    return validate_config(_read(read_private(path)))
