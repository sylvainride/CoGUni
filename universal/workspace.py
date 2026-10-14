"""Disconnected owner-only local Git object workspace, never a worker tool.

The owner supplies a freshly verified provider binding and a trusted local
checkout. No network, credentials, shell, checkout of candidate code or remote
publication is performed. Local ref CAS is not GitHub authorization or a gate
attestation. The owner broker must separately enforce grants and live remote
identity/base/checks before any external effect.
"""
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from .policy_runner import _files


_OID = re.compile(r'[0-9a-f]{40}\Z')
_RUN = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,47}\Z')
REMOTE = 'https://github.com/sylvainride/CoGUni.git'


class WorkspaceConflict(ValueError):
    pass


def _oid(value):
    if type(value) is not str or not _OID.fullmatch(value):
        raise ValueError('invalid Git SHA-1 identity')
    return value


@dataclass(frozen=True)
class RepositoryBinding:
    repository_id: int
    node_id: str
    full_name: str
    owner_id: int
    remote: str
    base_sha: str
    base_tree: str
    branch: str = 'main'

    def __post_init__(self):
        if (type(self.repository_id) is not int or self.repository_id != 1418009675
                or type(self.owner_id) is not int or self.owner_id != 265171248
                or self.node_id != 'R_kgDOVIUcSw' or self.full_name != 'sylvainride/CoGUni'
                or self.remote != REMOTE or self.branch != 'main'):
            raise ValueError('repository binding mismatch')
        _oid(self.base_sha)
        _oid(self.base_tree)


@dataclass(frozen=True)
class Candidate:
    parent: str
    tree: str
    commit: str

    def __post_init__(self):
        for value in (self.parent, self.tree, self.commit):
            _oid(value)


class LocalWorkspace:
    """Private bare object DB and one unique local branch per owner run.

    Text patches never touch the source checkout or traverse a worktree. Only
    exact allowlisted mode-100644 paths can change. Symlinks, executable/binary
    replacements and arbitrary refs are refused. Cleanup owns only its tempfile.
    """

    def __init__(self, source, binding, *, run_id, allowed_paths, expires_unix,
                 clock=time.time):
        if type(binding) is not RepositoryBinding or type(run_id) is not str or not _RUN.fullmatch(run_id):
            raise ValueError('invalid workspace owner inputs')
        if (type(allowed_paths) is not tuple or not 1 <= len(allowed_paths) <= 32
                or len(set(allowed_paths)) != len(allowed_paths)):
            raise ValueError('exact bounded path tuple required')
        _files({p: '' for p in allowed_paths})
        self.binding, self.allowed_paths, self.clock = binding, frozenset(allowed_paths), clock
        self.expires_unix = expires_unix
        now = self._time()
        if type(expires_unix) not in (int, float) or not math.isfinite(expires_unix) or not now < expires_unix <= now + 300:
            raise ValueError('invalid workspace lease')
        self.last_now = now
        path = Path(source).absolute()
        if not path.is_dir() or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('trusted canonical checkout required')
        if not (path / '.git').is_dir() or (path / '.git').is_symlink():
            raise ValueError('regular trusted checkout required')
        self.git = shutil.which('git', path=os.defpath)
        if not self.git:
            raise ValueError('Git unavailable')
        self.temp = tempfile.TemporaryDirectory(prefix='coguni-owner-git-')
        self.root = Path(self.temp.name)
        self.database = self.root / 'objects.git'
        self.ref = 'refs/heads/work/pass2/local-' + run_id
        try:
            observed = self._call(['-C', str(path), 'config', '--get', 'remote.origin.url']).decode().strip()
            if observed != binding.remote:
                raise ValueError('source remote mismatch')
            if self._call(['-C', str(path), 'rev-parse', 'HEAD']).decode().strip() != binding.base_sha:
                raise WorkspaceConflict('source HEAD differs from bound base')
            self._git('init', '--bare', '--quiet', '--object-format=sha1')
            self._git('-c', 'protocol.file.allow=always', 'fetch', '--quiet', '--no-tags',
                      '--depth=1', '--', str(path), binding.base_sha)
            if self.tree(binding.base_sha) != binding.base_tree:
                raise WorkspaceConflict('base tree mismatch')
            self._git('update-ref', self.ref, binding.base_sha, '0' * 40)
            self._check_modes(binding.base_sha)
        except BaseException:
            self.close()
            raise

    def _time(self):
        now = self.clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise ValueError('invalid owner clock')
        return now

    def _live(self):
        now = self._time()
        if now < self.last_now or now >= self.expires_unix:
            raise WorkspaceConflict('workspace lease expired or clock regressed')
        self.last_now = now

    def _call(self, args, *, data=None, index=None):
        env = {'PATH': os.defpath, 'LANG': 'C.UTF-8', 'HOME': str(self.root),
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null',
               'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_ATTR_NOSYSTEM': '1',
               'GIT_DEFAULT_HASH': 'sha1', 'GIT_TERMINAL_PROMPT': '0',
               'GIT_AUTHOR_NAME': 'Local owner fixture', 'GIT_AUTHOR_EMAIL': 'owner@example.invalid',
               'GIT_COMMITTER_NAME': 'Local owner fixture', 'GIT_COMMITTER_EMAIL': 'owner@example.invalid'}
        if index is not None:
            env['GIT_INDEX_FILE'] = str(index)
        process = subprocess.run([self.git, '-c', 'core.hooksPath=/dev/null',
                                  '-c', 'core.attributesFile=/dev/null',
                                  '-c', 'fetch.fsckObjects=true', *args],
                                 input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd=self.root, env=env, timeout=10, check=False)
        if process.returncode or len(process.stdout) > 1024 * 1024 or len(process.stderr) > 8192:
            raise WorkspaceConflict('bounded Git operation refused')
        return process.stdout

    def _git(self, *args, **kwargs):
        return self._call(['--git-dir=' + str(self.database), *args], **kwargs)

    def tree(self, commit):
        return _oid(self._git('rev-parse', _oid(commit) + '^{tree}').decode().strip())

    def head(self):
        return _oid(self._git('rev-parse', '--verify', self.ref).decode().strip())

    def _check_modes(self, commit):
        for row in self._git('ls-tree', '-r', '-z', _oid(commit)).split(b'\0'):
            if not row:
                continue
            metadata, path = row.split(b'\t', 1)
            name = path.decode('utf-8', 'strict')
            if name in self.allowed_paths:
                if metadata.split()[0] != b'100644':
                    raise ValueError('allowlisted base path must be ordinary nonexecutable text')
                content = self._git('cat-file', 'blob', metadata.split()[2].decode()).decode('utf-8', 'strict')
                _files({name: content})

    def prepare(self, patches, *, expected_head, expected_tree, deletions=()):
        """Build unreachable candidate objects; do not advance any ref."""
        self._live()
        expected_head, expected_tree = _oid(expected_head), _oid(expected_tree)
        if self.head() != expected_head or self.tree(expected_head) != expected_tree:
            raise WorkspaceConflict('stale base or tree')
        if type(patches) is not dict or type(deletions) is not tuple:
            raise ValueError('plain text patches and deletion tuple required')
        patches = _files(patches) if patches else {}
        changed = set(patches) | set(deletions)
        if (not changed or not changed <= self.allowed_paths or len(set(deletions)) != len(deletions)
                or set(patches) & set(deletions)):
            raise ValueError('patch outside exact scope or conflicting deletion')
        self._check_modes(expected_head)
        with tempfile.TemporaryDirectory(prefix='index-', dir=self.root) as directory:
            index = Path(directory) / 'index'
            self._git('read-tree', expected_head, index=index)
            records = bytearray()
            for name, text in sorted(patches.items()):
                blob = _oid(self._git('hash-object', '-w', '--stdin', data=text.encode('utf-8')).decode().strip())
                records.extend(b'100644 ' + blob.encode() + b'\t' + name.encode('ascii') + b'\0')
            for name in deletions:
                records.extend(b'0 ' + b'0' * 40 + b'\t' + name.encode('ascii') + b'\0')
            self._git('update-index', '-z', '--index-info', data=bytes(records), index=index)
            tree = _oid(self._git('write-tree', index=index).decode().strip())
        self._live()
        if self.head() != expected_head:
            raise WorkspaceConflict('base advanced during preparation')
        commit = _oid(self._git('commit-tree', tree, '-p', expected_head,
                               data=b'Prepare bounded owner text patch\n').decode().strip())
        return Candidate(expected_head, tree, commit)

    def advance(self, candidate, *, validated_tree):
        """CAS local ref after an owner-supplied exact-tree observation.

        validated_tree is NOT a signed gate proof. This interface must never be
        exposed to an untrusted worker or used as remote publication authority.
        """
        self._live()
        if type(candidate) is not Candidate or _oid(validated_tree) != candidate.tree:
            raise WorkspaceConflict('candidate differs from validated tree')
        if self.tree(candidate.commit) != candidate.tree:
            raise WorkspaceConflict('candidate commit tree mismatch')
        parents = self._git('rev-list', '--parents', '-n', '1', candidate.commit).decode().split()
        if parents != [candidate.commit, candidate.parent]:
            raise WorkspaceConflict('candidate parent mismatch')
        # Candidate is a public value object. Recheck actual objects rather
        # than assuming every trusted caller obtained it through prepare().
        paths = self._git('diff-tree', '--no-commit-id', '--name-only', '-r',
                          '-z', candidate.parent, candidate.commit).split(b'\0')
        changed = {path.decode('utf-8', 'strict') for path in paths if path}
        if not changed or not changed <= self.allowed_paths:
            raise WorkspaceConflict('candidate changes paths outside owner scope')
        self._check_modes(candidate.commit)
        patched = {}
        for name in sorted(changed):
            row = self._git('ls-tree', '-z', candidate.commit, '--', name)
            if row:  # Deletions carry no replacement blob.
                metadata, _ = row.rstrip(b'\0').split(b'\t', 1)
                patched[name] = self._git('cat-file', 'blob', metadata.split()[2].decode()).decode('utf-8', 'strict')
        if patched:
            _files(patched)  # Same aggregate bound as prepare(), not each file only.
        self._live()
        self._git('update-ref', self.ref, candidate.commit, candidate.parent)
        return candidate.commit

    def close(self):
        self.temp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()
