"""Owner-only, read-only integrity inspection of a synthetic result artifact.

No worker execution, signature, PASS, deployment, or project mutation. The
caller selects the local trusted root; the result is *integrity only*, not an
external oracle's acceptance or a remote effect receipt. Directory components
are opened through dir_fd with O_NOFOLLOW, not through a raceable Path.resolve.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat

from .mission_contracts import decode_mission, decode_receipt, MissionContractError

MAX_ARTIFACT_BYTES = 1_048_576


@dataclass(frozen=True)
class ArtifactInspection:
    artifact_sha256: str
    size: int
    scope: str = 'SYNTHETIC_INTEGRITY_ONLY'
    accepted: bool = False
    application_authorized: bool = False


def _secure_read(root, relative, *, max_bytes):
    """Open each component through a trusted directory FD and reject symlinks."""
    if not 1 <= len(relative.parts) <= 8 or any(p in ('', '.', '..') for p in relative.parts):
        raise MissionContractError('invalid artifact location')
    if any(len(p.encode('utf-8')) > 160 for p in relative.parts):
        raise MissionContractError('artifact component too long')
    fd = None
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(relative.parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            before = os.fstat(leaf)
            if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
                raise MissionContractError('not a bounded regular artifact')
            chunks = []
            used = 0
            while True:
                chunk = os.read(leaf, min(65536, max_bytes + 1 - used))
                if not chunk:
                    break
                used += len(chunk)
                if used > max_bytes:
                    raise MissionContractError('artifact exceeded read limit')
                chunks.append(chunk)
            after = os.fstat(leaf)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise MissionContractError('artifact changed while reading')
            return b''.join(chunks)
        finally:
            os.close(leaf)
    except OSError as exc:
        raise MissionContractError('artifact could not be opened safely') from exc
    finally:
        if fd is not None:
            os.close(fd)


def inspect_synthetic_artifact(raw_mission, raw_receipt, *, now_unix, root, path,
                               expected_run_id, expected_project_version,
                               max_bytes=MAX_ARTIFACT_BYTES):
    """Verify exact project/source linkage + bytes; never promote worker PASS."""
    mission = decode_mission(raw_mission, now_unix=now_unix)
    receipt = decode_receipt(raw_receipt)
    if (type(expected_run_id) is not str or not 1 <= len(expected_run_id) <= 96
            or type(expected_project_version) is not str
            or not 1 <= len(expected_project_version) <= 160
            or receipt['run_id'] != expected_run_id
            or mission['project']['base_version'] != expected_project_version):
        raise MissionContractError('owner run or project version mismatch')
    if (mission['project']['kind'] != 'local' or mission['privacy'] != 'PUBLIC_SYNTHETIC'
            or receipt['mission_id'] != mission['mission_id']
            or receipt['project_id'] != mission['project']['id']
            or receipt['source_sha256'] != mission['source_sha256']):
        raise MissionContractError('foreign mission/project/source or private artifact')
    if (receipt['result_state'] != 'RESULT_READY'
            or receipt['application_status'] != 'NOT_APPLIED'
            or receipt['acceptance_status'] != 'NOT_TESTED'
            or receipt['artifact_sha256'] is None):
        raise MissionContractError('unreviewed, applied, uncertain or claimed-PASS receipt')
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_ARTIFACT_BYTES:
        raise MissionContractError('invalid artifact byte budget')
    if type(root) is not str or type(path) is not str:
        raise MissionContractError('exact local paths required')
    base, target = Path(root), Path(path)
    if (not base.is_absolute() or not target.is_absolute()
            or str(base.resolve()) != root or not base.is_dir()):
        raise MissionContractError('noncanonical synthetic owner root')
    try:
        relative = target.relative_to(base)
    except ValueError as exc:
        raise MissionContractError('artifact outside owner root') from exc
    data = _secure_read(root, relative, max_bytes=max_bytes)
    actual = hashlib.sha256(data).hexdigest()
    if actual != receipt['artifact_sha256']:
        raise MissionContractError('source-bound receipt artifact hash mismatch')
    return ArtifactInspection(actual, len(data))
