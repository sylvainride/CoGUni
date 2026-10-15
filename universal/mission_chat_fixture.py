"""Read-only synthetic Chat fixture preview over the existing owner SQLite journal.

No model, worker, external API, sender authentication, remote receiver, owner
approval, artifact application or test PASS. A preview is not a result receipt.
"""
import hashlib
import os
from pathlib import Path
import stat

from .continuity import ContinuityJournal, MAX_SOURCE_BYTES
from .core import GuardError
from .mission_contracts import fingerprint


def preview_synthetic_task(journal, task):
    """Compute source-bound deterministic *trusted fixture* metadata only."""
    if type(journal) is not ContinuityJournal or type(task) is not str:
        raise GuardError('owner journal and task ID required', 'BLOCK')
    row = journal.get(task)
    policy = row['contract']
    if (len(policy['sources']) != 1
            or 'offline synthetic admission only' not in policy['constraints']
            or len(policy['actions']) != 1
            or policy['actions'][0]['tool'] != 'offline_fixture'
            or not journal.verify_chain()):
        raise GuardError('not a trusted synthetic owner fixture', 'BLOCK')
    path, expected_sha = next(iter(policy['sources'].items()))
    if not Path(path).is_absolute():
        raise GuardError('absolute pinned source required', 'BLOCK')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as src:
            metadata = os.fstat(src.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_SOURCE_BYTES:
                raise GuardError('source not a bounded regular file', 'BLOCK')
            content = src.read(MAX_SOURCE_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise GuardError('synthetic source unavailable', 'BLOCK') from exc
    if len(content) > MAX_SOURCE_BYTES or hashlib.sha256(content).hexdigest() != expected_sha:
        raise GuardError('synthetic source differs from owner pin', 'BLOCK')
    result = {
        'schema_version': 1, 'task_id': row['id'], 'contract_sha256': row['contract_sha'],
        'source_sha256': expected_sha, 'byte_count': len(content),
        'line_break_count': content.count(b'\n'),
        'result_state': 'PREVIEW_ONLY', 'accepted': False, 'action_executed': False,
    }
    return {**result, 'digest': fingerprint(result)}
