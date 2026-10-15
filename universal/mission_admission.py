"""Opt-in OFFLINE admission adapter using the existing ContinuityJournal.

An envelope is untrusted data. Only a trusted owner can call this interface with
real, owner-pinned local file paths. Admission does not execute an action or
register a verification proof. No additional database, outbox or consent store.
"""
from pathlib import Path

from .continuity import ContinuityJournal, source_sha
from .core import GuardError
from .mission_contracts import canonical, decode_mission, fingerprint


def admit_synthetic(journal, raw, *, now_unix, source_path, output_path):
    """Create/replay one inert local task; key collisions fail in the journal.

    Real remote effects, nonlocal adapters, private data and mission DAG edges
    are deliberately not supported. No worker receives this admission API.
    """
    if type(journal) is not ContinuityJournal:
        raise GuardError('trusted owner continuity journal required', 'BLOCK')
    envelope = decode_mission(raw, now_unix=now_unix)
    spec = envelope['contract']
    if (envelope['project']['kind'] != 'local' or envelope['privacy'] != 'PUBLIC_SYNTHETIC'
            or spec['artifact_policy'] != 'public_synthetic'
            or spec['allowed_actions'] != ['simulate'] or spec['max_external_cost'] != 0
            or spec['dependencies'] or len(spec['criteria']) > 16):
        raise GuardError('offline synthetic admission only', 'BLOCK')
    if type(source_path) is not str or type(output_path) is not str:
        raise GuardError('explicit absolute local paths required', 'BLOCK')
    src, out = Path(source_path), Path(output_path)
    if (not src.is_absolute() or str(src.resolve()) != source_path
            or not out.is_absolute() or str(out.resolve()) != output_path
            or src == out or out.is_symlink()):
        raise GuardError('noncanonical, symlink or overlapping fixture path', 'BLOCK')
    observed = source_sha(src)
    if observed != envelope['source_sha256']:
        raise GuardError('pinned source differs from envelope', 'BLOCK')
    task = 'mission-' + fingerprint({'project': envelope['project']['id'],
                                           'mission': envelope['mission_id']})[:40]
    key = 'admit-' + fingerprint({'project': envelope['project']['id'],
                                      'key': envelope['idempotency_key']})[:40]
    contract = {
        'version': 1,
        'mission': spec['objective'],
        'constraints': ['offline synthetic admission only',
                        'project:' + envelope['project']['id'],
                        'version:' + envelope['project']['base_version'],
                        'envelope:' + fingerprint(envelope)],
        'decisions': ['no remote effect or worker validation permitted'],
        'sources': {source_path: observed},
        'files': [output_path],
        'criteria': spec['criteria'],
        'actions': [{'id': 'simulate', 'tool': 'offline_fixture',
                     'files': [output_path], 'description': 'inert local fixture planning'}],
        'dependencies': {},
        'max_attempts': spec['max_attempts'],
        'budget': spec['max_attempts'],
    }
    return journal.create_task(task, contract, key=key)
