"""Private, read-only synthetic Chat handoff bound to the existing owner journal.

A handoff is NOT a recovery grant, signed proof, authentication credential,
worker command, or cancellation. Import rechecks live journal revision, fence,
source and lease. It never mutates state or starts/cancels an executor.
"""
from dataclasses import asdict, dataclass

from .continuity import ContinuityJournal
from .core import GuardError
from .mission_contracts import _read, canonical, fingerprint
from .mission_polling import PollCursor

_FIELDS = {'schema_version', 'kind', 'authority', 'task_id', 'journal_id',
           'run_id', 'contract_sha', 'source_sha256', 'expected_revision',
           'expected_fence', 'observed_state', 'observed_unix', 'cursor', 'digest'}
_CURSOR_FIELDS = set(PollCursor.__dataclass_fields__)
_MAX = 8192


@dataclass(frozen=True)
class ResumeHint:
    state: str
    reason: str
    cursor: PollCursor
    # This is informational, and can NEVER authorize an execution or effect.
    execution_authorized: bool = False


def _owner_row(journal, task):
    if type(journal) is not ContinuityJournal:
        raise GuardError('trusted owner journal required', 'BLOCK')
    row = journal.get(task)
    contract = row['contract']
    if (row['id'] != task or len(contract['sources']) != 1
            or 'offline synthetic admission only' not in contract['constraints']
            or len(contract['actions']) != 1
            or contract['actions'][0]['tool'] != 'offline_fixture'):
        raise GuardError('only owner-pinned synthetic fixtures can hand off', 'BLOCK')
    if not journal.verify_chain():
        raise GuardError('owner chain is not intact', 'BLOCK')
    return row


def _integer(value):
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise GuardError('invalid handoff integer', 'BLOCK')


def export_offline_handoff(journal, task, cursor, *, now_unix):
    """Return a private portable blob, without checkpoint or lease mutation."""
    _integer(now_unix)
    if type(cursor) is not PollCursor or type(task) is not str:
        raise GuardError('bound owner polling cursor required', 'BLOCK')
    row = _owner_row(journal, task)
    if (cursor.run_id != task or cursor.source_sha256 not in row['contract']['sources'].values()
            or cursor.fence != row['fence']):
        raise GuardError('handoff cursor identity mismatch', 'BLOCK')
    body = {
        'schema_version': 1, 'kind': 'coguni-private-owner-handoff-v1',
        'authority': 'NONE', 'task_id': task, 'journal_id': row['journal_id'],
        'run_id': cursor.run_id, 'contract_sha': row['contract_sha'],
        'source_sha256': cursor.source_sha256, 'expected_revision': row['revision'],
        'expected_fence': row['fence'], 'observed_state': row['state'],
        'observed_unix': now_unix, 'cursor': asdict(cursor),
    }
    wire = canonical({**body, 'digest': fingerprint(body)})
    if len(wire) > _MAX:
        raise GuardError('handoff exceeds size bound', 'BLOCK')
    return wire


def import_offline_handoff(journal, wire, *, now_unix):
    """Return a read-only resume hint, never an executor lease or action."""
    _integer(now_unix)
    if type(wire) not in (str, bytes):
        raise GuardError('handoff must be JSON text', 'BLOCK')
    # Reject oversized text *before* encoding it; untrusted Unicode must be
    # rejected as an explicit handoff refusal, not an uncaught codec error.
    if not 0 < len(wire) <= _MAX:
        raise GuardError('handoff size invalid', 'BLOCK')
    try:
        raw = wire.encode('utf-8') if type(wire) is str else wire
    except UnicodeError as exc:
        raise GuardError('handoff contains invalid Unicode', 'BLOCK') from exc
    if len(raw) > _MAX:
        raise GuardError('handoff size invalid', 'BLOCK')
    try:
        obj = _read(raw)
        if set(obj) != _FIELDS or type(obj['schema_version']) is not int or obj['schema_version'] != 1:
            raise ValueError('unknown handoff version or fields')
        if obj['kind'] != 'coguni-private-owner-handoff-v1' or obj['authority'] != 'NONE':
            raise ValueError('handoff not data-only')
        for n in ('expected_revision', 'expected_fence', 'observed_unix'):
            _integer(obj[n])
        if (type(obj['cursor']) is not dict or set(obj['cursor']) != _CURSOR_FIELDS
                or obj['digest'] != fingerprint({k:v for k,v in obj.items() if k != 'digest'})):
            raise ValueError('handoff digest/cursor mismatch')
        cursor = PollCursor(**obj['cursor'])
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise GuardError('handoff validation failed', 'BLOCK') from exc
    row = _owner_row(journal, obj['task_id'])
    if (obj['journal_id'] != row['journal_id'] or obj['contract_sha'] != row['contract_sha']
            or obj['expected_revision'] != row['revision'] or obj['expected_fence'] != row['fence']
            or obj['observed_state'] != row['state']
            or obj['run_id'] != cursor.run_id or obj['run_id'] != row['id']
            or obj['source_sha256'] != cursor.source_sha256
            or cursor.fence != row['fence']
            or obj['source_sha256'] not in row['contract']['sources'].values()):
        raise GuardError('stale, forged or foreign handoff', 'BLOCK')
    if not journal._sources_current(row['contract']):
        return ResumeHint('BLOCKED_SOURCE', 'owner source pin changed; do not resume', cursor)
    if row['state'] == 'RUNNING':
        # The message timestamp is untrusted handoff metadata, not the owner
        # lease clock. Use the journal's own controlled clock (also used by
        # claim/recover), so a forged/stale Chat time cannot change the hint.
        owner_now = journal._now()
        if row['lease_until'] is not None and owner_now < row['lease_until']:
            return ResumeHint('OBSERVE_ONLY', 'preserve healthy owner lease; read-only status', cursor)
        return ResumeHint('OWNER_RECOVERY_REQUIRED', 'lease expired; original owner must fence and recover', cursor)
    if row['state'] in {'READY', 'PAUSED'}:
        return ResumeHint('OWNER_CLAIM_REQUIRED', 'no lease; owner must explicitly claim', cursor)
    return ResumeHint('BLOCKED', 'owner task is not resumable', cursor)
