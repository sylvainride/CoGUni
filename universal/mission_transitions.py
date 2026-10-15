"""Pure mission status ordering; a decision here is never an authorization.

The owner store must atomically compare revision/fence and independently verify
actual permissions and proofs. This module emits no side effects, updates no
lease, never authenticates a provider or a Chat session, and cannot award PASS.
"""
from .mission_contracts import canonical, decode_event, MissionContractError

# Explicit edges avoid success inferred from a progress or a silent job.
EDGES = {
    'QUEUED': {'CLAIMED', 'PAUSED_NO_EXECUTOR', 'BLOCKED_TOOL', 'BLOCKED_PERMISSION'},
    'CLAIMED': {'RUNNING', 'PAUSED_NO_EXECUTOR', 'SUSPECT_RECOVERY', 'CANCELLED'},
    'RUNNING': {'SILENT_RUNNING', 'SUSPECT_RECOVERY', 'RESULT_READY', 'FAILED_CONFIRMED', 'UNKNOWN_EFFECT', 'CANCELLED'},
    'SILENT_RUNNING': {'RUNNING', 'SUSPECT_RECOVERY', 'RESULT_READY', 'FAILED_CONFIRMED', 'UNKNOWN_EFFECT', 'CANCELLED'},
    'SUSPECT_RECOVERY': {'RUNNING', 'SILENT_RUNNING', 'FAILED_CONFIRMED', 'UNKNOWN_EFFECT'},
    'RESULT_READY': {'RESULT_INSPECTED', 'FAILED_CONFIRMED'},
    'RESULT_INSPECTED': {'APPLY_REQUESTED', 'NEEDS_REWORK', 'FAILED_CONFIRMED'},
    'APPLY_REQUESTED': {'APPLIED', 'UNKNOWN_EFFECT', 'FAILED_CONFIRMED'},
    'APPLIED': {'VERIFYING', 'UNKNOWN_EFFECT'},
    'VERIFYING': {'ACCEPTED', 'NEEDS_REWORK', 'FAILED_CONFIRMED', 'UNKNOWN_EFFECT'},
    'NEEDS_REWORK': set(),  # a new owner-issued attempt/run is required
    'UNKNOWN_EFFECT': set(),  # reconcile via the same store, never blind retry
    'FAILED_CONFIRMED': set(),
    'CANCELLED': set(),
    'ACCEPTED': set(),
    'BLOCKED_TOOL': set(),
    'BLOCKED_PERMISSION': set(),
    'BLOCKED_QUOTA': set(),
    'PAUSED_NO_EXECUTOR': set(),  # resume is a new owner decision
    'CHAT_HANDOFF': set(),  # delivery status, not a new execution grant
}


def transition_eligible(previous, proposed):
    """Assess two events from one run; fail closed. No mutation, no grants.

    The independent owner authority must still prove any ACCEPTED/APPLIED
    transition. A string claiming OWNER_JOURNAL or AUTH_PROVIDER is not proof.
    """
    try:
        a = decode_event(canonical(previous))
        b = decode_event(canonical(proposed))
    except (MissionContractError, TypeError, ValueError, UnicodeError):
        return False
    if any(a[field] != b[field] for field in ('mission_id', 'run_id', 'source_sha256')):
        return False
    if 'project_id' in a or 'project_id' in b:
        if a.get('project_id') != b.get('project_id'):
            return False
    if b['event_seq'] != a['event_seq'] + 1 or b['revision'] != a['revision'] + 1:
        return False
    if b['observed_unix'] < a['observed_unix'] or b['fence'] < a['fence']:
        return False
    if b['fence'] != a['fence'] and b['proof_kind'] != 'OWNER_JOURNAL':
        return False
    prior_lease = a.get('lease_until_unix')
    next_lease = b.get('lease_until_unix')
    if prior_lease is not None and next_lease is not None and next_lease > prior_lease:
        if b['proof_kind'] != 'OWNER_JOURNAL':
            return False
    if b['state'] not in EDGES.get(a['state'], ()):
        return False
    if b['state'] in {'ACCEPTED', 'APPLIED', 'APPLY_REQUESTED'} and b['proof_kind'] == 'UNTRUSTED_WORKER':
        return False
    return True
