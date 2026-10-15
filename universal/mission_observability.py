"""P45: read-only synthetic health triage over existing liveness and poll plans.

This does not send notifications, authenticate observers, cancel workers,
renew leases, grant permission, call an executor or repair uncertain effects.
A raw provider status is never treated as independent trusted proof.
"""
from dataclasses import dataclass

from .mission_liveness import Observation, classify
from .mission_polling import PollCursor, plan_read
from .mission_redaction import redacted_liveness


@dataclass(frozen=True)
class Triage:
    health: str
    owner_attention: str
    run_tag: str
    details_scope: str = 'SYNTHETIC_REDACTED_OBSERVATION_ONLY'
    alert_sent: bool = False
    cancel_authorized: bool = False
    write_retry_authorized: bool = False
    accepted: bool = False


def review_observation(observation, cursor, *, now_unix):
    """Classify bounded monitoring data, never dispatch or claim terminal PASS.

    In particular, a stale cursor is BLOCKED_SCOPE even if a purported provider
    reports RUNNING, while SILENT_RUNNING on a matched healthy provider/lease
    means NO_ALERT. UNKNOWN_EFFECT means OWNER_RECONCILIATION, never retry.
    """
    if type(observation) is not Observation or type(cursor) is not PollCursor:
        raise ValueError('typed owner observation and poll cursor required')
    if type(now_unix) is not int or now_unix < 0 or now_unix > 2**63 - 1:
        raise ValueError('bounded observation clock required')
    health = classify(observation)
    poll = plan_read(cursor, now_unix=now_unix, run_id=observation.run_id,
                     source_sha256=cursor.source_sha256, fence=observation.fence,
                     liveness=health.state)
    public = redacted_liveness(observation)
    if poll.action == 'BLOCK':
        level, action = 'BLOCKED_SCOPE', 'OWNER_RECHECK_IDENTITY'
    elif poll.action == 'RECONCILE':
        level, action = 'UNKNOWN_EFFECT', 'OWNER_RECONCILIATION'
    elif health.state in {'RUNNING', 'SILENT_RUNNING'}:
        level, action = 'HEALTHY', 'NO_ALERT'
    elif health.state == 'SUSPECT_RECOVERY':
        level, action = 'SUSPECT', 'OWNER_INVESTIGATION'
    elif health.state in {'RESULT_READY', 'FAILED_CONFIRMED'}:
        level, action = 'TERMINAL_OBSERVED', 'OWNER_REVIEW_REQUIRED'
    elif health.state == 'CHAT_HANDOFF':
        level, action = 'HANDOFF', 'OWNER_RESUME_REVALIDATION'
    else:
        level, action = 'UNKNOWN', 'OWNER_INVESTIGATION'
    return Triage(level, action, public['run_tag'])
