"""Read-only liveness classification for *owner-supplied* synthetic observations.

Trusted source flags must be independently established by the caller; this
function cannot authenticate a provider, renew a lease, cancel work or retry an
uncertain write. Silence on stdout is never evidence of failure.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Observation:
    now_unix: int
    run_id: str
    fence: int
    provider_state: str = 'UNAVAILABLE'
    provider_trusted: bool = False
    provider_run_id: str = ''
    provider_fence: int = 0
    supervisor_trusted: bool = False
    supervisor_run_id: str = ''
    supervisor_fence: int = 0
    heartbeat_unix: int = 0
    lease_until_unix: int = 0
    result_manifest_verified: bool = False
    terminal_receipt_verified: bool = False
    output_progressed: bool = False
    effect_ack_unknown: bool = False
    chat_handoff: bool = False
    heartbeat_grace_seconds: int = 45


@dataclass(frozen=True)
class Liveness:
    state: str
    reason: str
    may_cancel: bool = False
    may_retry_write: bool = False


def classify(observation):
    """Report an observation category only; this is never an owner gate verdict."""
    o = observation
    if type(o) is not Observation:
        raise ValueError('typed owner observation required')
    for n in ('now_unix', 'fence', 'provider_fence', 'supervisor_fence',
              'heartbeat_unix', 'lease_until_unix', 'heartbeat_grace_seconds'):
        v = getattr(o, n)
        if type(v) is not int or not 0 <= v <= 2**63 - 1:
            raise ValueError('invalid bounded time/counter')
    if not 1 <= o.heartbeat_grace_seconds <= 3600:
        raise ValueError('invalid heartbeat grace')
    for n in ('run_id', 'provider_run_id', 'supervisor_run_id', 'provider_state'):
        v = getattr(o, n)
        if type(v) is not str or len(v) > 96:
            raise ValueError('invalid observation text')
    if not o.run_id:
        raise ValueError('target run required')
    for n in ('provider_trusted', 'supervisor_trusted', 'result_manifest_verified',
              'terminal_receipt_verified', 'output_progressed', 'effect_ack_unknown', 'chat_handoff'):
        if type(getattr(o, n)) is not bool:
            raise ValueError('invalid observation flag')
    if o.provider_state not in {'UNAVAILABLE', 'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED'}:
        raise ValueError('unknown provider state')
    if o.effect_ack_unknown:
        return Liveness('UNKNOWN_EFFECT', 'reconcile exact outbox receipt, never repeat write')
    provider_matches = (o.provider_trusted and o.provider_run_id == o.run_id
                        and o.provider_fence == o.fence)
    supervisor_matches = (o.supervisor_trusted and o.supervisor_run_id == o.run_id
                          and o.supervisor_fence == o.fence)
    if provider_matches and o.provider_state == 'COMPLETED' and o.result_manifest_verified:
        return Liveness('RESULT_READY', 'provider and manifest matched; acceptance remains separate')
    if provider_matches and o.provider_state in {'FAILED', 'CANCELLED'} and o.terminal_receipt_verified:
        return Liveness('FAILED_CONFIRMED', 'matched terminal receipt; no auto cancel')
    if provider_matches and o.provider_state in {'FAILED', 'CANCELLED', 'COMPLETED'}:
        return Liveness('UNKNOWN', 'terminal provider state lacks matched receipt')
    if o.chat_handoff:
        return Liveness('CHAT_HANDOFF', 'Chat ended; external execution status unchanged')
    lease_current = o.lease_until_unix > o.now_unix
    heartbeat_current = (0 < o.heartbeat_unix <= o.now_unix
                         and o.now_unix - o.heartbeat_unix <= o.heartbeat_grace_seconds)
    if (provider_matches and supervisor_matches and lease_current and heartbeat_current
            and o.provider_state in {'RUNNING', 'QUEUED'}):
        return Liveness('RUNNING' if o.output_progressed else 'SILENT_RUNNING',
                        'matched independent provider and supervisor liveness')
    if provider_matches and o.provider_state in {'RUNNING', 'QUEUED'}:
        return Liveness('SUSPECT_RECOVERY', 'provider active but independent health incomplete')
    if supervisor_matches and lease_current and heartbeat_current:
        return Liveness('SUSPECT_RECOVERY', 'supervisor fresh but provider not independently matched')
    return Liveness('UNKNOWN', 'insufficient independent observations')
