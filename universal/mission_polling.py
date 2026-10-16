"""Inert bounded read-only polling plan; no clocks, sleeps, HTTP or writer.

A caller may persist a cursor in its existing owner-controlled checkpoint.
This module has no background process, transport or authority to renew leases.
"""
from dataclasses import dataclass, replace
import re

_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z')
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_STATES = frozenset({'QUEUED', 'RUNNING', 'SILENT_RUNNING', 'SUSPECT_RECOVERY',
                     'UNKNOWN', 'RESULT_READY', 'FAILED_CONFIRMED', 'UNKNOWN_EFFECT',
                     'BLOCKED_PERMISSION', 'BLOCKED_QUOTA', 'CHAT_HANDOFF'})
_TERMINAL = frozenset({'RESULT_READY', 'FAILED_CONFIRMED', 'BLOCKED_PERMISSION', 'BLOCKED_QUOTA'})


@dataclass(frozen=True)
class PollCursor:
    run_id: str
    source_sha256: str
    fence: int
    polls_left: int
    next_unix: int
    stop_unix: int
    interval_seconds: int = 30

    def __post_init__(self):
        if (type(self.run_id) is not str or not _ID.fullmatch(self.run_id)
                or type(self.source_sha256) is not str or not _SHA.fullmatch(self.source_sha256)):
            raise ValueError('invalid bound run/source identity')
        for name in ('fence', 'polls_left', 'next_unix', 'stop_unix', 'interval_seconds'):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 2**63 - 1:
                raise ValueError('invalid bounded poll cursor')
        if (self.polls_left > 10_000 or not 1 <= self.interval_seconds <= 3600
                or self.next_unix > self.stop_unix):
            raise ValueError('unbounded polling request')


@dataclass(frozen=True)
class PollPlan:
    action: str
    cursor: PollCursor
    reason: str
    # Decision is advisory only. Never a grant or proof of a provider call.


def plan_read(cursor, *, now_unix, run_id, source_sha256, fence, liveness):
    if type(cursor) is not PollCursor or type(now_unix) is not int or not 0 <= now_unix <= 2**63 - 1:
        raise ValueError('invalid poll input')
    if (type(run_id) is not str or type(source_sha256) is not str or type(fence) is not int
            or (run_id, source_sha256, fence) != (cursor.run_id, cursor.source_sha256, cursor.fence)):
        return PollPlan('BLOCK', cursor, 'stale or foreign run, source, or fence')
    if type(liveness) is not str or liveness not in _STATES:
        return PollPlan('BLOCK', cursor, 'unrecognized liveness claim')
    if liveness == 'UNKNOWN_EFFECT':
        return PollPlan('RECONCILE', cursor, 'same-store receipt lookup required, no replay')
    if liveness in _TERMINAL:
        return PollPlan('STOP', cursor, 'terminal observation does not authorize execution')
    if liveness == 'CHAT_HANDOFF':
        return PollPlan('HANDOFF', cursor, 'persist cursor; do not cancel worker')
    if now_unix >= cursor.stop_unix or cursor.polls_left == 0:
        return PollPlan('HANDOFF', cursor, 'bounded observation budget exhausted')
    if now_unix < cursor.next_unix:
        return PollPlan('WAIT', cursor, 'not yet due; no implicit timer is running')
    # Reserve one READ plan, never an effect. The caller must reconcile actual
    # provider acknowledgements and fence after a reconnect.
    updated = replace(cursor, polls_left=cursor.polls_left - 1,
                      next_unix=min(cursor.stop_unix, now_unix + cursor.interval_seconds))
    return PollPlan('READ_ONLY_POLL', updated, 'one allowed read observation, no write')
