"""Passive finite owner supervisor. No provider client, dispatcher, timer or grant.

The injected reader belongs to a trusted owner host. A callback supplied by a
worker or by mission JSON is never authenticated by this module. Provider reads
may be persisted ONLY through the existing OwnerScheduler.observe operation.
"""
from dataclasses import dataclass
import time

from .core import GuardError
from .parallel_scheduler import OwnerScheduler
from .mission_liveness import Observation as LivenessObservation, classify
from .mission_polling import PollCursor, plan_read
from .persistent_provider_observation import ProviderObservation, UnavailableReadback


@dataclass(frozen=True, slots=True)
class HealthReadback:
    """Independent host-supplied supervisor heartbeat; never a lease renewal."""
    run_id: int
    fence: int
    heartbeat_unix: int

    def __post_init__(self):
        for field in ("run_id", "fence", "heartbeat_unix"):
            value = getattr(self, field)
            if type(value) is not int or not 0 <= value <= 2**63 - 1:
                raise GuardError("invalid supervisor heartbeat")


@dataclass(frozen=True, slots=True)
class SupervisorVerdict:
    task_id: str
    action: str
    liveness: str
    revision: int
    fence: int
    reason: str
    execution_authorized: bool = False
    may_cancel: bool = False
    may_retry_write: bool = False


class PassiveSupervisor:
    """A controller facade, NOT a long-running scheduler.

    The owner's original SQLite journal is authoritative. Ticks cannot reserve,
    recover, extend leases, accept results, create work or dispatch jobs.
    """

    def __init__(self, scheduler, *, repository_id=1418009675, actor_id=265171248):
        if type(scheduler) is not OwnerScheduler or not scheduler.enabled:
            raise GuardError("explicit enabled owner scheduler required")
        for ident in (repository_id, actor_id):
            if type(ident) is not int or ident <= 0:
                raise GuardError("explicit trusted provider identity required")
        self.scheduler = scheduler
        self.repository_id = repository_id
        self.actor_id = actor_id

    @staticmethod
    def _verdict(status, action, liveness, reason):
        return SupervisorVerdict(status["task_id"], action, liveness,
                                 status["revision"], status["fence"], reason)

    def observe_once(self, task_id, *, provider_reader, now_unix, deadline_monotonic=None):
        """Observe a reserved task. Reader must return (ProviderObservation, HealthReadback|None).

        The reader is injected by trusted owner code and must have an independent
        provider authentication path. It is never constructed from task JSON.
        A stable observation_id is the idempotency key for a lost local ACK.
        """
        if type(task_id) is not str or type(now_unix) is not int or not 0 <= now_unix <= 2**63 - 1:
            raise GuardError("invalid observation request")
        if not callable(provider_reader):
            raise GuardError("owner reader required")
        if deadline_monotonic is not None and (type(deadline_monotonic) not in (float, int)
                                                or time.monotonic() >= deadline_monotonic):
            raise GuardError("observation duration budget exhausted")
        # status/_row checks original journal source pins; no shadow state.
        status = self.scheduler.status(task_id)
        if status["state"] == "UNKNOWN_EFFECT":
            return self._verdict(status, "RECONCILE", "UNKNOWN_EFFECT",
                                 "same original store/receipt only; no repeat dispatch")
        if status["state"] not in {"IN_FLIGHT", "SUSPECT", "RESULT_READY", "HANDOFF"}:
            return self._verdict(status, "STOP", "UNKNOWN", "no active observation reservation")
        if (status["owner"] is None or type(status["lease_until"]) not in (int, float)
                or not now_unix < status["lease_until"]):
            return self._verdict(status, "HANDOFF", "SUSPECT_RECOVERY",
                                 "expired lease; no implicit owner recovery")
        budgets = self.scheduler.ready()
        if budgets["polls_left"] <= 0:
            return self._verdict(status, "HANDOFF", "UNKNOWN", "owner poll budget exhausted")
        # plan_read is advisory; it does not debit a durable counter.
        cursor = PollCursor(str(status["provider"]["run_id"]) if status["provider"] else task_id,
                            status["request_sha256"], status["fence"],
                            budgets["polls_left"], now_unix,
                            max(now_unix, int(status["lease_until"])))
        plan = plan_read(cursor, now_unix=now_unix, run_id=cursor.run_id,
                         source_sha256=cursor.source_sha256, fence=cursor.fence,
                         liveness="UNKNOWN")
        if plan.action != "READ_ONLY_POLL":
            return self._verdict(status, plan.action, "UNKNOWN", plan.reason)
        readback = provider_reader(task_id, status.copy())
        if type(readback) is UnavailableReadback:
            if readback.observed_unix > now_unix or now_unix - readback.observed_unix > 3600:
                raise GuardError("stale or future unavailable-provider report")
            return self._verdict(status, "HANDOFF", "UNKNOWN",
                                 "provider read unavailable: " + readback.reason
                                 + "; owner requalification required, no retry")
        if (type(readback) is not tuple or len(readback) != 2
                or type(readback[0]) is not ProviderObservation
                or (readback[1] is not None and type(readback[1]) is not HealthReadback)):
            raise GuardError("owner reader must supply typed readback, never worker JSON")
        provider, health = readback
        provider.matched(status, now_unix=now_unix,
                         expected_repository_id=self.repository_id,
                         expected_actor_id=self.actor_id)
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            return self._verdict(status, "HANDOFF", "UNKNOWN",
                                 "read overran bounded owner tick; no ledger transition")
        if (health is not None and (health.run_id != provider.run_id
                                    or health.fence != status["fence"]
                                    or health.heartbeat_unix > now_unix)):
            raise GuardError("independent heartbeat identity/fence/time mismatch")
        observation_key = "p4-" + provider.observation_id
        # Idempotent lost-ACK reconciliation from the ORIGINAL durable journal.
        # Never debit twice for the same read or accept a colliding read identity.
        for event in self.scheduler.journal.events():
            if event["body"]["key"] == observation_key:
                request = event["body"]["request"]
                if (request.get("operation") != "ps.observe"
                        or request.get("task") != task_id
                        or request.get("provider") != provider.scheduler_record()):
                    raise GuardError("observation id reused for different provider readback")
                current = self.scheduler.status(task_id)
                return self._verdict(current, "REPLAY", "UNKNOWN",
                                     "original owner observation already committed")
        liveness = classify(LivenessObservation(
            now_unix=now_unix, run_id=str(provider.run_id), fence=status["fence"],
            provider_state={"queued": "QUEUED", "in_progress": "RUNNING",
                            "completed": "COMPLETED"}[provider.status],
            provider_trusted=True, provider_run_id=str(provider.run_id),
            provider_fence=status["fence"],
            supervisor_trusted=health is not None,
            supervisor_run_id=str(health.run_id) if health else "",
            supervisor_fence=health.fence if health else 0,
            heartbeat_unix=health.heartbeat_unix if health else 0,
            lease_until_unix=int(status["lease_until"])))
        # Never derive result_manifest_verified, terminal_receipt_verified or
        # effect authorization from a provider conclusion.
        updated = self.scheduler.observe(task_id, provider.scheduler_record(),
                                         expected_revision=status["revision"],
                                         fence=status["fence"], owner=status["owner"],
                                         key=observation_key)
        return self._verdict(updated, "RECORDED", liveness.state, liveness.reason)

    def tick(self, task_ids, *, provider_reader, now_unix,
             max_observations=4, max_duration_ms=1000):
        """Finite batch; no sleep, background work, implicit task discovery or retry."""
        if type(task_ids) not in (tuple, list) or not 0 <= len(task_ids) <= 32:
            raise GuardError("bounded owner task selection required")
        if len(set(task_ids)) != len(task_ids):
            raise GuardError("duplicate task selected in owner tick")
        if (type(max_observations) is not int or not 1 <= max_observations <= 16
                or type(max_duration_ms) is not int or not 1 <= max_duration_ms <= 60_000):
            raise GuardError("invalid owner tick budgets")
        deadline = time.monotonic() + max_duration_ms / 1000
        verdicts = []
        for task in task_ids[:max_observations]:
            if time.monotonic() >= deadline:
                break
            verdicts.append(self.observe_once(task, provider_reader=provider_reader,
                                              now_unix=now_unix,
                                              deadline_monotonic=deadline))
        return tuple(verdicts)
