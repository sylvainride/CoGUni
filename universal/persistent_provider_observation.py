"""Bounded immutable owner-supplied provider readback; never an authentication proof.

Only a trusted host is permitted to construct observations from an authenticated
read-only provider connection. The dataclass, including its metadata, cannot
authenticate itself. Mission JSON and worker receipts are NOT suitable inputs.
"""
from dataclasses import dataclass
import re

from .core import GuardError

_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_BRANCH = re.compile(r"work/mvp-mission-transport-[A-Za-z0-9._/-]{1,96}\Z")
_STATUSES = frozenset({"queued", "in_progress", "completed"})
_CONCLUSIONS = frozenset({None, "success", "failure", "cancelled", "timed_out", "skipped"})


@dataclass(frozen=True, slots=True)
class ProviderObservation:
    """A single provider read, not a grant, signature, or worker assertion."""

    observation_id: str
    repository_id: int
    actor_id: int
    run_id: int
    attempt: int
    commit: str
    branch: str
    code_ref: str
    request_sha256: str
    status: str
    conclusion: str | None
    observed_unix: int

    def __post_init__(self):
        if type(self.observation_id) is not str or not _IDENT.fullmatch(self.observation_id):
            raise GuardError("invalid provider observation identity")
        for name, maximum in (("repository_id", 2**63 - 1), ("actor_id", 2**63 - 1),
                              ("run_id", 10**15 - 1), ("attempt", 100),
                              ("observed_unix", 2**63 - 1)):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= maximum or value == 0:
                raise GuardError("invalid provider numeric identity")
        if (type(self.commit) is not str or not _SHA40.fullmatch(self.commit)
                or type(self.code_ref) is not str or not _SHA40.fullmatch(self.code_ref)
                or type(self.request_sha256) is not str or not _SHA64.fullmatch(self.request_sha256)
                or type(self.branch) is not str or not _BRANCH.fullmatch(self.branch)):
            raise GuardError("invalid provider source/ref pin")
        if (type(self.status) is not str or self.status not in _STATUSES
                or (self.conclusion is not None and type(self.conclusion) is not str)
                or self.conclusion not in _CONCLUSIONS
                or (self.status != "completed" and self.conclusion is not None)
                or (self.status == "completed" and self.conclusion is None)):
            raise GuardError("invalid provider terminal status")

    def matched(self, status, *, now_unix, expected_repository_id, expected_actor_id):
        """Check against the CURRENT owner ledger, not a mission payload."""
        if (type(status) is not dict or type(now_unix) is not int or not 0 <= now_unix <= 2**63 - 1
                or type(expected_repository_id) is not int or type(expected_actor_id) is not int):
            raise GuardError("invalid owner provider binding")
        if (self.repository_id != expected_repository_id or self.actor_id != expected_actor_id
                or self.observed_unix > now_unix or now_unix - self.observed_unix > 3600
                or any(getattr(self, name) != status[name] for name in ("branch", "code_ref", "request_sha256"))):
            raise GuardError("provider readback not bound to current owner source")
        previous = status["provider"]
        if previous and any(getattr(self, name) != previous[name] for name in ("run_id", "attempt", "commit")):
            raise GuardError("provider run/attempt/commit substituted")
        if previous and previous["status"] == "completed" and self.status != "completed":
            raise GuardError("terminal provider read regressed")
        return self

    def scheduler_record(self):
        """Only the exact existing OwnerScheduler.observe schema is emitted."""
        return {name: getattr(self, name) for name in (
            "repository_id", "actor_id", "run_id", "attempt", "commit", "branch",
            "code_ref", "request_sha256", "status", "conclusion")}
