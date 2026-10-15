"""Bounded owner-side admission calculation, with no effects or grants.

Inputs must come from the owner journal, not a worker verdict. Selection alone
does not reserve a resource, authenticate ACLs, refresh a version, dispatch work
or authorize application. The persistent facade must do those under its existing
transaction/fence, then use the existing runtime and outbox.
"""
from dataclasses import dataclass
import re

from .dag import topological_order

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}\Z")
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_PATH = re.compile(r"/[A-Za-z0-9._/-]*\Z")
_REF = re.compile(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}\Z")
STATES = frozenset({"READY", "IN_FLIGHT", "RESULT_READY", "APPLY_PENDING",
                    "UNKNOWN_EFFECT", "SUSPECT", "HANDOFF", "ACCEPTED_APPLIED",
                    "BLOCKED", "FAILED_CONFIRMED", "CANCELLED"})
HOLDING_STATES = frozenset({"IN_FLIGHT", "RESULT_READY", "APPLY_PENDING",
                            "UNKNOWN_EFFECT", "SUSPECT", "HANDOFF"})
WORK_CLASSES = frozenset({"READ_SOURCE", "COMPUTE_ONLY", "PROPOSE_CHANGE", "APPLY_TARGET"})


def _identifier(value):
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError("invalid resource/task identity")


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid bounded integer")


def _path(value):
    if (type(value) is not str or not 1 <= len(value) <= 512
            or not _PATH.fullmatch(value) or "//" in value
            or any(part in {".", ".."} for part in value.split("/"))
            or (value != "/" and value.endswith("/"))):
        raise ValueError("noncanonical resource path")


def _ref(value):
    if type(value) is not str:
        raise ValueError("invalid source ref")
    if _SHA.fullmatch(value):
        return
    if (not _REF.fullmatch(value) or "//" in value or ".." in value
            or "@{" in value or value.endswith(("/", ".", ".lock"))
            or any(part.startswith(".") or part.endswith(".lock") for part in value.split("/"))):
        raise ValueError("invalid source ref")


@dataclass(frozen=True)
class Access:
    provider: str
    repo_id: int
    project_id: str
    ref: str
    path: str
    mode: str
    expected_sha: str
    physical_id: str
    immutable: bool = False

    def __post_init__(self):
        if type(self.provider) is not str or self.provider not in {"github", "local"}:
            raise ValueError("unsupported resource provider")
        _integer(self.repo_id, 1, 2**63 - 1)
        _identifier(self.project_id)
        _identifier(self.physical_id)
        _ref(self.ref)
        _path(self.path)
        if type(self.mode) is not str or self.mode not in {"R", "W"}:
            raise ValueError("invalid access mode")
        if type(self.expected_sha) is not str or not _SHA.fullmatch(self.expected_sha):
            raise ValueError("immutable expected version required")
        if type(self.immutable) is not bool or (self.immutable and self.mode != "R"):
            raise ValueError("only pinned reads may be immutable")
        if self.immutable and self.ref != self.expected_sha:
            raise ValueError("immutable read must address its pinned snapshot")


@dataclass(frozen=True)
class Work:
    task_id: str
    depends_on: tuple[str, ...]
    accesses: tuple[Access, ...]
    state: str = "READY"
    work_class: str = "PROPOSE_CHANGE"
    run_cost: int = 1
    duration_seconds: int = 300
    authorized: bool = False

    def __post_init__(self):
        _identifier(self.task_id)
        if type(self.depends_on) is not tuple or len(self.depends_on) > 32:
            raise ValueError("bounded immutable dependencies required")
        for dependency in self.depends_on:
            _identifier(dependency)
        if len(set(self.depends_on)) != len(self.depends_on) or self.task_id in self.depends_on:
            raise ValueError("duplicate/self dependency")
        if (type(self.accesses) is not tuple or not 1 <= len(self.accesses) <= 32
                or any(type(access) is not Access for access in self.accesses)):
            raise ValueError("bounded typed resource claims required")
        if len(set(self.accesses)) != len(self.accesses):
            raise ValueError("duplicate access")
        if type(self.state) is not str or self.state not in STATES:
            raise ValueError("invalid owner state")
        if type(self.work_class) is not str or self.work_class not in WORK_CLASSES:
            raise ValueError("invalid work class")
        if self.work_class in {"READ_SOURCE", "COMPUTE_ONLY"} and any(a.mode != "R" for a in self.accesses):
            raise ValueError("read/compute stage cannot claim a write")
        _integer(self.run_cost, 1, 32)
        _integer(self.duration_seconds, 1, 3600)
        if type(self.authorized) is not bool:
            raise ValueError("owner authorization flag required")


@dataclass(frozen=True)
class Decision:
    selected: tuple[str, ...]
    blocked: tuple[tuple[str, str], ...]
    held: tuple[str, ...]
    execution_authorized: bool = False


def _owner_resource_policy(resource_aliases, case_insensitive_targets):
    if type(resource_aliases) is not tuple or len(resource_aliases) > 128:
        raise ValueError("bounded owner resource aliases required")
    aliases = {}
    for pair in resource_aliases:
        if type(pair) is not tuple or len(pair) != 2:
            raise ValueError("invalid owner alias")
        source, target = pair
        _identifier(source)
        _identifier(target)
        if source in aliases or source == target:
            raise ValueError("duplicate/self resource alias")
        aliases[source] = target
    def canonical(identity):
        seen = set()
        while identity in aliases:
            if identity in seen:
                raise ValueError("resource alias cycle")
            seen.add(identity)
            identity = aliases[identity]
        return identity
    for identity in aliases:
        canonical(identity)
    if type(case_insensitive_targets) is not tuple or len(case_insensitive_targets) > 128:
        raise ValueError("bounded owner case policy required")
    for identity in case_insensitive_targets:
        _identifier(identity)
    if len(set(case_insensitive_targets)) != len(case_insensitive_targets):
        raise ValueError("duplicate case policy")
    return canonical, {canonical(identity) for identity in case_insensitive_targets}


def _overlap(left, right):
    # Root needs special handling; '/'+ '/' must not turn into '//'.
    return (left == right or left == "/" or right == "/"
            or left.startswith(right + "/") or right.startswith(left + "/"))


def _conflicts(left, right, canonical, insensitive):
    for a in left.accesses:
        identity = canonical(a.physical_id)
        for b in right.accesses:
            if identity != canonical(b.physical_id):
                continue
            a_path, b_path = a.path, b.path
            if identity in insensitive:
                a_path, b_path = a_path.casefold(), b_path.casefold()
            if _overlap(a_path, b_path) and not (a.immutable and b.immutable):
                return True
    return False


def conflicts(left, right, *, resource_aliases=(), case_insensitive_targets=()):
    """Owner-defined physical target aliases override branch identities.

    An immutable read is a pinned snapshot, not a live view of a mutable target.
    Mutable reads conservatively retain the resource through owner reconciliation.
    Filesystem/symlink discovery is a host responsibility; no I/O occurs here.
    """
    if type(left) is not Work or type(right) is not Work:
        raise ValueError("typed owner work required")
    canonical, insensitive = _owner_resource_policy(resource_aliases, case_insensitive_targets)
    return _conflicts(left, right, canonical, insensitive)


def select_ready(tasks, *, enabled=False, max_parallel=2, remaining_runs=0,
                 remaining_seconds=0, max_backlog=128, resource_aliases=(),
                 case_insensitive_targets=()):
    """Return a deterministic, budgeted eligible subset; never dispatch or grant.

    Budgets are the owner's *remaining unreserved* run count and aggregate runner
    seconds, not a prediction of wall time. Active/unknown/result-pending tasks
    retain resources and slots even when permission or budgets are later reduced.
    Only owner ACCEPTED_APPLIED satisfies a dependency, not worker completion.
    """
    if type(enabled) is not bool:
        raise ValueError("explicit owner opt-in required")
    _integer(max_parallel, 1, 8)
    _integer(remaining_runs, 0, 1024)
    _integer(remaining_seconds, 0, 1024 * 3600)
    _integer(max_backlog, 1, 256)
    if type(tasks) not in (tuple, list) or len(tasks) > max_backlog:
        raise ValueError("bounded task backlog required")
    if any(type(task) is not Work for task in tasks):
        raise ValueError("typed owner work required")
    tasks = tuple(sorted(tasks, key=lambda task: task.task_id))
    by_id = {task.task_id: task for task in tasks}
    if len(by_id) != len(tasks):
        raise ValueError("duplicate task identity")
    topological_order({task.task_id: task.depends_on for task in tasks})
    canonical, insensitive = _owner_resource_policy(resource_aliases, case_insensitive_targets)
    identities = {}
    for task in tasks:
        for access in task.accesses:
            identity = canonical(access.physical_id)
            domain = (access.provider, access.repo_id, access.project_id)
            if identity in identities and identities[identity] != domain:
                raise ValueError("physical target identity changed")
            identities[identity] = domain
    active = [task for task in tasks if task.state in HOLDING_STATES]
    slots = max(0, max_parallel - len(active))
    selected, blocked = [], []
    for task in tasks:
        if task.state != "READY":
            continue
        if not enabled:
            reason = "DISABLED"
        elif not task.authorized:
            reason = "OWNER_PERMISSION_REQUIRED"
        elif any(by_id[dependency].state != "ACCEPTED_APPLIED" for dependency in task.depends_on):
            reason = "DEPENDENCY_NOT_APPLIED"
        elif any(_conflicts(task, held, canonical, insensitive) for held in active + selected):
            reason = "RESOURCE_HELD"
        elif slots == 0:
            reason = "PARALLEL_LIMIT"
        elif task.run_cost > remaining_runs or task.duration_seconds > remaining_seconds:
            reason = "BUDGET_EXHAUSTED"
        else:
            selected.append(task)
            remaining_runs -= task.run_cost
            remaining_seconds -= task.duration_seconds
            slots -= 1
            continue
        blocked.append((task.task_id, reason))
    return Decision(tuple(task.task_id for task in selected), tuple(blocked),
                    tuple(task.task_id for task in active))
