"""Disabled-by-default pure planning and in-memory fixtures; no executor.

Simulated budgets are not runtime grants, leases, fences or consent. Even an
explicitly enabled planner never authorizes an effect, opens a browser, reads a
credential or makes a network call. The existing owner broker remains required.
"""
from dataclasses import dataclass, field
import re


@dataclass(frozen=True)
class Request:
    task: str
    api_available: bool
    cli_available: bool
    browser_available: bool
    offline_possible: bool
    network_permission: bool
    browser_permission: bool
    contains_secret: bool
    budget_calls: int


@dataclass(frozen=True)
class Decision:
    route: str
    reason: str
    execution_authorized: bool = field(default=False, init=False)


def select(req, *, enabled=False):
    if type(req) is not Request or type(enabled) is not bool:
        raise ValueError('plain request and explicit boolean flag required')
    if type(req.task) is not str or req.task not in {'READ', 'LOCAL_COMPUTE', 'WRITE'}:
        return Decision('DENY', 'unknown task')
    if type(req.budget_calls) is not int or req.budget_calls < 0:
        return Decision('DENY', 'invalid simulated budget')
    if any(type(getattr(req, name)) is not bool for name in (
            'api_available', 'cli_available', 'browser_available', 'offline_possible',
            'network_permission', 'browser_permission', 'contains_secret')):
        return Decision('DENY', 'invalid capability or permission type')
    if req.contains_secret:
        return Decision('DENY', 'secret-bearing input requires separate trust flow')
    if req.task == 'WRITE':
        return Decision('DENY', 'planner never plans effects')
    if not enabled:
        return Decision('DISABLED', 'experimental planner is OFF')
    if req.offline_possible:
        return Decision('OFFLINE', 'feasible without an external effect')
    if req.budget_calls == 0:
        return Decision('DENY', 'no simulated call allowance')
    if not req.network_permission:
        return Decision('DENY', 'external access not permitted')
    if req.api_available:
        return Decision('FAKE_API', 'API-first')
    if req.cli_available:
        return Decision('FAKE_CLI', 'CLI before browser')
    if req.browser_available and req.browser_permission:
        return Decision('SIMULATED_BROWSER', 'browser-last')
    return Decision('DENY', 'no permitted route')


@dataclass(frozen=True)
class Budget:
    calls: int
    millis: int
    cpu_ms: int
    retries: int

    def __post_init__(self):
        if any(type(x) is not int or not 0 <= x <= 10**9 for x in
               (self.calls, self.millis, self.cpu_ms, self.retries)):
            raise ValueError('invalid bounded simulated budget')

    def charge(self, *, calls=0, millis=0, cpu_ms=0, retries=0):
        charges = (calls, millis, cpu_ms, retries)
        if any(type(x) is not int or x < 0 for x in charges):
            raise ValueError('invalid simulated charge')
        balance = tuple(a - b for a, b in zip((self.calls, self.millis, self.cpu_ms, self.retries), charges))
        if any(x < 0 for x in balance):
            raise ValueError('BUDGET_EXCEEDED')
        return Budget(*balance)


@dataclass(frozen=True)
class FakeResponse:
    status: int
    body: dict
    uncertainty: bool = False
    retry_allowed: bool = False


class FakeReadOnlyAPI:
    """In-memory read-only fault fixture, no HTTP client or real quota."""

    def __init__(self, *, scopes=frozenset({'read'}), fault='OK', budget=None):
        if type(scopes) not in (set, frozenset) or not scopes <= {'read'}:
            raise ValueError('fake read-only scope required')
        if type(fault) is not str:
            raise ValueError('invalid fixture fault')
        if budget is not None and type(budget) is not Budget:
            raise ValueError('fake budget required')
        self.scopes, self.fault = frozenset(scopes), fault
        self.budget = Budget(1, 10, 10, 0) if budget is None else budget
        self.calls = 0

    def read(self, key):
        if type(key) is not str or not re.fullmatch(r'synthetic:[A-Za-z0-9._-]{1,64}', key):
            return FakeResponse(400, {'code': 'BAD_INPUT'})
        if 'read' not in self.scopes:
            return FakeResponse(403, {'code': 'SCOPE_DENIED'})
        self.budget = self.budget.charge(calls=1, millis=1, cpu_ms=1)
        self.calls += 1
        codes = {'UNAUTHENTICATED': 401, 'FORBIDDEN': 403, 'RATELIMIT': 429,
                 'TIMEOUT': 504, 'UNKNOWN': 503}
        if self.fault in codes:
            return FakeResponse(codes[self.fault], {'code': self.fault},
                                self.fault in {'TIMEOUT', 'UNKNOWN'})
        if self.fault != 'OK':
            return FakeResponse(400, {'code': 'UNKNOWN_FIXTURE'})
        return FakeResponse(200, {'value': key, 'source': 'FAKE_ONLY'})


class BrowserSession:
    """Simulated reservation only; terminal failure and closure release it."""
    _allowed = {'NEEDED': {'ACTIVE', 'CLOSED', 'FAILED'},
                'ACTIVE': {'API_VERIFIED', 'CLOSED', 'FAILED'},
                'API_VERIFIED': {'CLOSED', 'FAILED'}, 'CLOSED': set(), 'FAILED': set()}

    def __init__(self):
        self._state, self._reserved, self._transitions = 'NEEDED', False, 0

    @property
    def state(self):
        return self._state

    @property
    def reserved(self):
        return self._reserved

    @property
    def secret_observed(self):
        return False

    def move(self, target, *, key=None):
        if type(target) is not str or target not in self._allowed[self._state]:
            raise ValueError('invalid simulated browser transition')
        if key is not None:
            raise ValueError('credentials may not cross this interface')
        if self._transitions >= 4:
            raise ValueError('transition budget reached')
        self._state = target
        self._reserved = target in {'ACTIVE', 'API_VERIFIED'}
        self._transitions += 1
        return target
