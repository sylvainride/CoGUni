"""Inert, source-bound project and tool capability profiles (P11/P12).

These are *observations*, not authenticators or permissions. A connected
connector in the Chat does not create a connection in the CoGUni runtime.
The existing pure tool_router is the sole route selector. No effects, grants,
credentials, model requests, browser sessions or network calls occur here.
"""
from dataclasses import dataclass
import re

from .mission_contracts import decode_mission, fingerprint, MissionContractError
from .tool_router import Request, select

_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z')
_SHA = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True)
class ProjectProfile:
    kind: str
    project_id: str
    owner: str
    source_of_truth: str
    base_version: str
    source_sha256: str
    privacy: str
    contract_sha256: str


@dataclass(frozen=True)
class ReadCapability:
    """Non-authoritative bounded observation tied to an exact project version."""
    project_id: str
    base_version: str
    source_sha256: str
    observed_unix: int
    expires_unix: int
    api_declared: bool = False
    api_callable: bool = False
    api_tested: bool = False
    api_connected: bool = False
    cli_declared: bool = False
    cli_callable: bool = False
    cli_tested: bool = False
    cli_connected: bool = False
    browser_declared: bool = False
    browser_callable: bool = False
    browser_tested: bool = False
    browser_connected: bool = False
    offline_possible: bool = False
    network_permission: bool = False
    browser_permission: bool = False
    read_permission: bool = False
    contains_secret: bool = False
    budget_calls: int = 0

    def __post_init__(self):
        if type(self.project_id) is not str or not 1 <= len(self.project_id) <= 160:
            raise ValueError('invalid capability project')
        if type(self.base_version) is not str or not 1 <= len(self.base_version) <= 160:
            raise ValueError('invalid capability version')
        if type(self.source_sha256) is not str or not _SHA.fullmatch(self.source_sha256):
            raise ValueError('invalid capability source SHA')
        for name in ('observed_unix', 'expires_unix', 'budget_calls'):
            val = getattr(self, name)
            if type(val) is not int or not 0 <= val <= 2**63 - 1:
                raise ValueError('invalid capability numeric field')
        if self.budget_calls > 10**6 or self.expires_unix - self.observed_unix > 3600 or self.expires_unix <= self.observed_unix:
            raise ValueError('unbounded capability observation')
        for name in self.__dataclass_fields__:
            if name in {'project_id', 'base_version', 'source_sha256', 'observed_unix', 'expires_unix', 'budget_calls'}:
                continue
            if type(getattr(self, name)) is not bool:
                raise ValueError('invalid capability boolean')


@dataclass(frozen=True)
class ReadPlan:
    route: str
    reason: str
    execution_authorized: bool = False


def profile_from_mission(raw, *, now_unix):
    """Extract exact project/source/policy identity from a validated envelope."""
    env = decode_mission(raw, now_unix=now_unix)
    p = env['project']
    return ProjectProfile(p['kind'], p['id'], p['owner'], p['source_of_truth'],
                          p['base_version'], env['source_sha256'], env['privacy'],
                          fingerprint(env['contract']))


def preview_read_route(profile, observation, *, now_unix, planner_enabled=False):
    """Conservative, non-executable wrapper around the existing router.

    Even a returned FAKE_API route is a simulation, NEVER a runtime connection.
    Capability flags are owner observations, not signed provider attestations.
    """
    if type(profile) is not ProjectProfile or type(observation) is not ReadCapability:
        return ReadPlan('BLOCK', 'typed project/capability required')
    if type(now_unix) is not int or type(planner_enabled) is not bool or now_unix < 0:
        return ReadPlan('BLOCK', 'invalid observation time or planner flag')
    if (profile.project_id, profile.base_version, profile.source_sha256) != (
            observation.project_id, observation.base_version, observation.source_sha256):
        return ReadPlan('BLOCK', 'foreign project, stale source or version')
    if not observation.observed_unix <= now_unix < observation.expires_unix:
        return ReadPlan('BLOCK', 'stale or future capability observation')
    if profile.privacy != 'PUBLIC_SYNTHETIC' or observation.contains_secret:
        return ReadPlan('DENY', 'private or secret-bearing work requires separate authorization')
    if not observation.read_permission:
        return ReadPlan('DENY', 'read scope not granted in capability observation')
    if not planner_enabled:
        return ReadPlan('DISABLED', 'inert tool router OFF')
    api = all((observation.api_declared, observation.api_callable,
               observation.api_tested, observation.api_connected))
    cli = all((observation.cli_declared, observation.cli_callable,
               observation.cli_tested, observation.cli_connected))
    browser = all((observation.browser_declared, observation.browser_callable,
                   observation.browser_tested, observation.browser_connected))
    selection = select(Request('READ', api, cli, browser, observation.offline_possible,
                               observation.network_permission, observation.browser_permission,
                               observation.contains_secret, observation.budget_calls), enabled=True)
    return ReadPlan(selection.route, 'INERT_ONLY: ' + selection.reason)
