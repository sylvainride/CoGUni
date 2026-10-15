"""P44: inert, synthetic-only manual Chat-applies plan for a Floot-shaped profile.

This file neither imports Floot SDKs nor calls any Floot project, service,
backend, account or deployment API. The plan is not a credential, grant,
verified artifact, application request or remote receipt.
"""
from dataclasses import dataclass

from .mission_adapter_registry import InertAdapterRegistry
from .mission_projects import ProjectProfile


@dataclass(frozen=True)
class ManualFlootPlan:
    project_id: str
    owner: str
    base_version: str
    source_sha256: str
    contract_sha256: str
    route: str = 'MANUAL_REVIEW_ONLY'
    state: str = 'NOT_APPLIED'
    effect_authorized: bool = False
    connected: bool = False
    deployable: bool = False


def preview_manual_floot_plan(registry, profile, *, now_unix):
    """Emit an inert manual review plan only for a registered synthetic fixture.

    An actual user action would require separate authenticated connection,
    project scope and permission; none exists in this interface.
    """
    if type(registry) is not InertAdapterRegistry or type(profile) is not ProjectProfile:
        raise ValueError('typed inert registry and owner profile required')
    if profile.kind != 'floot' or profile.privacy != 'PUBLIC_SYNTHETIC':
        raise ValueError('synthetic Floot-shaped project only')
    decision = registry.preview(profile, now_unix=now_unix)
    if decision.route != 'DISABLED':
        raise ValueError('unsupported or expired owner profile')
    return ManualFlootPlan(profile.project_id, profile.owner, profile.base_version,
                           profile.source_sha256, profile.contract_sha256)
