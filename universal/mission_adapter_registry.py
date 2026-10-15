"""P43: immutable, inert multi-project routing inventory. Not an executor.

Owner-supplied observations only; no SDKs, tokens, provider calls or grants.
Route previews reuse mission_projects.preview_read_route, which in turn
reuses the disabled-by-default tool_router. A listed route is not connected.
"""
from dataclasses import dataclass
from types import MappingProxyType

from .mission_projects import ProjectProfile, ReadCapability, ReadPlan, preview_read_route


@dataclass(frozen=True)
class AdapterSlot:
    profile: ProjectProfile
    capability: ReadCapability


class InertAdapterRegistry:
    def __init__(self, slots=()):
        if type(slots) is not tuple or len(slots) > 24:
            raise ValueError('bounded immutable adapter slots required')
        by_id = {}
        for slot in slots:
            if type(slot) is not AdapterSlot or type(slot.profile) is not ProjectProfile or type(slot.capability) is not ReadCapability:
                raise ValueError('typed adapter profile and observation required')
            profile, cap = slot.profile, slot.capability
            if ((profile.project_id, profile.kind, profile.owner, profile.base_version,
                 profile.source_sha256, profile.contract_sha256) !=
                    (cap.project_id, cap.kind, cap.owner, cap.base_version,
                     cap.source_sha256, cap.contract_sha256)):
                raise ValueError('capability does not bind exact owner/project/contract')
            if profile.project_id in by_id:
                raise ValueError('duplicate project ID, including incompatible owner')
            by_id[profile.project_id] = slot
        self._slots = MappingProxyType(by_id)

    def project_ids(self):
        return tuple(sorted(self._slots))

    def preview(self, profile, *, now_unix, planner_enabled=False):
        if type(profile) is not ProjectProfile:
            return ReadPlan('BLOCK', 'trusted profile type required')
        slot = self._slots.get(profile.project_id)
        if slot is None or slot.profile != profile:
            return ReadPlan('BLOCK', 'unknown or changed project identity')
        return preview_read_route(slot.profile, slot.capability, now_unix=now_unix,
                                  planner_enabled=planner_enabled)
