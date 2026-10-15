"""P43: A/B and inert Floot inventory cannot cross project or owner scope."""
from dataclasses import replace
import unittest

from tests.test_mission_contracts import mission
from universal.mission_contracts import canonical
from universal.mission_projects import profile_from_mission, ReadCapability
from universal.mission_adapter_registry import AdapterSlot, InertAdapterRegistry


class InertAdapterRegistryTests(unittest.TestCase):
    def slot(self, project, *, kind='local', owner='owner-A'):
        data = mission(project)
        data['project']['kind'] = kind
        data['project']['owner'] = owner
        profile = profile_from_mission(canonical(data), now_unix=150)
        capability = ReadCapability(project_id=profile.project_id, kind=profile.kind,
            owner=profile.owner, base_version=profile.base_version,
            source_sha256=profile.source_sha256, contract_sha256=profile.contract_sha256,
            observed_unix=100, expires_unix=200, offline_possible=True,
            read_permission=True, budget_calls=0)
        return AdapterSlot(profile, capability)

    def test_a_b_distinct_and_default_router_off(self):
        a, b = self.slot('fixture-A'), self.slot('fixture-B')
        registry = InertAdapterRegistry((a,b))
        self.assertEqual(registry.project_ids(), ('fixture-A','fixture-B'))
        self.assertEqual(registry.preview(a.profile, now_unix=150).route, 'DISABLED')
        self.assertEqual(registry.preview(b.profile, now_unix=150, planner_enabled=True).route, 'OFFLINE')
        self.assertFalse(registry.preview(b.profile, now_unix=150, planner_enabled=True).execution_authorized)

    def test_cross_owner_version_and_source_cannot_reuse_slot(self):
        original = self.slot('fixture-A')
        registry = InertAdapterRegistry((original,))
        for changed in (replace(original.profile, owner='other-owner'),
                        replace(original.profile, base_version='v2'),
                        replace(original.profile, contract_sha256='b'*64),
                        replace(original.profile, source_sha256='c'*64),
                        replace(original.profile, kind='github')):
            with self.subTest(changed=changed):
                self.assertEqual(registry.preview(changed, now_unix=150, planner_enabled=True).route, 'BLOCK')

    def test_duplicate_ids_and_foreign_capability_denied(self):
        a = self.slot('fixture-A')
        b = self.slot('fixture-A', owner='other-owner')
        with self.assertRaises(ValueError):
            InertAdapterRegistry((a,b))
        with self.assertRaises(ValueError):
            InertAdapterRegistry((AdapterSlot(a.profile,b.capability),))

    def test_inert_floot_profile_has_no_runtime_connector(self):
        floot = self.slot('floot-fixture', kind='floot')
        registry = InertAdapterRegistry((floot,))
        self.assertEqual(registry.preview(floot.profile, now_unix=150).route, 'DISABLED')
        self.assertEqual(registry.preview(floot.profile, now_unix=150, planner_enabled=True).route, 'OFFLINE')
        self.assertFalse(hasattr(registry, 'dispatch'))
        self.assertFalse(hasattr(registry, 'apply'))
        with self.assertRaises(TypeError):
            registry._slots['unexpected'] = floot

    def test_registry_slots_cannot_be_replaced_after_validation(self):
        from types import MappingProxyType
        a, b = self.slot('fixture-A'), self.slot('fixture-B')
        registry = InertAdapterRegistry((a,))
        self.assertEqual(registry.preview(b.profile, now_unix=150, planner_enabled=True).route, 'BLOCK')
        with self.assertRaises((AttributeError, TypeError)):
            registry._slots = MappingProxyType({'fixture-B': b})
        with self.assertRaises((AttributeError, TypeError)):
            registry._new_slots = MappingProxyType({'fixture-B': b})
        self.assertEqual(registry.project_ids(), ('fixture-A',))
        self.assertEqual(registry.preview(b.profile, now_unix=150, planner_enabled=True).route, 'BLOCK')

    def test_expiry_does_not_infer_connected_tool(self):
        slot = self.slot('fixture-A')
        registry = InertAdapterRegistry((slot,))
        self.assertEqual(registry.preview(slot.profile, now_unix=200, planner_enabled=True).route, 'BLOCK')
        self.assertEqual(registry.preview(slot.profile, now_unix=True, planner_enabled=True).route, 'BLOCK')


if __name__ == '__main__':
    unittest.main()
