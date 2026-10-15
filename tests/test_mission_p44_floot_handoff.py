"""P44: non-connected Floot-shaped manual plan is never an effect."""
from dataclasses import replace
import unittest

from tests.test_mission_p43_registry import InertAdapterRegistryTests
from universal.mission_adapter_registry import InertAdapterRegistry
from universal.mission_floot_handoff import preview_manual_floot_plan


class FlootManualHandoffTests(unittest.TestCase):
    def setUp(self):
        self.slot = InertAdapterRegistryTests().slot('synthetic-floot', kind='floot')
        self.registry = InertAdapterRegistry((self.slot,))

    def test_manual_plan_has_no_connected_or_applied_effect(self):
        plan = preview_manual_floot_plan(self.registry,self.slot.profile,now_unix=150)
        self.assertEqual(plan.state,'NOT_APPLIED')
        self.assertEqual(plan.route,'MANUAL_REVIEW_ONLY')
        self.assertFalse(plan.effect_authorized)
        self.assertFalse(plan.connected)
        self.assertFalse(plan.deployable)

    def test_foreign_owner_or_version_rejected(self):
        for changed in (replace(self.slot.profile, owner='other'),
                        replace(self.slot.profile, base_version='v2')):
            with self.assertRaises(ValueError):
                preview_manual_floot_plan(self.registry,changed,now_unix=150)

    def test_non_floot_and_expired_inputs_refused(self):
        with self.assertRaises(ValueError):
            preview_manual_floot_plan(self.registry,replace(self.slot.profile,kind='local'),now_unix=150)
        with self.assertRaises(ValueError):
            preview_manual_floot_plan(self.registry,self.slot.profile,now_unix=200)


if __name__ == '__main__':
    unittest.main()
