"""P47 scoped D0-D2 offline acceptance, with D3/D4 explicitly NOT_RUN.

This is a fixture-level integration of existing owner Runtime, Outbox, oracle
and DAG. It is not a Chat transport, real Floot apply, signed generative proof
or production end-to-end delivery.
"""
from pathlib import Path
import tempfile
import unittest

from tests.test_mission_contracts import mission
from universal.mission_contracts import canonical
from universal.mission_projects import profile_from_mission, ReadCapability
from universal.core import GuardError, Runtime, Intent, digest
from universal.mission_adapter_registry import InertAdapterRegistry, AdapterSlot
from universal.mission_owner_oracle import verify_local_exact_sha
from universal.mission_floot_handoff import preview_manual_floot_plan
from universal.outbox import Outbox, FakeAdapter


class OfflineAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='p47-offline-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rt = Runtime(self.root/'owner.sqlite', clock=lambda: 150.)
        self.addCleanup(self.rt.close)
        self.fake = FakeAdapter(self.root/'effects.sqlite')
        self.addCleanup(self.fake.close)
        for name, before, expected in (('A','alpha','ALPHA'),('B','beta','BETA')):
            self.rt.put_resource('src_'+name,before)
            self.rt.put_resource('out_'+name,'')
            self.rt.add_task('task_'+name,'src_'+name,'out_'+name,'uppercase',
                digest(expected),dependencies=['task_A'] if name=='B' else ())

    def test_fake_effect_then_independent_owner_validation_then_next_task(self):
        # D0: two owner-defined local projects, exact output scopes.
        self.assertIsNone(self.rt.claim('worker-B',task_id='task_B'))
        claim = self.rt.claim('worker-A',task_id='task_A')
        intent = Intent(claim['run_id'],'artifact.write','out_A',1,
                        'apply-A-synthetic',claim['fence'],{'content':'ALPHA'})
        box = Outbox(self.rt)
        row = box.prepare(intent,claim['token'])
        receipt = box.dispatch(row['key'],claim['token'],row['revision'],self.fake)
        self.assertEqual(receipt['state'],'COMMITTED')
        self.assertEqual(self.fake.statistics()['semantic_effects'],1)
        self.assertEqual(self.rt.resource('out_A')['version'],1)
        # D1: fake adapter ACK has no independent oracle authority.
        with self.assertRaises(GuardError):
            verify_local_exact_sha(self.rt,'task_A',claim['run_id'],'local-test',
                         owner_output_resource='out_A',owner_expected_sha256=digest('ALPHA'))
        self.assertIsNone(self.rt.claim('worker-B',task_id='task_B'))
        # The existing owner-local Runtime effect is a separate explicit step.
        self.rt.execute(intent,claim['token'])
        inspected=verify_local_exact_sha(self.rt,'task_A',claim['run_id'],'local-test',
                         owner_output_resource='out_A',owner_expected_sha256=digest('ALPHA'))
        self.assertTrue(inspected.accepted_at_observation)
        self.assertFalse(inspected.remote_effect_authorized)
        # D2: existing DAG can now claim the successor without Chat authority.
        successor = self.rt.claim('worker-B',task_id='task_B')
        self.assertIsNotNone(successor)
        self.assertTrue(self.rt.check_journal())
        self.assertEqual(self.fake.statistics()['semantic_effects'],1)

    def test_failure_does_not_auto_advance_or_recover_as_success(self):
        claim = self.rt.claim('worker-A',task_id='task_A')
        wrong = Intent(claim['run_id'],'artifact.write','out_A',1,'wrong-A',
                       claim['fence'],{'content':'WRONG'})
        self.rt.execute(wrong,claim['token'])
        verdict=verify_local_exact_sha(self.rt,'task_A',claim['run_id'],'local-test',
                    owner_output_resource='out_A',owner_expected_sha256=digest('ALPHA'))
        self.assertEqual(verdict.outcome,'FAIL')
        self.assertFalse(verdict.accepted_at_observation)
        self.assertIsNone(self.rt.claim('worker-B',task_id='task_B'))

    def test_d3_d4_are_explicitly_unconnected_and_not_applied(self):
        m = mission('synthetic-only-floot')
        m['project']['kind'] = 'floot'
        profile = profile_from_mission(canonical(m), now_unix=150)
        cap = ReadCapability(project_id=profile.project_id, kind=profile.kind, owner=profile.owner,
            base_version=profile.base_version, source_sha256=profile.source_sha256,
            contract_sha256=profile.contract_sha256, observed_unix=100, expires_unix=200,
            offline_possible=True, read_permission=True, budget_calls=0)
        slot = AdapterSlot(profile, cap)
        registry=InertAdapterRegistry((slot,))
        self.assertEqual(registry.preview(slot.profile,now_unix=150).route,'DISABLED')
        plan=preview_manual_floot_plan(registry,slot.profile,now_unix=150)
        self.assertEqual(plan.state,'NOT_APPLIED')
        self.assertFalse(plan.connected)
        self.assertFalse(plan.effect_authorized)
        self.assertFalse(plan.deployable)


if __name__=='__main__':
    unittest.main()
