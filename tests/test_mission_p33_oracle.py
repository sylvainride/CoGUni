"""P33: positive/negative independent owner oracle, no worker PASS shortcut."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from universal.core import GuardError, Intent, Runtime, digest
from universal.mission_owner_oracle import verify_local_exact_sha
from universal.outbox import Outbox, FakeAdapter


class IndependentMissionOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mission-p33-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rt = Runtime(self.root/'owner.sqlite', clock=lambda: 150.0)
        self.addCleanup(self.rt.close)
        self.rt.put_resource('source_A', 'alpha')
        self.rt.put_resource('out_A', '')
        self.rt.add_task('task_A', 'source_A', 'out_A', 'uppercase', digest('ALPHA'))
        self.claim = self.rt.claim('worker-A', task_id='task_A', ttl=60)

    def intent(self, value='ALPHA'):
        return Intent(self.claim['run_id'], 'artifact.write', 'out_A', 1,
                      'write-A', self.claim['fence'], {'content': value})

    def oracle(self, **changes):
        args = dict(runtime=self.rt, task_id='task_A', expected_run_id=self.claim['run_id'],
                    environment='owner-test-env', owner_output_resource='out_A',
                    owner_expected_sha256=digest('ALPHA'))
        args.update(changes)
        return verify_local_exact_sha(**args)

    def test_fake_outbox_ack_is_not_independent_oracle(self):
        adapter = FakeAdapter(self.root/'fake.sqlite')
        self.addCleanup(adapter.close)
        outbox = Outbox(self.rt)
        prepared = outbox.prepare(self.intent(), self.claim['token'])
        ack = outbox.dispatch(prepared['key'], self.claim['token'], prepared['revision'], adapter)
        self.assertEqual(ack['state'], 'COMMITTED')
        self.assertEqual(self.rt.resource('out_A')['version'], 1)
        with self.assertRaises(GuardError):
            self.oracle()
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0], 0)

    def test_true_owner_oracle_after_local_effect_produces_scoped_gate_proof(self):
        self.rt.execute(self.intent(), self.claim['token'])
        result = self.oracle()
        self.assertEqual(result.outcome, 'PASS')
        self.assertTrue(result.accepted_at_observation)
        self.assertEqual(result.output_sha256, digest('ALPHA'))
        self.assertTrue(self.rt.proof_is_accepted_for_gate(result.evidence_id, 'owner-test-env'))
        self.assertFalse(result.signed_generative_proof)
        self.assertFalse(result.remote_effect_authorized)
        self.assertFalse(self.rt.proof_is_accepted_for_gate(result.evidence_id, 'foreign-env'))

    def test_actual_wrong_output_yields_fail_even_if_worker_claims_pass(self):
        self.rt.execute(self.intent('WRONG'), self.claim['token'])
        result = self.oracle()
        self.assertEqual(result.outcome, 'FAIL')
        self.assertFalse(result.accepted_at_observation)
        self.assertTrue(self.rt.proof_is_fresh(result.evidence_id))
        self.assertFalse(self.rt.proof_is_accepted_for_gate(result.evidence_id, 'owner-test-env'))

    def test_cross_project_and_wrong_run_rejected_before_verifier(self):
        self.rt.put_resource('source_B', 'beta')
        self.rt.put_resource('out_B', '')
        self.rt.add_task('task_B', 'source_B', 'out_B', 'uppercase', digest('BETA'))
        self.rt.execute(self.intent(), self.claim['token'])
        for kwargs in ({'task_id': 'task_B'}, {'expected_run_id': 'run-foreign'},
                       {'owner_output_resource': 'out_B'},
                       {'owner_expected_sha256': digest('BETA')},
                       {'owner_expected_sha256': 'INVALID'}, {'environment': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(GuardError):
                self.oracle(**kwargs)
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0], 0)

    def test_revocation_and_source_mutation_invalidate_old_acceptance(self):
        self.rt.execute(self.intent(), self.claim['token'])
        got = self.oracle()
        self.rt.revoke_evidence(got.evidence_id, 'owner-withdrawal')
        self.assertFalse(self.rt.proof_is_accepted_for_gate(got.evidence_id, 'owner-test-env'))
        self.assertTrue(self.rt.proof_is_fresh(got.evidence_id))
        self.rt.put_resource('source_A', 'changed', 1)
        self.assertFalse(self.rt.proof_is_fresh(got.evidence_id))

    def test_stale_post_verification_must_not_promote_pass(self):
        self.rt.execute(self.intent(), self.claim['token'])
        with patch.object(self.rt, '_proof_is_accepted_for_gate', return_value=False):
            with self.assertRaises(GuardError):
                self.oracle()


if __name__ == '__main__':
    unittest.main()
