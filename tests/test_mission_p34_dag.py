"""P34: existing owner DAG advances only after independent local oracle."""
from pathlib import Path
import tempfile
import unittest

from tests.test_continuity_v8 import fixture_contract
from universal.continuity import ContinuityJournal
from universal.core import GuardError, Intent, Runtime, digest
from universal.mission_owner_oracle import verify_local_exact_sha


class MissionDAGContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mission-p34-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rt = Runtime(self.root/'owner.sqlite', clock=lambda: 150.)
        self.addCleanup(self.rt.close)
        for name, content, expected in (('A', 'alpha', 'ALPHA'),
                                        ('B', 'beta', 'BETA'),
                                        ('C', 'gamma', 'GAMMA')):
            self.rt.put_resource('source_'+name, content)
            self.rt.put_resource('out_'+name, '')
            self.rt.add_task('task_'+name, 'source_'+name, 'out_'+name, 'uppercase',
                             digest(expected), dependencies=['task_A'] if name == 'B' else ())

    def write(self, claim, name, value):
        intent = Intent(claim['run_id'], 'artifact.write', 'out_'+name, 1,
                        'write-'+name, claim['fence'], {'content': value})
        return self.rt.execute(intent, claim['token'])

    def oracle(self, claim, name, expected):
        return verify_local_exact_sha(self.rt, 'task_'+name, claim['run_id'], 'fixture-env',
            owner_output_resource='out_'+name, owner_expected_sha256=digest(expected))

    def test_next_task_claimed_without_new_human_go_after_oracle(self):
        self.assertIsNone(self.rt.claim('worker-B', task_id='task_B'))
        a = self.rt.claim('worker-A', task_id='task_A')
        self.write(a, 'A', 'ALPHA')
        self.assertIsNone(self.rt.claim('worker-B', task_id='task_B'))
        accepted = self.oracle(a, 'A', 'ALPHA')
        self.assertTrue(self.rt.proof_is_accepted_for_gate(accepted.evidence_id, 'fixture-env'))
        b = self.rt.claim('worker-B', task_id='task_B')
        self.assertEqual(b['task']['id'], 'task_B')
        self.assertTrue(self.rt.check_journal())

    def test_wrong_parent_oracle_fails_and_descendant_stays_unclaimable(self):
        a = self.rt.claim('worker-A', task_id='task_A')
        self.write(a, 'A', 'BAD')
        observation = self.oracle(a, 'A', 'ALPHA')
        self.assertEqual(observation.outcome, 'FAIL')
        self.assertFalse(observation.accepted_at_observation)
        self.assertIsNone(self.rt.claim('worker-B', task_id='task_B'))
        self.assertEqual(self.rt.task('task_B')['status'], 'READY')

    def test_independent_project_not_globally_blocked_by_failed_parent(self):
        a = self.rt.claim('worker-A', task_id='task_A')
        self.write(a, 'A', 'BAD')
        self.oracle(a, 'A', 'ALPHA')
        c = self.rt.claim('worker-C', task_id='task_C')
        self.assertIsNotNone(c)
        self.write(c, 'C', 'GAMMA')
        result = self.oracle(c, 'C', 'GAMMA')
        self.assertTrue(result.accepted_at_observation)
        self.assertIsNone(self.rt.claim('worker-B', task_id='task_B'))

    def test_revoked_parent_proof_cannot_unlock_fresh_descendant(self):
        a = self.rt.claim('worker-A', task_id='task_A')
        self.write(a, 'A', 'ALPHA')
        evidence = self.oracle(a, 'A', 'ALPHA')
        self.rt.revoke_evidence(evidence.evidence_id, 'owner-revoked')
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence.evidence_id, 'fixture-env'))
        self.assertIsNone(self.rt.claim('worker-B', task_id='task_B'))

    def test_existing_continuity_attempt_budget_blocks_unbounded_rework(self):
        clock = [100.]
        journal = ContinuityJournal(self.root/'continuity.sqlite', clock=lambda: clock[0])
        self.addCleanup(journal.close)
        contract = fixture_contract(self.root, budget=1, attempts=1)
        start = journal.create_task('bounded', contract, key='create')
        claim = journal.claim('bounded', 'owner', 'local_copy', expected_revision=start['revision'],
                              key='first', ttl=1)
        clock[0] = 102.
        recovered = journal.recover('bounded', expected_revision=claim['revision'], key='recover')
        self.assertEqual(recovered['state'], 'BLOCKED_BUDGET')
        with self.assertRaises(GuardError):
            journal.claim('bounded', 'owner', 'local_copy', expected_revision=recovered['revision'],
                          key='retry-unapproved')
        self.assertEqual(journal.get('bounded')['attempts'], 1)


if __name__ == '__main__':
    unittest.main()
