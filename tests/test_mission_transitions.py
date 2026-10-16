"""Adversarial pure state-order oracles without claimed owner authority."""
import unittest
from universal.mission_transitions import transition_eligible
from tests.test_mission_contracts import event


class TransitionTests(unittest.TestCase):
    def step(self, previous, target, **changes):
        return dict(previous, event_seq=previous['event_seq'] + 1,
                    revision=previous['revision'] + 1,
                    observed_unix=previous['observed_unix'] + 1,
                    state=target, **changes)

    def test_silent_then_running_or_result_allowed_without_claimed_pass(self):
        start = event()
        silent = self.step(start, 'SILENT_RUNNING')
        result = self.step(silent, 'RESULT_READY')
        self.assertTrue(transition_eligible(start, silent))
        self.assertTrue(transition_eligible(silent, result))
        self.assertFalse(transition_eligible(start, self.step(start, 'ACCEPTED')))

    def test_unknown_effect_is_terminal_and_does_not_auto_retry(self):
        before = event()
        unknown = self.step(before, 'UNKNOWN_EFFECT')
        self.assertTrue(transition_eligible(before, unknown))
        self.assertFalse(transition_eligible(unknown, self.step(unknown, 'RUNNING')))
        self.assertFalse(transition_eligible(unknown, self.step(unknown, 'APPLIED')))

    def test_worker_may_not_claim_apply_or_accept(self):
        before = dict(event(), state='RESULT_INSPECTED')
        self.assertFalse(transition_eligible(before, self.step(before, 'APPLY_REQUESTED')))
        verified = dict(before, state='VERIFYING')
        self.assertFalse(transition_eligible(verified, self.step(verified, 'ACCEPTED')))

    def test_identity_seq_revision_fence_and_lease_cas(self):
        old = dict(event(), lease_until_unix=200)
        good = self.step(old, 'SILENT_RUNNING')
        self.assertTrue(transition_eligible(old, good))
        for update in ({'mission_id': 'other'}, {'run_id': 'other'}, {'source_sha256': 'b'*64},
                       {'event_seq': 0}, {'revision': 1}, {'fence': 0},
                       {'observed_unix': 100}, {'lease_until_unix': 300}):
            self.assertFalse(transition_eligible(old, dict(good, **update)))
        owner = dict(good, fence=2, lease_until_unix=300, proof_kind='OWNER_JOURNAL')
        self.assertTrue(transition_eligible(old, owner))

    def test_handoff_not_a_new_run_and_no_permissive_edges(self):
        start = event()
        self.assertFalse(transition_eligible(start, self.step(start, 'CHAT_HANDOFF')))
        self.assertFalse(transition_eligible(start, self.step(start, 'QUEUED')))
        self.assertFalse(transition_eligible(start, self.step(start, 'APPLY_REQUESTED')))
        with_project = dict(start, project_id='project-A')
        self.assertFalse(transition_eligible(with_project, dict(self.step(with_project, 'RESULT_READY'), project_id='project-B')))


if __name__ == '__main__':
    unittest.main()
