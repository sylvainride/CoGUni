"""Offline liveness and silence classification with explicit trust boundaries."""
import unittest
from universal.mission_liveness import Observation, classify


class LivenessTests(unittest.TestCase):
    def healthy(self, **kwargs):
        values = dict(now_unix=1800, run_id='run-A', fence=7, provider_state='RUNNING',
                      provider_trusted=True, provider_run_id='run-A', provider_fence=7,
                      supervisor_trusted=True, supervisor_run_id='run-A', supervisor_fence=7,
                      heartbeat_unix=1799, lease_until_unix=1900)
        values.update(kwargs)
        return Observation(**values)

    def test_silent_job_still_running(self):
        self.assertEqual(classify(self.healthy()).state, 'SILENT_RUNNING')
        self.assertEqual(classify(self.healthy(output_progressed=True)).state, 'RUNNING')
        self.assertFalse(classify(self.healthy()).may_cancel)

    def test_stale_or_mismatched_supervisor_is_only_suspect(self):
        for changes in ({'heartbeat_unix': 100}, {'lease_until_unix': 1700},
                        {'supervisor_run_id': 'run-B'}, {'supervisor_fence': 8},
                        {'supervisor_trusted': False}):
            with self.subTest(changes=changes):
                self.assertEqual(classify(self.healthy(**changes)).state, 'SUSPECT_RECOVERY')

    def test_worker_claim_without_provider_never_proves_running(self):
        self.assertEqual(classify(self.healthy(provider_trusted=False)).state, 'SUSPECT_RECOVERY')
        self.assertEqual(classify(Observation(now_unix=1800, run_id='run-A', fence=1)).state, 'UNKNOWN')

    def test_terminal_requires_matching_receipt_not_just_state(self):
        for state in ('FAILED', 'CANCELLED', 'COMPLETED'):
            self.assertEqual(classify(self.healthy(provider_state=state)).state, 'UNKNOWN')
        self.assertEqual(classify(self.healthy(provider_state='COMPLETED', result_manifest_verified=True)).state, 'RESULT_READY')
        self.assertEqual(classify(self.healthy(provider_state='FAILED', terminal_receipt_verified=True)).state, 'FAILED_CONFIRMED')
        self.assertEqual(classify(self.healthy(provider_state='FAILED', terminal_receipt_verified=True,
                                                provider_run_id='run-B')).state, 'SUSPECT_RECOVERY')

    def test_unknown_effect_never_retries_and_chat_handoff_not_cancel(self):
        d = classify(self.healthy(effect_ack_unknown=True))
        self.assertEqual(d.state, 'UNKNOWN_EFFECT')
        self.assertFalse(d.may_retry_write)
        self.assertFalse(d.may_cancel)
        self.assertEqual(classify(self.healthy(chat_handoff=True)).state, 'CHAT_HANDOFF')

    def test_strict_bounded_flags_and_time(self):
        for changes in ({'now_unix': True}, {'provider_trusted': 1}, {'run_id': ''},
                        {'fence': -1}, {'heartbeat_grace_seconds': 0},
                        {'provider_state': 'UNTRUSTED_PASS'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                classify(self.healthy(**changes))


if __name__ == '__main__':
    unittest.main()
