"""P45 adversarial triage: no false cancellation, no private canaries in logs."""
from dataclasses import replace
import json
import unittest

from universal.mission_liveness import Observation
from universal.mission_polling import PollCursor
from universal.mission_observability import review_observation

CANARY = 'PRIVATE_CANARY_SHOULD_NOT_APPEAR'
SHA = 'a'*64


class MissionObservabilityTests(unittest.TestCase):
    def setUp(self):
        self.run = 'run-' + CANARY
        self.observation = Observation(now_unix=150, run_id=self.run, fence=3,
                          provider_state='RUNNING', provider_trusted=True,
                          provider_run_id=self.run, provider_fence=3,
                          supervisor_trusted=True, supervisor_run_id=self.run,
                          supervisor_fence=3, heartbeat_unix=149,
                          lease_until_unix=205, output_progressed=False)
        self.cursor = PollCursor(self.run, SHA, 3, 2, 150, 200, 30)

    def inspect(self, ob=None, cursor=None, now_unix=150):
        return review_observation(self.observation if ob is None else ob,
                                  self.cursor if cursor is None else cursor, now_unix=now_unix)

    def test_healthy_silence_never_cancels_or_alerts(self):
        result = self.inspect()
        self.assertEqual(result.health, 'HEALTHY')
        self.assertEqual(result.owner_attention, 'NO_ALERT')
        self.assertFalse(result.alert_sent)
        self.assertFalse(result.cancel_authorized)
        self.assertFalse(result.accepted)

    def test_fenced_run_blocks_even_with_matching_fake_provider_status(self):
        stale = replace(self.cursor, fence=2)
        result = self.inspect(cursor=stale)
        self.assertEqual(result.health, 'BLOCKED_SCOPE')
        self.assertEqual(result.owner_attention, 'OWNER_RECHECK_IDENTITY')

    def test_stale_supervisor_is_suspect_not_confirmed_failure(self):
        stale=replace(self.observation, heartbeat_unix=20)
        result=self.inspect(ob=stale)
        self.assertEqual(result.health, 'SUSPECT')
        self.assertEqual(result.owner_attention, 'OWNER_INVESTIGATION')
        self.assertFalse(result.cancel_authorized)

    def test_ack_unknown_requires_reconciliation_and_never_new_write(self):
        result=self.inspect(ob=replace(self.observation, effect_ack_unknown=True))
        self.assertEqual(result.health, 'UNKNOWN_EFFECT')
        self.assertEqual(result.owner_attention, 'OWNER_RECONCILIATION')
        self.assertFalse(result.write_retry_authorized)

    def test_missing_trusted_provider_is_not_healthy(self):
        result=self.inspect(ob=replace(self.observation, provider_trusted=False))
        self.assertNotEqual(result.health, 'HEALTHY')

    def test_canary_and_full_run_id_never_leave_redacted_projection(self):
        result=self.inspect()
        wire=json.dumps(result.__dict__, sort_keys=True)
        self.assertNotIn(CANARY, wire)
        self.assertNotIn(self.run, wire)
        self.assertLessEqual(len(result.run_tag), 16)

    def test_truthy_time_or_untyped_payload_fails(self):
        with self.assertRaises(ValueError):
            self.inspect(now_unix=True)
        with self.assertRaises(ValueError):
            review_observation({'RUNNING':True}, self.cursor, now_unix=150)


if __name__ == '__main__':
    unittest.main()
