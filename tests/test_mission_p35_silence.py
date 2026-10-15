"""P35: many synthetic hours of stdout silence do not prove a failure.

No real background service or wall-clock time is simulated as deployed.
"""
from dataclasses import replace
import unittest

from universal.mission_liveness import Observation, classify
from universal.mission_observability import review_observation
from universal.mission_polling import PollCursor, plan_read


class LongSilentMissionTests(unittest.TestCase):
    def setUp(self):
        self.run_id = 'synthetic-silent-run'
        self.sha = 'a'*64

    def observed(self, now, *, heartbeat_age=1, provider='RUNNING'):
        return Observation(now_unix=now, run_id=self.run_id, fence=4,
            provider_state=provider, provider_trusted=True,
            provider_run_id=self.run_id, provider_fence=4,
            supervisor_trusted=True, supervisor_run_id=self.run_id,
            supervisor_fence=4, heartbeat_unix=now-heartbeat_age,
            lease_until_unix=now+60, output_progressed=False)

    def test_four_hour_silence_with_independently_fresh_health_is_not_failure(self):
        cursor = PollCursor(self.run_id, self.sha, 4, 5, 100, 20000, 3600)
        for now in (100, 3700, 7300, 10900, 14500):
            with self.subTest(now=now):
                state = classify(self.observed(now))
                self.assertEqual(state.state, 'SILENT_RUNNING')
                self.assertFalse(state.may_cancel)
                triage = review_observation(self.observed(now), cursor, now_unix=now)
                self.assertEqual(triage.health, 'HEALTHY')
                self.assertEqual(triage.owner_attention, 'NO_ALERT')
                plan = plan_read(cursor, now_unix=now, run_id=self.run_id,
                                 source_sha256=self.sha, fence=4, liveness=state.state)
                self.assertEqual(plan.action, 'READ_ONLY_POLL')
                cursor = plan.cursor
        self.assertEqual(cursor.polls_left, 0)
        exhausted = plan_read(cursor, now_unix=18000, run_id=self.run_id,
                              source_sha256=self.sha, fence=4, liveness='SILENT_RUNNING')
        self.assertEqual(exhausted.action, 'HANDOFF')

    def test_expired_health_is_suspect_but_never_killed(self):
        observation = self.observed(14500, heartbeat_age=5000)
        state = classify(observation)
        self.assertEqual(state.state, 'SUSPECT_RECOVERY')
        self.assertFalse(state.may_cancel)
        self.assertFalse(state.may_retry_write)

    def test_old_provider_fence_is_not_healthy(self):
        observation = replace(self.observed(14000), provider_fence=3)
        self.assertNotEqual(classify(observation).state, 'SILENT_RUNNING')


if __name__ == '__main__':
    unittest.main()
