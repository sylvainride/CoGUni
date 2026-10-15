"""Bounded poll planning, stale identities, silent execution, handoff."""
import unittest
from universal.mission_polling import PollCursor, plan_read

SHA = 'a' * 64


class PollTests(unittest.TestCase):
    def setUp(self):
        self.cursor = PollCursor('run-A', SHA, 3, 2, 100, 500, 20)

    def step(self, **updates):
        args = {'now_unix': 100, 'run_id': 'run-A', 'source_sha256': SHA,
                'fence': 3, 'liveness': 'SILENT_RUNNING'}
        args.update(updates)
        return plan_read(self.cursor, **args)

    def test_silent_running_uses_read_budget_without_cancelling(self):
        first = self.step()
        self.assertEqual(first.action, 'READ_ONLY_POLL')
        self.assertEqual((first.cursor.polls_left, first.cursor.next_unix), (1, 120))
        self.assertEqual(plan_read(first.cursor, now_unix=110, run_id='run-A', source_sha256=SHA,
                                   fence=3, liveness='SILENT_RUNNING').action, 'WAIT')
        last = plan_read(first.cursor, now_unix=120, run_id='run-A', source_sha256=SHA,
                         fence=3, liveness='SILENT_RUNNING')
        self.assertEqual(last.cursor.polls_left, 0)
        self.assertEqual(plan_read(last.cursor, now_unix=140, run_id='run-A', source_sha256=SHA,
                                   fence=3, liveness='SILENT_RUNNING').action, 'HANDOFF')

    def test_unknown_effect_requires_reconciliation(self):
        result = self.step(liveness='UNKNOWN_EFFECT')
        self.assertEqual(result.action, 'RECONCILE')
        self.assertEqual(result.cursor, self.cursor)

    def test_fence_source_and_run_mismatch_do_not_consume_budget(self):
        for changes in ({'fence': 4}, {'source_sha256': 'b' * 64}, {'run_id': 'run-B'},
                        {'liveness': 'UNTRUSTED_PASS'}):
            with self.subTest(changes=changes):
                result = self.step(**changes)
                self.assertEqual(result.action, 'BLOCK')
                self.assertEqual(result.cursor, self.cursor)

    def test_terminal_handoff_timeout_distinct(self):
        self.assertEqual(self.step(liveness='RESULT_READY').action, 'STOP')
        self.assertEqual(self.step(liveness='CHAT_HANDOFF').action, 'HANDOFF')
        self.assertEqual(self.step(now_unix=500).action, 'HANDOFF')

    def test_invalid_budget_and_flags_refused(self):
        for changes in ({'polls_left': -1}, {'interval_seconds': 0}, {'next_unix': 501},
                        {'fence': True}, {'source_sha256': 'BAD'}):
            kwargs = dict(run_id='run-A', source_sha256=SHA, fence=3, polls_left=2,
                          next_unix=100, stop_unix=500, interval_seconds=20)
            kwargs.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                PollCursor(**kwargs)
        with self.assertRaises(ValueError):
            self.step(now_unix=True)


if __name__ == '__main__':
    unittest.main()
