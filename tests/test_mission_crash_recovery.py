"""Owner-journal crash/reopen and no-blind-retry cross-module synthetic oracles.

No real external effect is exercised; these qualify local admission/recovery,
not global exactly-once execution across a production adapter.
"""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from universal.continuity import ContinuityJournal
from universal.core import GuardError
from universal.mission_admission import admit_synthetic
from universal.mission_contracts import canonical
from universal.mission_handoff import export_offline_handoff, import_offline_handoff
from universal.mission_polling import PollCursor, plan_read
from tests.test_mission_contracts import mission


class MissionCrashRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mission-recovery-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.now = [150]
        self.db_path = self.base / 'journal.sqlite'
        self.db = ContinuityJournal(self.db_path, clock=lambda: self.now[0])
        self.addCleanup(self.db.close)
        self.src = self.base / 'source.txt'
        self.src.write_bytes(b'fixture-atomic')
        self.dst = self.base / 'output.txt'
        self.payload = mission()
        self.payload['source_sha256'] = hashlib.sha256(self.src.read_bytes()).hexdigest()

    def submit(self, value=None):
        return admit_synthetic(self.db, canonical(value if value is not None else self.payload),
                               now_unix=150, source_path=str(self.src), output_path=str(self.dst))

    def restart(self):
        self.db.close()
        self.db = ContinuityJournal(self.db_path, clock=lambda: self.now[0])
        self.addCleanup(self.db.close)

    def test_ack_loss_restart_reuses_same_admission_only(self):
        row = self.submit()
        self.restart()
        replay = self.submit()
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['id'], row['id'])
        self.assertEqual(len(self.db.events()), 1)
        self.assertTrue(self.db.verify_chain())
        self.assertFalse(self.dst.exists())

    def test_key_collision_after_restart_rejected_with_original_contract(self):
        row = self.submit()
        self.restart()
        tampered = copy.deepcopy(self.payload)
        tampered['contract']['objective'] = 'new unauthorized objective'
        with self.assertRaises(GuardError):
            self.submit(tampered)
        self.assertEqual(self.db.get(row['id'])['contract'], row['contract'])
        self.assertEqual(len(self.db.events()), 1)

    def test_fenced_expired_lease_refuses_stale_handoff(self):
        initial = self.submit()
        claimed = self.db.claim(initial['id'], 'owner', 'offline_fixture',
                                expected_revision=initial['revision'], key='claim', ttl=5)
        cursor = PollCursor(initial['id'], self.payload['source_sha256'], claimed['fence'], 2, 150, 240)
        saved = export_offline_handoff(self.db, initial['id'], cursor, now_unix=150)
        self.restart()
        self.now[0] = 156
        recovered = self.db.recover(initial['id'], expected_revision=claimed['revision'], key='recover')
        self.assertEqual(recovered['state'], 'PAUSED')
        self.assertGreater(recovered['fence'], claimed['fence'])
        with self.assertRaises(GuardError):
            import_offline_handoff(self.db, saved, now_unix=156)
        self.assertFalse(self.dst.exists())

    def test_source_changed_while_chat_offline_blocks_resume(self):
        initial = self.submit()
        self.restart()
        self.src.write_bytes(b'changed')
        claimed = self.db.claim(initial['id'], 'owner', 'offline_fixture',
                                expected_revision=initial['revision'], key='claim')
        self.assertEqual(claimed['state'], 'BLOCKED_SOURCE')
        self.assertFalse(self.dst.exists())

    def test_unknown_effect_reconciliation_has_no_retry_command(self):
        row = self.submit()
        cursor = PollCursor(row['id'], self.payload['source_sha256'], row['fence'], 3, 150, 250)
        plan = plan_read(cursor, now_unix=150, run_id=row['id'], source_sha256=cursor.source_sha256,
                         fence=cursor.fence, liveness='UNKNOWN_EFFECT')
        self.assertEqual(plan.action, 'RECONCILE')
        self.assertEqual(plan.cursor, cursor)
        self.assertEqual(self.db.get(row['id'])['state'], 'READY')
        self.assertFalse(self.dst.exists())


if __name__ == '__main__':
    unittest.main()
