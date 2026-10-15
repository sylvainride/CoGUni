"""Private source-bound handoff never mutates a running lease or replays work."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from universal.continuity import ContinuityJournal
from universal.core import GuardError
from universal.mission_admission import admit_synthetic
from universal.mission_contracts import canonical
from universal.mission_handoff import export_offline_handoff, import_offline_handoff
from universal.mission_polling import PollCursor
from tests.test_mission_contracts import mission


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='handoff-owner-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.now = [150]
        self.db = ContinuityJournal(self.base / 'journal.sqlite', clock=lambda: self.now[0])
        self.addCleanup(self.db.close)
        self.src = self.base / 'source.txt'
        self.src.write_text('fixture-only', encoding='utf-8')
        payload = mission()
        self.sha = hashlib.sha256(self.src.read_bytes()).hexdigest()
        payload['source_sha256'] = self.sha
        self.task = admit_synthetic(self.db, canonical(payload), now_unix=150,
                                    source_path=str(self.src), output_path=str(self.base/'out.txt'))['id']
        self.row = self.db.get(self.task)

    def cursor(self):
        return PollCursor(self.task, self.sha, self.row['fence'], 3, 150, 260, 30)

    def snapshot(self):
        return export_offline_handoff(self.db, self.task, self.cursor(), now_unix=self.now[0])

    def test_ready_handoff_is_never_a_worker_grant(self):
        before = self.db.get(self.task)
        hint = import_offline_handoff(self.db, self.snapshot(), now_unix=150)
        self.assertEqual(hint.state, 'OWNER_CLAIM_REQUIRED')
        self.assertFalse(hint.execution_authorized)
        self.assertEqual(self.db.get(self.task), before)
        self.assertTrue(self.db.verify_chain())

    def test_chat_end_does_not_cancel_a_healthy_owner_run(self):
        self.row = self.db.claim(self.task, 'owner', 'offline_fixture', expected_revision=self.row['revision'],
                                 key='start', ttl=60)
        recorded = self.db.get(self.task)
        wire = self.snapshot()
        self.now[0] = 180
        self.assertEqual(import_offline_handoff(self.db, wire, now_unix=180).state, 'OBSERVE_ONLY')
        self.assertEqual(self.db.get(self.task), recorded)
        self.now[0] = 210
        self.assertEqual(import_offline_handoff(self.db, wire, now_unix=210).state, 'OWNER_RECOVERY_REQUIRED')
        self.assertEqual(self.db.get(self.task), recorded)

    def test_untrusted_handoff_clock_cannot_falsify_owner_lease(self):
        self.row = self.db.claim(self.task, 'owner', 'offline_fixture', expected_revision=self.row['revision'],
                                 key='start', ttl=60)
        wire = self.snapshot()
        # The durable journal clock, not a caller-supplied message timestamp,
        # controls the lease. Premature expiry must never be inferred.
        self.now[0] = 180
        before = self.db.get(self.task)
        self.assertEqual(import_offline_handoff(self.db, wire, now_unix=9999).state, 'OBSERVE_ONLY')
        # Conversely, an outdated Chat timestamp must not hide actual expiry.
        self.now[0] = 210
        self.assertEqual(import_offline_handoff(self.db, wire, now_unix=151).state,
                         'OWNER_RECOVERY_REQUIRED')
        self.assertEqual(self.db.get(self.task), before)
        self.assertTrue(self.db.verify_chain())

    def test_restart_same_journal_revalidates(self):
        wire = self.snapshot()
        self.db.close()
        self.db = ContinuityJournal(self.base / 'journal.sqlite', clock=lambda: self.now[0])
        self.addCleanup(self.db.close)
        self.assertEqual(import_offline_handoff(self.db, wire, now_unix=150).state, 'OWNER_CLAIM_REQUIRED')

    def test_reject_cross_journal_and_stale_revision(self):
        wire = self.snapshot()
        foreign = ContinuityJournal(self.base / 'foreign.sqlite', clock=lambda: 150)
        self.addCleanup(foreign.close)
        with self.assertRaises(GuardError):
            import_offline_handoff(foreign, wire, now_unix=150)
        self.row = self.db.claim(self.task, 'owner', 'offline_fixture', expected_revision=self.row['revision'],
                                 key='start', ttl=30)
        with self.assertRaises(GuardError):
            import_offline_handoff(self.db, wire, now_unix=151)

    def test_tampered_digest_fence_run_and_schema_denied(self):
        original = json.loads(self.snapshot())
        for key, value in (('digest', '0'*64), ('run_id', 'other'), ('expected_fence', 100),
                           ('schema_version', 2), ('authority', 'OWNER_GRANT')):
            tampered = copy.deepcopy(original)
            tampered[key] = value
            with self.subTest(key=key), self.assertRaises(GuardError):
                import_offline_handoff(self.db, canonical(tampered), now_unix=150)

    def test_unpaired_unicode_and_oversize_message_rejected_before_owner_read(self):
        # Neither an invalid scalar nor an oversized handoff string may raise
        # an unhandled codec error or cause any journal mutation.
        initial = self.db.get(self.task)
        for raw in ('\ud800', '\udfff', 'a' * 8193, b'a' * 8193):
            with self.subTest(value_type=type(raw).__name__, length=len(raw)):
                with self.assertRaises(GuardError):
                    import_offline_handoff(self.db, raw, now_unix=150)
        self.assertEqual(self.db.get(self.task), initial)
        self.assertTrue(self.db.verify_chain())

    def test_source_drift_prevents_resume(self):
        wire = self.snapshot()
        self.src.write_text('changed', encoding='utf-8')
        hint = import_offline_handoff(self.db, wire, now_unix=150)
        self.assertEqual(hint.state, 'BLOCKED_SOURCE')
        self.assertFalse(hint.execution_authorized)

    def test_symlink_to_foreign_source_denied(self):
        wire = self.snapshot()
        other = self.base/'target'
        other.write_text('fixture-only', encoding='utf-8')
        self.src.unlink()
        self.src.symlink_to(other)
        self.assertEqual(import_offline_handoff(self.db, wire, now_unix=150).state, 'BLOCKED_SOURCE')


if __name__ == '__main__':
    unittest.main()
