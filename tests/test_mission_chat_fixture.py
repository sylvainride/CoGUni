"""Synthetic A/B submission to existing SQLite and read-only result preview."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from universal.continuity import ContinuityJournal
from universal.core import GuardError
from universal.mission_admission import admit_synthetic
from universal.mission_chat_fixture import preview_synthetic_task
from universal.mission_contracts import canonical, fingerprint
from tests.test_mission_contracts import mission


class ChatFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-chat-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.db = ContinuityJournal(self.base/'journal.sqlite', clock=lambda: 150)
        self.addCleanup(self.db.close)

    def submit(self, project, text):
        src = self.base/(project + '.txt')
        src.write_bytes(text)
        m = mission(project)
        m['mission_id'] = 'mission-' + project
        m['idempotency_key'] = 'fixture-key-' + project
        m['source_sha256'] = hashlib.sha256(text).hexdigest()
        out = self.base/(project + '.out')
        r = admit_synthetic(self.db, canonical(m), now_unix=150,
                            source_path=str(src), output_path=str(out))
        return r, src, out

    def test_end_to_end_two_projects_and_replay_no_execution(self):
        a, sa, oa = self.submit('fixture-A', b'a\nb\n')
        b, sb, ob = self.submit('fixture-B', b'hello world\n')
        av = preview_synthetic_task(self.db, a['id'])
        bv = preview_synthetic_task(self.db, b['id'])
        self.assertEqual(av['result_state'], 'PREVIEW_ONLY')
        self.assertFalse(av['accepted'])
        self.assertFalse(av['action_executed'])
        self.assertEqual((av['byte_count'], av['line_break_count']), (4, 2))
        self.assertNotEqual(av['digest'], bv['digest'])
        self.assertEqual(av['digest'], fingerprint({k:v for k,v in av.items() if k != 'digest'}))
        self.assertFalse(oa.exists())
        self.assertFalse(ob.exists())
        self.assertEqual(len(self.db.events()), 2)

    def test_reconnect_reads_same_bound_preview(self):
        a, _, _ = self.submit('fixture-A', b'synthetic\n')
        first = preview_synthetic_task(self.db, a['id'])
        self.db.close()
        self.db = ContinuityJournal(self.base/'journal.sqlite', clock=lambda: 150)
        self.addCleanup(self.db.close)
        self.assertEqual(preview_synthetic_task(self.db, a['id']), first)

    def test_source_drift_and_symlink_replacement_denied(self):
        a, src, _ = self.submit('fixture-A', b'x')
        src.write_bytes(b'y')
        with self.assertRaises(GuardError):
            preview_synthetic_task(self.db, a['id'])
        src.unlink()
        target = self.base/'target'
        target.write_bytes(b'x')
        src.symlink_to(target)
        with self.assertRaises(GuardError):
            preview_synthetic_task(self.db, a['id'])

    def test_worker_forged_contract_cannot_preview(self):
        _, _, _ = self.submit('fixture-A', b'x')
        with self.assertRaises(GuardError):
            preview_synthetic_task(self.db, 'foreign-task')
        with self.assertRaises(GuardError):
            preview_synthetic_task(self.db, True)


if __name__ == '__main__':
    unittest.main()
