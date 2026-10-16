"""Real owner SQLite journal, synthetic sources, no worker or remote effect."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from universal.continuity import ContinuityJournal
from universal.core import GuardError
from universal.mission_admission import admit_synthetic
from universal.mission_contracts import canonical, MissionContractError
from tests.test_mission_contracts import mission


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mission-admission-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.journal_path = self.base / 'owner-journal.sqlite'
        self.journal = ContinuityJournal(self.journal_path, clock=lambda: 150.)
        self.addCleanup(self.journal.close)
        self.src = self.base / 'source.txt'
        self.src.write_text('fixture-only', encoding='utf-8')
        self.dst = self.base / 'output.txt'
        self.payload = mission()
        self.payload['source_sha256'] = hashlib.sha256(self.src.read_bytes()).hexdigest()

    def admit(self, payload=None):
        return admit_synthetic(self.journal, canonical(self.payload if payload is None else payload),
                               now_unix=150, source_path=str(self.src), output_path=str(self.dst))

    def test_admits_in_existing_owner_journal_and_replays_without_new_task(self):
        first = self.admit()
        self.assertEqual(first['state'], 'READY')
        self.assertFalse(first['replayed'])
        self.assertTrue(self.admit()['replayed'])
        self.assertEqual(len(self.journal.events()), 1)
        self.assertTrue(self.journal.verify_chain())
        self.assertEqual(first['contract']['sources'][str(self.src)], self.payload['source_sha256'])

    def test_crash_restart_ack_loss_replay(self):
        self.admit()
        self.journal.close()
        self.journal = ContinuityJournal(self.journal_path, clock=lambda: 150.)
        self.addCleanup(self.journal.close)
        self.assertTrue(self.admit()['replayed'])
        self.assertEqual(len(self.journal.events()), 1)

    def test_same_key_changed_content_refused_and_no_effect(self):
        self.admit()
        changed = copy.deepcopy(self.payload)
        changed['contract']['objective'] = 'changed after replay'
        with self.assertRaises(GuardError):
            self.admit(changed)
        self.assertEqual(len(self.journal.events()), 1)

    def test_separate_projects_do_not_cross_task_id_or_key(self):
        first = self.admit()
        other = copy.deepcopy(self.payload)
        other['project']['id'] = 'fixture-B'
        second = self.admit(other)
        self.assertNotEqual(first['id'], second['id'])
        self.assertEqual(len(self.journal.events()), 2)

    def test_private_remote_or_nonzero_cost_refused(self):
        for edit in (lambda m: m['project'].update(kind='github'),
                     lambda m: m['contract'].update(max_external_cost=1),
                     lambda m: m['contract'].update(allowed_actions=['write']),
                     lambda m: m['contract'].update(dependencies=['previous'])):
            changed = copy.deepcopy(self.payload)
            edit(changed)
            with self.assertRaises((GuardError, MissionContractError)):
                self.admit(changed)
        self.assertEqual(len(self.journal.events()), 0)

    def test_source_drift_and_invalid_target_refused(self):
        self.src.write_text('changed', encoding='utf-8')
        with self.assertRaises(GuardError):
            self.admit()
        self.assertEqual(len(self.journal.events()), 0)
        self.src.write_text('fixture-only', encoding='utf-8')
        with self.assertRaises(GuardError):
            admit_synthetic(self.journal, canonical(self.payload), now_unix=150,
                            source_path=str(self.src), output_path=str(self.src))
        self.assertEqual(len(self.journal.events()), 0)


if __name__ == '__main__':
    unittest.main()
