"""P36: two disconnected Chat turns cannot duplicate a fake SQLite effect."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from tests.test_mission_contracts import mission
from universal.continuity import ContinuityJournal
from universal.core import GuardError, Intent, Runtime, digest
from universal.mission_admission import admit_synthetic
from universal.mission_contracts import canonical
from universal.mission_handoff import export_offline_handoff, import_offline_handoff
from universal.mission_polling import PollCursor
from universal.outbox import FakeAdapter, Outbox


class TwoTurnMissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mission-two-turns-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = [150.]
        self.runtime_path = self.root/'runtime.sqlite'
        self.effect_path = self.root/'fake-effects.sqlite'
        self.continuity_path = self.root/'continuity.sqlite'

    def owner_runtime(self):
        return Runtime(self.runtime_path, clock=lambda: self.clock[0])

    def test_lost_ack_second_turn_reconciles_same_run_without_write_retry(self):
        with self.owner_runtime() as rt, FakeAdapter(self.effect_path) as adapter:
            rt.put_resource('source', 'alpha')
            rt.put_resource('output', '')
            rt.add_task('T', 'source', 'output', 'uppercase', digest('ALPHA'))
            claim = rt.claim('owner', task_id='T', ttl=120)
            intent = Intent(claim['run_id'], 'artifact.write', 'output', 1,
                            'same-business-key', claim['fence'], {'content':'ALPHA'})
            box = Outbox(rt)
            row = box.prepare(intent, claim['token'])
            def lose_ack(point):
                if point == 'after_effect_before_ack':
                    raise RuntimeError('synthetic_ack_lost')
            with self.assertRaises(RuntimeError):
                box.dispatch(row['key'], claim['token'], row['revision'], adapter,
                             crash_hook=lose_ack)
            uncertain = box.status('same-business-key')
            self.assertEqual(uncertain['state'], 'UNKNOWN')
            self.assertEqual(adapter.statistics()['semantic_effects'], 1)
            original_run = claim['run_id']
        # A distinct session/process-owned connection reloads the *same* stores.
        with self.owner_runtime() as rt, FakeAdapter(self.effect_path) as adapter:
            box = Outbox(rt)
            uncertain = box.status('same-business-key')
            self.assertEqual(uncertain['state'], 'UNKNOWN')
            with self.assertRaises(GuardError):
                box.dispatch('same-business-key', claim['token'], uncertain['revision'], adapter)
            reconciled = box.reconcile('same-business-key', uncertain['revision'], adapter)
            self.assertEqual(reconciled['state'], 'COMMITTED')
            self.assertEqual(adapter.statistics()['semantic_effects'], 1)
            self.assertEqual(adapter.statistics()['calls']['apply'], 1)
            self.assertEqual(rt.db.execute('SELECT run FROM simulated_outbox WHERE key=?',
                ('same-business-key',)).fetchone()[0], original_run)
            self.assertTrue(rt.check_journal())

    def test_handoff_second_turn_is_read_only_and_preserves_owner_lease(self):
        src = self.root/'fixture.txt'
        src.write_bytes(b'offline fixture')
        envelope = mission()
        envelope['source_sha256'] = hashlib.sha256(src.read_bytes()).hexdigest()
        with ContinuityJournal(self.continuity_path, clock=lambda: self.clock[0]) as journal:
            row = admit_synthetic(journal, canonical(envelope), now_unix=150,
                     source_path=str(src), output_path=str(self.root/'out.txt'))
            active = journal.claim(row['id'], 'owner', 'offline_fixture',
                                   expected_revision=row['revision'], key='claim', ttl=120)
            cursor = PollCursor(row['id'], envelope['source_sha256'], active['fence'],
                                2, 150, 300, 30)
            wire = export_offline_handoff(journal, row['id'], cursor, now_unix=150)
            prior_events = len(journal.events())
        with ContinuityJournal(self.continuity_path, clock=lambda: self.clock[0]) as journal:
            hint = import_offline_handoff(journal, wire, now_unix=160)
            self.assertEqual(hint.state, 'OBSERVE_ONLY')
            self.assertFalse(hint.execution_authorized)
            self.assertEqual(journal.get(row['id'])['state'], 'RUNNING')
            self.assertEqual(len(journal.events()), prior_events)
            with self.assertRaises(GuardError):
                journal.claim(row['id'], 'other', 'offline_fixture',
                              expected_revision=active['revision'], key='duplicate')


if __name__ == '__main__':
    unittest.main()
