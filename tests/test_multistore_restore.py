"""Cold, coordinated snapshot/restore on test-owned stores and fixed locators.

Writers are quiescent in this harness. No production backup coordinator, global
transaction, physical disk failure, encryption or new-host claim is implied.
"""
from pathlib import Path
from contextlib import closing
import shutil
import sqlite3
import tempfile
import unittest

from tests.test_continuity_v8 import fixture_contract
from universal.core import Runtime, Intent, GuardError, digest
from universal.continuity import ContinuityJournal
from universal.outbox import Outbox, FakeAdapter


def cold_backup(paths, backup_root):
    backup_root.mkdir()
    for name, path in paths.items():
        with closing(sqlite3.connect(path)) as source, closing(sqlite3.connect(backup_root / (name + '.sqlite'))) as target:
            source.backup(target)


def restore_test_copies(paths, backup_root):
    # Refuse incomplete sets before replacing any test-owned store.
    if any(not (backup_root / (name + '.sqlite')).is_file() for name in paths):
        raise GuardError('coordinated snapshot incomplete', 'BLOCK')
    for name, path in paths.items():
        for suffix in ('', '-wal', '-shm'):
            Path(str(path) + suffix).unlink(missing_ok=True)
        shutil.copyfile(backup_root / (name + '.sqlite'), path)


class MultistoreRestoreTests(unittest.TestCase):
    def setup_stores(self, root):
        paths = {name: root / (name + '.sqlite') for name in ['owner', 'fake', 'continuity']}
        with Runtime(paths['owner'], clock=lambda: 100) as rt, FakeAdapter(paths['fake']) as adapter:
            rt.put_resource('input', 'alpha')
            rt.put_resource('output', '')
            rt.add_task('T', 'input', 'output', 'uppercase', digest('ALPHA'))
            claim = rt.claim('owner', ttl=60)
            box = Outbox(rt)
            row = box.prepare(Intent(claim['run_id'], 'artifact.write', 'output', 1, 'effect', claim['fence'],
                                     {'content': 'ALPHA'}), claim['token'], budget=2)
            def lose_ack(point):
                if point == 'after_effect_before_ack':
                    raise RuntimeError('synthetic ACK loss after fake commit')
            with self.assertRaises(RuntimeError):
                box.dispatch('effect', claim['token'], row['revision'], adapter, crash_hook=lose_ack)
            self.assertEqual(box.status('effect')['state'], 'UNKNOWN')
            adapter_id = adapter.identity
        with ContinuityJournal(paths['continuity'], clock=lambda: 100) as journal:
            journal.create_task('mission', fixture_contract(root), key='offline-create')
            journal_id = journal.identity
        return paths, claim, adapter_id, journal_id

    def test_restore_same_locators_preserves_unknown_receipt_and_never_reapplies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, claim, adapter_id, journal_id = self.setup_stores(root)
            backup = root / 'backup'
            cold_backup(paths, backup)
            # A later local-only write establishes the tested snapshot RPO.
            with Runtime(paths['owner'], clock=lambda: 100) as rt:
                rt.put_resource('after-snapshot', 'discarded local tail')
            restore_test_copies(paths, backup)
            with Runtime(paths['owner'], clock=lambda: 200) as rt, FakeAdapter(paths['fake']) as adapter, ContinuityJournal(paths['continuity'], clock=lambda: 200) as journal:
                self.assertEqual(adapter.identity, adapter_id)
                self.assertEqual(journal.identity, journal_id)
                self.assertTrue(rt.check_journal() and journal.verify_chain())
                self.assertEqual(rt.db.execute("SELECT count(*) FROM resources WHERE id='after-snapshot'").fetchone()[0], 0)
                box = Outbox(rt)
                row = box.status('effect')
                self.assertEqual(row['state'], 'UNKNOWN')
                with self.assertRaises(GuardError):
                    box.dispatch('effect', claim['token'], row['revision'], adapter)
                rt.revoke(claim['run_id'])
                done = box.reconcile('effect', row['revision'], adapter)
                self.assertEqual(done['state'], 'COMMITTED')
                self.assertEqual(adapter.statistics()['semantic_effects'], 1)
                self.assertEqual(adapter.statistics()['calls']['apply'], 1)

    def test_missing_fake_uuid_or_relocated_same_uuid_refuses_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, claim, _, _ = self.setup_stores(root)
            moved = root / 'moved.sqlite'
            shutil.copyfile(paths['fake'], moved)
            with Runtime(paths['owner'], clock=lambda: 100) as rt, FakeAdapter(moved) as relocated, FakeAdapter(root / 'empty.sqlite') as missing:
                row = Outbox(rt).status('effect')
                for adapter in [relocated, missing]:
                    with self.subTest(store=adapter.identity), self.assertRaises(GuardError):
                        Outbox(rt).reconcile('effect', row['revision'], adapter)
                self.assertEqual(missing.statistics()['semantic_effects'], 0)
                self.assertEqual(Outbox(rt).status('effect')['state'], 'UNKNOWN')
            with self.assertRaises(GuardError):
                relocated_journal = root / 'relocated-journal.sqlite'
                shutil.copyfile(paths['continuity'], relocated_journal)
                ContinuityJournal(relocated_journal)

    def test_missing_journal_snapshot_stops_harness_before_any_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths, _, _, _ = self.setup_stores(root)
            backup = root / 'backup'
            cold_backup(paths, backup)
            before = {name: path.read_bytes() for name, path in paths.items()}
            (backup / 'continuity.sqlite').unlink()
            with self.assertRaises(GuardError):
                restore_test_copies(paths, backup)
            self.assertEqual({name: path.read_bytes() for name, path in paths.items()}, before)
