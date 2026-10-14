"""Real SQLite capacity errors and injected commit IO errors on private copies.

max_page_count is a real SQLITE_FULL probe, not host disk exhaustion. The commit
proxy simulates an IOERR_FSYNC boundary; no physical fsync/power-loss claim.
"""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from universal.core import Runtime
from universal.continuity import ContinuityJournal
from universal.outbox import FakeAdapter
from tests.test_continuity_v8 import fixture_contract


def cap_current_pages(db):
    db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    pages = db.execute('PRAGMA page_count').fetchone()[0]
    db.execute('PRAGMA max_page_count=' + str(pages))
    return pages


class CommitIOFailure:
    def __init__(self, db):
        self.db, self.armed = db, True

    def execute(self, statement, *args):
        if statement == 'COMMIT' and self.armed:
            self.armed = False
            error = sqlite3.OperationalError('synthetic commit fsync failure')
            error.sqlite_errorcode = sqlite3.SQLITE_IOERR_FSYNC
            raise error
        return self.db.execute(statement, *args)

    def __getattr__(self, name):
        return getattr(self.db, name)


class StorageFailClosedTests(unittest.TestCase):
    def test_runtime_sqlite_full_preserves_error_code_and_no_false_commit(self):
        with tempfile.TemporaryDirectory() as root, Runtime(Path(root) / 'owner.sqlite', clock=lambda: 100) as rt:
            cap_current_pages(rt.db)
            events = rt.db.execute('SELECT count(*) FROM events').fetchone()[0]
            with self.assertRaises(sqlite3.OperationalError) as observed:
                rt.put_resource('large', 'X' * 500000)
            self.assertEqual(observed.exception.sqlite_errorcode, sqlite3.SQLITE_FULL)
            self.assertFalse(rt.db.in_transaction)
            self.assertEqual(rt.db.execute("SELECT count(*) FROM resources WHERE id='large'").fetchone()[0], 0)
            self.assertEqual(rt.db.execute('SELECT count(*) FROM events').fetchone()[0], events)
            self.assertEqual(rt.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertTrue(rt.check_journal())

    def test_continuity_sqlite_full_keeps_receipts_and_tasks_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with ContinuityJournal(root / 'journal.sqlite', clock=lambda: 100) as journal:
                contract = fixture_contract(root)
                contract['constraints'] = ['X' * 500 for _ in range(1)]
                cap_current_pages(journal.db)
                before = tuple(journal.db.execute('SELECT count(*) FROM ' + table).fetchone()[0]
                               for table in ('continuity_tasks', 'continuity_receipts', 'continuity_events'))
                # The immutable contract and planned checkpoint occupy pages.
                # Use distinct bounded text entries to reliably exceed free space.
                contract['constraints'] = [str(i) + 'X' * 390 for i in range(16)]
                with self.assertRaises(sqlite3.OperationalError) as observed:
                    journal.create_task('large', contract, key='create-large')
                self.assertEqual(observed.exception.sqlite_errorcode, sqlite3.SQLITE_FULL)
                after = tuple(journal.db.execute('SELECT count(*) FROM ' + table).fetchone()[0]
                              for table in ('continuity_tasks', 'continuity_receipts', 'continuity_events'))
                self.assertEqual(after, before)
                self.assertFalse(journal.db.in_transaction)
                self.assertTrue(journal.verify_chain())
                self.assertEqual(journal.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_fake_effect_sqlite_full_never_commits_call_or_effect(self):
        with tempfile.TemporaryDirectory() as root, FakeAdapter(Path(root) / 'fake.sqlite') as adapter:
            cap_current_pages(adapter.db)
            with self.assertRaises(sqlite3.OperationalError) as observed:
                adapter.apply('large', 'fingerprint', 'X' * 500000)
            self.assertEqual(observed.exception.sqlite_errorcode, sqlite3.SQLITE_FULL)
            self.assertFalse(adapter.db.in_transaction)
            self.assertEqual(adapter.statistics()['semantic_effects'], 0)
            self.assertEqual(adapter.statistics()['calls'], {})
            self.assertEqual(adapter.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_injected_commit_io_failure_rolls_back_and_remains_nonpositive(self):
        with tempfile.TemporaryDirectory() as root, Runtime(Path(root) / 'owner.sqlite', clock=lambda: 100) as rt:
            original = rt.db
            rt.db = CommitIOFailure(original)
            try:
                before = original.execute('SELECT count(*) FROM events').fetchone()[0]
                with self.assertRaises(sqlite3.OperationalError) as observed:
                    rt.put_resource('uncommitted', 'data')
                self.assertEqual(observed.exception.sqlite_errorcode, sqlite3.SQLITE_IOERR_FSYNC)
                self.assertFalse(original.in_transaction)
                self.assertEqual(original.execute("SELECT count(*) FROM resources WHERE id='uncommitted'").fetchone()[0], 0)
                self.assertEqual(original.execute('SELECT count(*) FROM events').fetchone()[0], before)
                self.assertTrue(rt.check_journal())
            finally:
                rt.db = original
