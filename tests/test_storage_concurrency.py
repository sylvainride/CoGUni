"""Multiprocess WAL contention on isolated owner journal copies."""
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from universal.continuity import ContinuityJournal
from universal.core import GuardError
from tests.test_continuity_v8 import fixture_contract


def hold_writer(path, ready, release):
    db = sqlite3.connect(path, timeout=1, isolation_level=None)
    try:
        db.execute('BEGIN IMMEDIATE')
        ready.set()
        if not release.wait(timeout=10):
            raise RuntimeError('bounded test lock wait expired')
        db.execute('ROLLBACK')
    finally:
        db.close()


def claim_writer(path, actor, barrier, connection):
    try:
        with ContinuityJournal(path, clock=lambda: 100) as journal:
            barrier.wait(timeout=10)
            try:
                result = journal.claim('T', actor, 'local_copy', expected_revision=1,
                                       key='claim-' + actor, ttl=30)
                connection.send(('CLAIMED', result['fence']))
            except GuardError:
                connection.send(('CONFLICT', None))
    finally:
        connection.close()


class StorageConcurrencyTests(unittest.TestCase):
    def test_wal_writer_lock_timeout_is_bounded_and_reader_state_remains_consistent(self):
        context = multiprocessing.get_context('spawn')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with ContinuityJournal(root / 'journal.sqlite', clock=lambda: 100) as journal:
                journal.create_task('T', fixture_contract(root), key='create')
                self.assertEqual(journal.db.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
                before = journal.get('T')
                ready, release = context.Event(), context.Event()
                child = context.Process(target=hold_writer, args=(str(journal.path), ready, release))
                child.start()
                try:
                    self.assertTrue(ready.wait(timeout=5))
                    self.assertEqual(journal.get('T'), before)  # WAL read succeeds while writer holds lock.
                    journal.db.execute('PRAGMA busy_timeout=75')  # Test connection only, production unchanged.
                    start = time.monotonic()
                    with self.assertRaises(sqlite3.OperationalError) as observed:
                        journal.claim('T', 'owner', 'local_copy', expected_revision=1, key='locked-claim')
                    elapsed = time.monotonic() - start
                    self.assertEqual(observed.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
                    self.assertGreaterEqual(elapsed, 0.05)
                    self.assertLess(elapsed, 3)
                    self.assertEqual(journal.get('T'), before)
                    self.assertTrue(journal.verify_chain())
                finally:
                    release.set()
                    child.join(timeout=5)
                    if child.is_alive():
                        child.kill()
                        child.join(timeout=3)
                self.assertEqual(child.exitcode, 0)
                claim = journal.claim('T', 'owner', 'local_copy', expected_revision=1, key='confirmed-retry')
                self.assertEqual(claim['spent'], 1)
                self.assertEqual(claim['attempts'], 1)

    def test_two_process_claims_have_one_fenced_winner_without_lost_update(self):
        context = multiprocessing.get_context('spawn')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with ContinuityJournal(root / 'journal.sqlite', clock=lambda: 100) as journal:
                journal.create_task('T', fixture_contract(root), key='create')
                barrier = context.Barrier(2)
                pairs = [context.Pipe(duplex=False) for _ in range(2)]
                children = [context.Process(target=claim_writer,
                            args=(str(journal.path), 'owner-' + str(i), barrier, pairs[i][1])) for i in range(2)]
                outcomes = []
                try:
                    for child in children:
                        child.start()
                    for receive, send in pairs:
                        send.close()
                        self.assertTrue(receive.poll(10))
                        outcomes.append(receive.recv())
                    for child in children:
                        child.join(timeout=5)
                        self.assertEqual(child.exitcode, 0)
                finally:
                    for child in children:
                        if child.is_alive():
                            child.kill()
                            child.join(timeout=3)
                    for receive, send in pairs:
                        receive.close()
                        send.close()
                self.assertEqual(sorted(x[0] for x in outcomes), ['CLAIMED', 'CONFLICT'])
                task = journal.get('T')
                self.assertEqual((task['spent'], task['attempts'], task['revision']), (1, 1, 2))
                self.assertEqual(task['fence'], next(x[1] for x in outcomes if x[0] == 'CLAIMED'))
                self.assertTrue(journal.verify_chain())
