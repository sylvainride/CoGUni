"""Trusted-side object forgery and synthetic double SQLite failures."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tests import test_workspace as fixtures
from universal.workspace import Candidate, WorkspaceConflict
from universal.core import Runtime
from universal.continuity import ContinuityJournal
from universal.outbox import FakeAdapter


class RollbackFault:
    def __init__(self, db):
        self.db = db

    def execute(self, statement, *args):
        if statement == 'ROLLBACK':
            raise sqlite3.OperationalError('synthetic rollback failure')
        return self.db.execute(statement, *args)

    def __getattr__(self, name):
        return getattr(self.db, name)


class LegacyError(sqlite3.OperationalError):
    """Emulate Python 3.10's absence of exception notes, not its interpreter."""
    def __getattribute__(self, name):
        if name == 'add_note':
            raise AttributeError(name)
        return super().__getattribute__(name)


class OwnerHardeningTests(unittest.TestCase):
    def test_fabricated_candidate_cannot_bypass_path_or_text_scope(self):
        fixture = fixtures.WorkspaceTests()
        fixture.setUp()
        try:
            for path, mode, data in [('keep.txt', '100644', b'outside\n'),
                                     ('a.txt', '120000', b'/tmp/escape'),
                                     ('a.txt', '100644', b'\0binary')]:
                with self.subTest(path=path, mode=mode), fixture.workspace() as ws:
                    blob = ws._git('hash-object', '-w', '--stdin', data=data).decode().strip()
                    index = ws.root / 'forged-index'
                    ws._git('read-tree', fixture.sha, index=index)
                    ws._git('update-index', '-z', '--index-info', index=index,
                            data=(mode + ' ' + blob + '\t' + path + '\0').encode())
                    tree = ws._git('write-tree', index=index).decode().strip()
                    commit = ws._git('commit-tree', tree, '-p', fixture.sha,
                                     data=b'fabricated owner object\n').decode().strip()
                    with self.assertRaises(ValueError):
                        ws.advance(Candidate(fixture.sha, tree, commit), validated_tree=tree)
                    self.assertEqual(ws.head(), fixture.sha)
            self.assertEqual((fixture.source / 'keep.txt').read_text(), 'unchanged\n')
        finally:
            fixture.tearDown()

    def test_rollback_failure_preserves_original_and_closes_poisoned_connection(self):
        with tempfile.TemporaryDirectory() as root:
            for cls, method in [(Runtime, 'transaction'), (ContinuityJournal, '_transaction'),
                                (FakeAdapter, 'transaction')]:
                with self.subTest(store=cls.__name__):
                    path = Path(root) / (cls.__name__ + '.sqlite')
                    obj = cls(path)
                    db = obj.db
                    obj.db = RollbackFault(db)
                    original = sqlite3.OperationalError('synthetic original fsync failure')
                    original.sqlite_errorcode = sqlite3.SQLITE_IOERR_FSYNC
                    try:
                        with self.assertRaises(sqlite3.OperationalError) as seen:
                            with getattr(obj, method)():
                                raise original
                        self.assertIs(seen.exception, original)
                        self.assertEqual(seen.exception.sqlite_errorcode, sqlite3.SQLITE_IOERR_FSYNC)
                        self.assertIn('Rollback failed: OperationalError', seen.exception.__notes__)
                        with self.assertRaises(sqlite3.ProgrammingError):
                            db.execute('COMMIT')
                    finally:
                        db.close()
                    with sqlite3.connect(path) as restored:
                        self.assertEqual(restored.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_cleanup_without_exception_notes_still_closes_and_preserves_error(self):
        with tempfile.TemporaryDirectory() as root, Runtime(Path(root) / 'owner.sqlite') as obj:
            db = obj.db
            obj.db = RollbackFault(db)
            original = LegacyError('original')
            with self.assertRaises(LegacyError) as seen:
                with obj.transaction():
                    raise original
            self.assertIs(seen.exception, original)
            with self.assertRaises(sqlite3.ProgrammingError):
                db.execute('COMMIT')
