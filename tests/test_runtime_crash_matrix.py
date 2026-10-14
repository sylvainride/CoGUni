"""SIGKILL at coordinated owner SQLite boundaries; local fake effects only.

These trusted test helpers are owner processes, not untrusted sandbox workers.
Existing sandbox/worker crash tests remain separate requirements.
"""
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest

from universal.core import GuardError, Intent, Runtime, digest
from universal.outbox import FakeAdapter, Outbox


def pause_write(path, claim, connection):
    with Runtime(path, clock=lambda: 1000) as rt:
        original = rt._event
        def paused(actor, action, target, outcome, metadata=None):
            original(actor, action, target, outcome, metadata)
            if action == 'artifact.write' and outcome == 'COMMITTED':
                connection.send('BEFORE_COMMIT')
                connection.recv()
        rt._event = paused
        rt.execute(Intent(claim['run_id'], 'artifact.write', 'output', 1, 'write',
                          claim['fence'], {'content': 'ALPHA'}), claim['token'])


def pause_ack(path, fake, claim, connection):
    with Runtime(path, clock=lambda: 1000) as rt, FakeAdapter(fake) as adapter:
        box = Outbox(rt)
        def paused(point):
            if point == 'after_effect_before_ack':
                connection.send('EFFECT_COMMITTED_ACK_MISSING')
                connection.recv()
        row = box.status('effect')
        box.dispatch('effect', claim['token'], row['revision'], adapter, crash_hook=paused)


class RuntimeCrashMatrixTests(unittest.TestCase):
    def setup_owner(self, path):
        with Runtime(path, clock=lambda: 1000) as rt:
            rt.put_resource('input', 'alpha')
            rt.put_resource('output', '')
            rt.add_task('T', 'input', 'output', 'uppercase', digest('ALPHA'))
            return rt.claim('trusted-test-owner', ttl=60)

    def kill_at_handshake(self, target, args, expected):
        context = multiprocessing.get_context('spawn')
        parent, child = context.Pipe()
        process = context.Process(target=target, args=(*args, child))
        process.start()
        child.close()
        try:
            self.assertTrue(parent.poll(10))
            self.assertEqual(parent.recv(), expected)
            process.kill()
            process.join(timeout=5)
            self.assertEqual(process.exitcode, -9)
        finally:
            if process.is_alive():
                process.kill()
                process.join(timeout=3)
            parent.close()

    def test_sigkill_before_owner_commit_rolls_back_and_same_key_has_one_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'owner.sqlite'
            claim = self.setup_owner(path)
            self.kill_at_handshake(pause_write, (str(path), claim), 'BEFORE_COMMIT')
            with Runtime(path, clock=lambda: 1000) as rt:
                self.assertEqual(rt.resource('output')['version'], 1)
                self.assertEqual(rt.resource('output')['content'], '')
                self.assertEqual(rt.db.execute('SELECT count(*) FROM effects').fetchone()[0], 0)
                self.assertTrue(rt.check_journal())
                intent = Intent(claim['run_id'], 'artifact.write', 'output', 1, 'write', claim['fence'], {'content': 'ALPHA'})
                rt.execute(intent, claim['token'])
                rt.execute(intent, claim['token'])
                self.assertEqual(rt.resource('output')['version'], 2)
                self.assertEqual(rt.db.execute('SELECT count(*) FROM effects').fetchone()[0], 1)

    def test_sigkill_after_fake_commit_requires_bound_reconcile_and_no_second_emission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, fake = root / 'owner.sqlite', root / 'fake.sqlite'
            claim = self.setup_owner(path)
            with Runtime(path, clock=lambda: 1000) as rt, FakeAdapter(fake):
                box = Outbox(rt)
                box.prepare(Intent(claim['run_id'], 'artifact.write', 'output', 1, 'effect',
                                   claim['fence'], {'content': 'ALPHA'}), claim['token'], budget=2)
            self.kill_at_handshake(pause_ack, (str(path), str(fake), claim), 'EFFECT_COMMITTED_ACK_MISSING')
            with Runtime(path, clock=lambda: 1000) as rt, FakeAdapter(fake) as adapter, FakeAdapter(root / 'other.sqlite') as wrong:
                box = Outbox(rt)
                row = box.status('effect')
                self.assertEqual(row['state'], 'INFLIGHT')
                with self.assertRaises(GuardError):
                    box.dispatch('effect', claim['token'], row['revision'], adapter)
                row = box.recover_uncertain('effect', row['revision'])
                with self.assertRaises(GuardError):
                    box.reconcile('effect', row['revision'], wrong)
                rt.revoke(claim['run_id'])  # Observation remains possible, emission does not.
                done = box.reconcile('effect', row['revision'], adapter)
                self.assertEqual(done['state'], 'COMMITTED')
                self.assertEqual(adapter.statistics()['semantic_effects'], 1)
                self.assertEqual(adapter.statistics()['calls']['apply'], 1)
                self.assertEqual(rt.resource('output')['version'], 1)
                self.assertEqual(rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0], 0)
                self.assertTrue(rt.check_journal())
