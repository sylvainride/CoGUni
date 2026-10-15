"""P32: existing owner Outbox + FakeAdapter enforce optimistic local CAS.

All effects are separate SQLite fake fixtures. These are NOT mission receipt
verification or a right to apply any worker result to a live remote project.
"""
from pathlib import Path
import tempfile
import unittest

from universal.core import Runtime, Intent, GuardError, digest
from universal.outbox import Outbox, FakeAdapter


class MissionP32CASFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mission-p32-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rt = Runtime(self.root/'owner.sqlite', clock=lambda: 150.)
        self.addCleanup(self.rt.close)
        self.adapter = FakeAdapter(self.root/'effect.sqlite')
        self.addCleanup(self.adapter.close)
        self.rt.put_resource('source_A', 'alpha')
        self.rt.put_resource('out_A', '')
        self.rt.add_task('task_A', 'source_A', 'out_A', 'uppercase', digest('ALPHA'))
        self.claim = self.rt.claim('owner-A', ttl=60)
        self.outbox = Outbox(self.rt)

    def intent(self, *, version=1, output='out_A', key='P32-A-effect', content='ALPHA'):
        c = self.claim
        return Intent(c['run_id'], 'artifact.write', output, version,
                      key, c['fence'], {'content':content})

    def test_positive_fake_write_remains_unverified_and_no_project_mutation(self):
        planned = self.outbox.prepare(self.intent(), self.claim['token'])
        observed = self.outbox.dispatch(planned['key'], self.claim['token'],
                                        planned['revision'], self.adapter)
        self.assertEqual(observed['state'], 'COMMITTED')
        self.assertEqual(self.adapter.statistics()['semantic_effects'], 1)
        self.assertEqual(self.rt.resource('out_A')['version'], 1)
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0], 0)
        self.assertEqual(self.rt.task('task_A')['status'], 'RUNNING')

    def test_version_mismatch_refuses_before_adapter_effect(self):
        original = self.outbox.prepare(self.intent(), self.claim['token'])
        # Existing owner lease prevents a competing writer from changing the
        # version at all. Do not weaken the lease just to simulate a race.
        with self.assertRaises(GuardError):
            self.rt.put_resource('out_A', 'concurrent-owner-update', 1)
        # An optimistic operation targeting version 2 while actual version is
        # 1 must fail before the fake adapter is called.
        with self.assertRaises(GuardError):
            self.outbox.prepare(self.intent(version=2, key='P32-stale-version'),
                                self.claim['token'])
        with self.assertRaises(GuardError):
            self.outbox.dispatch(original['key'], self.claim['token'],
                                 original['revision']+1, self.adapter)
        self.assertEqual(self.adapter.statistics()['semantic_effects'], 0)
        self.assertEqual(self.rt.resource('out_A')['version'], 1)
        self.assertTrue(self.rt.check_journal())

    def test_project_b_foreign_scope_is_denied(self):
        self.rt.put_resource('out_B', '')
        with self.assertRaises(GuardError):
            self.outbox.prepare(self.intent(output='out_B'), self.claim['token'])
        self.assertEqual(self.adapter.statistics()['semantic_effects'], 0)

    def test_replay_same_business_key_is_idempotent(self):
        planned = self.outbox.prepare(self.intent(), self.claim['token'])
        first = self.outbox.dispatch(planned['key'], self.claim['token'],
                                     planned['revision'], self.adapter)
        second = self.outbox.dispatch(planned['key'], self.claim['token'],
                                      first['revision'], self.adapter)
        self.assertEqual(second['state'], 'COMMITTED')
        self.assertEqual(self.adapter.statistics()['semantic_effects'], 1)
        with self.assertRaises(GuardError):
            self.outbox.prepare(self.intent(content='CHANGED'), self.claim['token'])

    def test_worker_result_claim_is_not_authorization(self):
        self.outbox.prepare(self.intent(), self.claim['token'])
        with self.assertRaises(GuardError):
            self.outbox.dispatch('P32-A-effect', 'WORKER_PASS', 1, self.adapter)
        self.assertEqual(self.adapter.statistics()['semantic_effects'], 0)


if __name__ == '__main__':
    unittest.main()
