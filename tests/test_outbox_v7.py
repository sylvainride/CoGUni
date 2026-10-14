"""Real independent fake-effect SQLite commits, crashes and owner controls."""
from pathlib import Path
import multiprocessing
import os
import json
import sqlite3
import tempfile
import unittest

from universal.core import GuardError, Intent, Runtime, digest
from universal.credentials import rotate_run_token
from universal.outbox import FakeAdapter, Outbox


def crash_dispatch(path, fake, claim, point):
    with Runtime(path, clock=lambda:1000.0) as rt, FakeAdapter(fake) as adapter:
        box=Outbox(rt)
        def crash(where):
            if where==point:os._exit(83)
        intent=Intent(claim['run_id'],'artifact.write','output',1,'business-effect',claim['fence'],{'content':'ALPHA'})
        if point=='before_prepare_commit':box.prepare(intent,claim['token'],budget=2,crash_hook=crash)
        else:
            row=box.prepare(intent,claim['token'],budget=2)
            box.dispatch(row['key'],claim['token'],row['revision'],adapter,crash_hook=crash)


def racing_dispatch(path, fake, claim, barrier, queue):
    with Runtime(path,clock=lambda:1000.0) as rt,FakeAdapter(fake) as adapter:
        box=Outbox(rt);barrier.wait(timeout=10)
        try:
            row=box.dispatch('effect',claim['token'],1,adapter)
            queue.put(row['state'])
        except GuardError:queue.put('DENIED')


class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.path=self.root/'state.sqlite';self.fake=self.root/'effect.sqlite'
        self.now=[1000.0]
        self.rt=Runtime(self.path,clock=lambda:self.now[0]);self.adapter=FakeAdapter(self.fake);self.box=Outbox(self.rt)
        self.rt.put_resource('input','alpha');self.rt.put_resource('output','')
        self.rt.add_task('T','input','output','uppercase',digest('ALPHA'))
        self.claim=self.rt.claim('owner',ttl=60)
    def tearDown(self):self.adapter.close();self.rt.close();self.temp.cleanup()
    def intent(self,key='effect',text='ALPHA',target='output'):
        c=self.claim
        return Intent(c['run_id'],'artifact.write',target,1,key,c['fence'],{'content':text})
    def prepare(self,**kwargs):return self.box.prepare(self.intent(),self.claim['token'],**kwargs)
    def dispatch(self):
        row=self.box.status('effect')
        return self.box.dispatch('effect',self.claim['token'],row['revision'],self.adapter)
    def test_prepare_dispatch_replay_and_distinct_artifact_proof(self):
        row=self.prepare();done=self.dispatch()
        self.assertEqual(done['state'],'COMMITTED')
        replay=self.box.dispatch('effect',self.claim['token'],done['revision'],self.adapter)
        self.assertEqual(replay['state'],'COMMITTED')
        self.assertEqual(self.adapter.statistics()['semantic_effects'],1)
        self.assertEqual(self.adapter.statistics()['calls']['apply'],1)
        self.assertEqual(self.rt.resource('output')['version'],1)
        self.assertEqual(self.rt.task('T')['status'],'RUNNING')
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0],0)
        self.assertTrue(self.rt.check_journal())
    def test_business_key_payload_collision_and_stale_revision_denied(self):
        self.prepare()
        with self.assertRaises(GuardError):self.box.prepare(self.intent(text='changed'),self.claim['token'])
        with self.assertRaises(GuardError):self.box.dispatch('effect',self.claim['token'],2,self.adapter)
        self.assertEqual(self.adapter.statistics()['semantic_effects'],0)
    def test_unknown_requires_lookup_before_retry(self):
        self.prepare(budget=2)
        def fail(point):
            if point=='after_attempt_before_effect':raise RuntimeError('connection_lost')
        with self.assertRaises(RuntimeError):self.box.dispatch('effect',self.claim['token'],1,self.adapter,crash_hook=fail)
        row=self.box.status('effect')
        self.box.recover_uncertain('effect',row['revision'])
        row=self.box.status('effect');self.assertEqual(row['state'],'UNKNOWN')
        with self.assertRaises(GuardError):self.box.dispatch('effect',self.claim['token'],row['revision'],self.adapter)
        row=self.box.reconcile('effect',row['revision'],self.adapter)
        self.assertEqual(row['state'],'PREPARED')
        self.assertEqual(self.dispatch()['state'],'COMMITTED')
        self.assertEqual(self.adapter.statistics()['semantic_effects'],1)
    def test_attempt_budget_cannot_be_refreshed_by_replay_or_reconcile(self):
        self.prepare(budget=1)
        def fail(point):
            if point=='after_attempt_before_effect':raise RuntimeError('lost')
        with self.assertRaises(RuntimeError):self.box.dispatch('effect',self.claim['token'],1,self.adapter,crash_hook=fail)
        row=self.box.status('effect');row=self.box.reconcile('effect',row['revision'],self.adapter)
        with self.assertRaises(GuardError):self.dispatch()
        self.assertEqual(row['attempts'],1)
    def test_rotation_and_revocation_checked_before_effect_and_replay(self):
        self.prepare()
        old=self.claim['token'];new=rotate_run_token(self.rt,self.claim['run_id'],old,expected_fence=self.claim['fence'])
        with self.assertRaises(GuardError):self.box.dispatch('effect',old,1,self.adapter)
        self.claim['token']=new.token;done=self.dispatch()
        self.rt.revoke(self.claim['run_id'])
        with self.assertRaises(GuardError):self.box.dispatch('effect',new.token,done['revision'],self.adapter)
        self.assertEqual(self.adapter.statistics()['semantic_effects'],1)
    def test_expired_and_foreign_scope_refused(self):
        self.rt.put_resource('outside','')
        with self.assertRaises(GuardError):self.box.prepare(self.intent(target='outside'),self.claim['token'])
        self.now[0]=1061.0
        with self.assertRaises(GuardError):self.prepare()
        self.assertEqual(self.adapter.statistics()['semantic_effects'],0)
    def test_source_drift_and_revocation_after_prepare_prevent_emission(self):
        self.prepare();self.rt.put_resource('input','changed',1)
        with self.assertRaises(GuardError):self.dispatch()
        self.assertEqual(self.adapter.statistics()['semantic_effects'],0)
    def test_owner_reconciliation_remains_observation_after_revocation(self):
        self.prepare()
        def fail(point):
            if point=='after_effect_before_ack':raise RuntimeError('ack_lost')
        with self.assertRaises(RuntimeError):self.box.dispatch('effect',self.claim['token'],1,self.adapter,crash_hook=fail)
        row=self.box.status('effect');self.assertEqual(row['state'],'UNKNOWN')
        self.rt.revoke(self.claim['run_id'])
        result=self.box.reconcile('effect',row['revision'],self.adapter)
        self.assertEqual(result['state'],'COMMITTED')
        self.assertEqual(self.adapter.statistics()['semantic_effects'],1)
        self.assertEqual(self.adapter.statistics()['calls']['apply'],1)
    def test_compensation_distinct_contract_idempotent_and_second_key_denied(self):
        self.prepare();done=self.dispatch()
        comp=self.box.compensate('effect','compensation',self.claim['token'],done['revision'],self.adapter)
        again=self.box.compensate('effect','compensation',self.claim['token'],done['revision'],self.adapter)
        self.assertEqual(comp['state'],again['state'])
        with self.assertRaises(GuardError):self.box.compensate('effect','another-compensation',self.claim['token'],done['revision'],self.adapter)
        self.assertEqual(self.adapter.statistics()['compensations'],1)
        self.assertEqual(self.adapter.statistics()['calls']['compensate'],1)
    def test_compensation_ack_loss_is_reconciled_not_reemitted(self):
        self.prepare();done=self.dispatch()
        def fail(point):
            if point=='after_compensation_before_ack':raise RuntimeError('lost')
        with self.assertRaises(RuntimeError):self.box.compensate('effect','compensation',self.claim['token'],done['revision'],self.adapter,crash_hook=fail)
        row=self.box.compensation_status('compensation')
        self.assertEqual(row['state'],'UNKNOWN')
        resolved=self.box.reconcile_compensation('compensation',row['revision'],self.adapter)
        self.assertEqual(resolved['state'],'COMMITTED')
        self.assertEqual(self.adapter.statistics()['compensations'],1)
    def test_fake_adapter_refuses_controller_database_without_changes(self):
        before=self.rt.db.execute('PRAGMA user_version').fetchone()[0]
        with self.assertRaises(GuardError):FakeAdapter(self.path)
        self.assertEqual(self.rt.db.execute('PRAGMA user_version').fetchone()[0],before)
        self.assertFalse(self.rt.db.execute("SELECT 1 FROM sqlite_master WHERE name='fake_effects'").fetchone())
    def test_state_snapshot_excludes_payload_and_credentials(self):
        self.prepare()
        value=str(self.box.status('effect'))+str(self.rt.snapshot())
        self.assertNotIn(self.claim['token'],value)
        self.assertNotIn("'payload'",value)
    def test_real_process_crashes_at_four_commit_boundaries(self):
        ctx=multiprocessing.get_context('spawn')
        for point,effect_count in [('before_prepare_commit',0),('after_attempt_before_effect',0),('after_effect_before_ack',1),('after_ack_before_commit',1)]:
            with self.subTest(point=point):
                # Reuse the live artifact contract, clear only these disposable
                # fixture outbox rows through a fresh business key database.
                temp=Path(self.temp.name)/point;temp.mkdir()
                path=temp/'state.sqlite';fake=temp/'fake.sqlite'
                with Runtime(path,clock=lambda:1000.0) as rt:
                    rt.put_resource('input','alpha');rt.put_resource('output','')
                    rt.add_task('T','input','output','uppercase',digest('ALPHA'))
                    claim=rt.claim('owner',ttl=60)
                    Outbox(rt)
                child=ctx.Process(target=crash_dispatch,args=(str(path),str(fake),claim,point))
                child.start();child.join(15)
                if child.is_alive():child.terminate();child.join(5)
                self.assertEqual(child.exitcode,83)
                with Runtime(path,clock=lambda:1000.0) as rt,FakeAdapter(fake) as adapter:
                    box=Outbox(rt)
                    self.assertEqual(adapter.statistics()['semantic_effects'],effect_count)
                    if point=='before_prepare_commit':
                        with self.assertRaises(GuardError):box.status('business-effect')
                    else:
                        row=box.status('business-effect')
                        if row['state']=='INFLIGHT':row=box.recover_uncertain(row['key'],row['revision'])
                        if row['state'] in ('UNKNOWN','ACKED'):row=box.reconcile(row['key'],row['revision'],adapter)
                        if row['state']=='PREPARED':row=box.dispatch(row['key'],claim['token'],row['revision'],adapter)
                        self.assertEqual(row['state'],'COMMITTED')
                        self.assertEqual(adapter.statistics()['semantic_effects'],1)
                    self.assertTrue(rt.check_journal())
    def test_two_real_dispatchers_produce_one_fake_effect(self):
        self.prepare();ctx=multiprocessing.get_context('spawn')
        barrier=ctx.Barrier(2);queue=ctx.Queue()
        children=[ctx.Process(target=racing_dispatch,args=(str(self.path),str(self.fake),self.claim,barrier,queue)) for _ in range(2)]
        try:
            for child in children:child.start()
            outcomes=[queue.get(timeout=15) for child in children]
            for child in children:child.join(15);self.assertEqual(child.exitcode,0)
            self.assertEqual(sorted(outcomes),['COMMITTED','DENIED'])
            self.assertEqual(self.adapter.statistics()['semantic_effects'],1)
        finally:
            for child in children:
                if child.is_alive():child.terminate();child.join(5)
            queue.close();queue.join_thread()

    def test_ack_loss_cannot_reconcile_or_dispatch_against_another_store(self):
        self.prepare(budget=2)
        def fail(point):
            if point=='after_effect_before_ack':raise RuntimeError('ack_lost')
        with self.assertRaises(RuntimeError):
            self.box.dispatch('effect',self.claim['token'],1,self.adapter,crash_hook=fail)
        uncertain=self.box.status('effect')
        self.assertEqual(uncertain['state'],'UNKNOWN')
        with FakeAdapter(self.root/'wrong.sqlite') as wrong:
            with self.assertRaises(GuardError):self.box.reconcile('effect',uncertain['revision'],wrong)
            with self.assertRaises(GuardError):self.box.dispatch('effect',self.claim['token'],uncertain['revision'],wrong)
            self.assertEqual(self.box.status('effect'),uncertain)
            self.assertEqual(wrong.statistics(),{'semantic_effects':0,'compensations':0,'calls':{}})
        resolved=self.box.reconcile('effect',uncertain['revision'],self.adapter)
        self.assertEqual(resolved['state'],'COMMITTED')
        self.assertEqual(self.adapter.statistics()['semantic_effects'],1)
        self.assertTrue(self.rt.check_journal())

    def test_restart_preserves_binding_and_wrong_store_denies_committed_replay(self):
        self.prepare();done=self.dispatch();identity=self.adapter.identity
        self.adapter.close();self.adapter=FakeAdapter(self.fake)
        self.assertEqual(identity,self.adapter.identity)
        self.assertEqual(done['adapter_id'],identity)
        self.assertEqual(self.box.dispatch('effect',self.claim['token'],done['revision'],self.adapter)['state'],'COMMITTED')
        with FakeAdapter(self.root/'wrong.sqlite') as wrong:
            with self.assertRaises(GuardError):self.box.dispatch('effect',self.claim['token'],done['revision'],wrong)
            with self.assertRaises(GuardError):self.box.reconcile('effect',done['revision'],wrong)
            self.assertEqual(wrong.statistics()['calls'],{})

    def test_copy_with_same_uuid_at_another_locator_cannot_replace_bound_store(self):
        self.prepare(budget=2)
        clone=self.root/'clone.sqlite'
        with sqlite3.connect(clone) as destination:self.adapter.db.backup(destination)
        def fail(point):
            if point=='after_attempt_before_effect':raise RuntimeError('lost_before_effect')
        with self.assertRaises(RuntimeError):self.box.dispatch('effect',self.claim['token'],1,self.adapter,crash_hook=fail)
        row=self.box.status('effect');row=self.box.recover_uncertain('effect',row['revision'])
        with FakeAdapter(clone) as copied:
            self.assertEqual(self.adapter.db.execute('SELECT uuid FROM fake_identity').fetchone()[0],copied.db.execute('SELECT uuid FROM fake_identity').fetchone()[0])
            self.assertNotEqual(self.adapter.identity,copied.identity)
            with self.assertRaises(GuardError):self.box.reconcile('effect',row['revision'],copied)
            self.assertEqual(copied.statistics()['calls'],{})
        row=self.box.reconcile('effect',row['revision'],self.adapter)
        self.assertEqual(self.box.dispatch('effect',self.claim['token'],row['revision'],self.adapter)['state'],'COMMITTED')
        self.assertEqual(self.adapter.statistics()['semantic_effects'],1)

    def test_wrong_store_cannot_emit_or_reconcile_a_compensation(self):
        self.prepare();done=self.dispatch()
        with FakeAdapter(self.root/'wrong.sqlite') as wrong:
            with self.assertRaises(GuardError):self.box.compensate('effect','compensation',self.claim['token'],done['revision'],wrong)
            self.assertEqual(wrong.statistics()['calls'],{})
            def fail(point):
                if point=='after_compensation_before_ack':raise RuntimeError('ack_lost')
            with self.assertRaises(RuntimeError):self.box.compensate('effect','compensation',self.claim['token'],done['revision'],self.adapter,crash_hook=fail)
            comp=self.box.compensation_status('compensation')
            with self.assertRaises(GuardError):self.box.reconcile_compensation('compensation',comp['revision'],wrong)
            self.assertEqual(wrong.statistics()['calls'],{})
            self.assertEqual(self.box.compensation_status('compensation'),comp)
        self.assertEqual(self.box.reconcile_compensation('compensation',comp['revision'],self.adapter)['state'],'COMMITTED')
        self.assertEqual(self.adapter.statistics()['compensations'],1)

    def make_legacy_outbox(self):
        # Construct the actual previous optional outbox layout on this disposable
        # fixture, without changing the core schema or manufacturing a binding.
        with self.rt.transaction():
            self.rt.db.execute('DROP TRIGGER simulated_outbox_adapter_immutable')
            self.rt.db.execute('ALTER TABLE simulated_outbox DROP COLUMN adapter_id')
        self.box=Outbox(self.rt)

    def test_legacy_attempt_without_binding_fails_closed_after_migration(self):
        self.prepare(budget=2)
        with self.rt.transaction():
            self.rt.db.execute("UPDATE simulated_outbox SET state='UNKNOWN',attempts=1,revision=3 WHERE key='effect'")
        self.make_legacy_outbox()
        row=self.box.status('effect');self.assertIsNone(row['adapter_id'])
        with self.assertRaises(GuardError):self.box.reconcile('effect',3,self.adapter)
        with self.assertRaises(GuardError):self.box.dispatch('effect',self.claim['token'],3,self.adapter)
        self.assertEqual(self.box.status('effect'),row)
        self.assertEqual(self.adapter.statistics()['calls'],{})
        self.assertEqual(self.rt.db.execute('PRAGMA user_version').fetchone()[0],4)

    def test_legacy_unattempted_intent_can_bind_and_commit(self):
        self.prepare();self.make_legacy_outbox()
        self.assertIsNone(self.box.status('effect')['adapter_id'])
        self.assertEqual(self.dispatch()['adapter_id'],self.adapter.identity)
        self.assertEqual(self.adapter.statistics()['semantic_effects'],1)

    def test_bound_adapter_and_store_uuid_are_immutable(self):
        self.prepare();self.dispatch()
        for sql in ["UPDATE simulated_outbox SET adapter_id='other'",'UPDATE simulated_outbox SET adapter_id=NULL']:
            with self.assertRaises(sqlite3.IntegrityError),self.rt.transaction():self.rt.db.execute(sql)
        for sql in ["UPDATE fake_identity SET uuid='other'",'DELETE FROM fake_identity']:
            with self.assertRaises(sqlite3.IntegrityError),self.adapter.transaction():self.adapter.db.execute(sql)

    def test_effect_and_compensation_receipts_include_exact_bound_identity(self):
        self.prepare();done=self.dispatch();row=self.box._row('effect')
        receipt=json.loads(row['receipt']);self.assertEqual(receipt['adapter_id'],done['adapter_id'])
        self.box._accept_receipt(row,receipt)
        for altered in [{**receipt,'adapter_id':'wrong'},{key:value for key,value in receipt.items() if key!='adapter_id'}]:
            with self.assertRaises(GuardError):self.box._accept_receipt(row,altered)
        comp=self.box.compensate('effect','compensation',self.claim['token'],done['revision'],self.adapter)
        self.assertEqual(json.loads(comp['receipt'])['adapter_id'],done['adapter_id'])
