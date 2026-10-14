"""Separate owner processes contest lineage revocation, claim and actual effects."""
import multiprocessing
from pathlib import Path
import tempfile
import unittest

from universal.core import GuardError, Intent, Runtime, digest


def race_actor(path,operation,barrier,queue,claim,proof):
    with Runtime(path,clock=lambda:1000.0) as rt:
        barrier.wait(timeout=10)
        try:
            if operation=='revoke':rt.revoke_evidence(proof,'owner_race');queue.put('REVOKED')
            elif operation=='write':
                rt.execute(Intent(claim['run_id'],'artifact.write','out',1,'child-effect',claim['fence'],{'content':'ALPHA'}),claim['token']);queue.put('COMMITTED')
            elif operation=='claim':queue.put('CLAIMED' if rt.claim('consumer',environment='env') else 'NO_CLAIM')
            elif operation=='drift':rt.put_resource('mid','ALPHA',2);queue.put('DRIFT')
        except GuardError:queue.put('DENIED')


class BindingRaceTests(unittest.TestCase):
    def setup_graph(self,path):
        with Runtime(path,clock=lambda:1000.0) as rt:
            for name,text in [('input','alpha'),('mid',''),('out','')]:rt.put_resource(name,text)
            rt.add_task('A','input','mid','uppercase',digest('ALPHA'))
            rt.add_task('B','mid','out','copy',digest('ALPHA'),['A'],input_mode='VERIFIED_UPSTREAM_OUTPUT',producer='A',source_expected_sha=digest('ALPHA'))
            a=rt.claim('producer',environment='env')
            rt.execute(Intent(a['run_id'],'artifact.write','mid',1,'parent-effect',a['fence'],{'content':'ALPHA'}),a['token'])
            proof=rt.verify('A','env')['evidence']
        return proof
    def run_race(self,path,operations,claim,proof):
        ctx=multiprocessing.get_context('spawn');barrier=ctx.Barrier(2);queue=ctx.Queue()
        children=[ctx.Process(target=race_actor,args=(str(path),op,barrier,queue,claim,proof)) for op in operations]
        try:
            for child in children:child.start()
            results=[queue.get(timeout=15) for child in children]
            for child in children:child.join(15);self.assertEqual(child.exitcode,0)
            return results
        finally:
            for child in children:
                if child.is_alive():child.terminate();child.join(5)
            queue.close();queue.join_thread()
    def test_revocation_race_has_no_accepted_child_proof_or_post_revoke_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'state.sqlite';proof=self.setup_graph(path)
            with Runtime(path,clock=lambda:1000.0) as rt:claim=rt.claim('consumer',environment='env')
            results=self.run_race(path,['write','revoke'],claim,proof)
            self.assertIn('REVOKED',results)
            with Runtime(path,clock=lambda:1000.0) as rt:
                version=rt.resource('out')['version'];self.assertIn(version,(1,2))
                if 'COMMITTED' in results:self.assertEqual(version,2)
                else:self.assertEqual(version,1)
                with self.assertRaises(GuardError):rt.verify('B','env')
                self.assertEqual(rt.db.execute("SELECT count(*) FROM evidence WHERE task='B'").fetchone()[0],0)
                self.assertTrue(rt.check_journal())
    def test_claim_drift_race_never_consumes_an_unattested_revision(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'state.sqlite';proof=self.setup_graph(path)
            self.run_race(path,['claim','drift'],None,proof)
            with Runtime(path,clock=lambda:1000.0) as rt:
                self.assertEqual(rt.resource('mid')['version'],3)
                self.assertEqual(rt.resource('out')['version'],1)
                self.assertNotEqual(rt.task('B')['status'],'VERIFIED')
                for row in rt.db.execute("SELECT runs.id FROM runs WHERE task='B'"):
                    self.assertFalse(rt._dependencies_current(row['id']))
                self.assertTrue(rt.check_journal())
