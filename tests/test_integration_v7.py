"""Actual confined pipelines, owner rotation and conservative migrations."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from universal.broker import WorkerGate, environment_identity, run_pool
from universal.core import GuardError, Intent, Runtime, SCHEMA, digest

MODE = "VERIFIED_UPSTREAM_OUTPUT"


def make_chain(path, count):
    with Runtime(path) as rt:
        rt.put_resource("r0", "alpha")
        for i in range(1, count + 1):
            rt.put_resource("r" + str(i), "")
        for i in range(count):
            args = {} if i == 0 else {"dependencies": ["T%03d" % (i-1)], "input_mode": MODE,
                                     "producer": "T%03d" % (i-1), "source_expected_sha": digest("ALPHA")}
            rt.add_task("T%03d" % i, "r" + str(i), "r" + str(i+1), "uppercase" if i == 0 else "copy", digest("ALPHA"), **args)


class IntegrationV7Tests(unittest.TestCase):
    def test_actual_confined_two_three_and_hundred_stage_pipelines(self):
        for count in (2, 3, 100):
            with self.subTest(stages=count), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "state.sqlite"
                make_chain(path, count)
                reports = run_pool(path, workers=2, max_jobs=100, timeout=30)
                jobs = [job for report in reports for job in report["results"]]
                self.assertEqual(len(jobs), count)
                self.assertTrue(all(job["verification"]["accepted_for_gate"] for job in jobs))
                with Runtime(path) as rt:
                    self.assertEqual(rt.resource("r" + str(count))["content"], "ALPHA")
                    self.assertEqual(rt.db.execute("SELECT count(*) FROM evidence WHERE outcome='PASS'").fetchone()[0], count)
                    self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], count)
                    self.assertEqual(rt.db.execute("SELECT count(*) FROM run_input_bindings").fetchone()[0], count-1)
                    self.assertTrue(rt.check_journal())

    def test_actual_pool_retains_owner_rotated_credentials_without_exposing_them(self):
        original = WorkerGate.handle
        rotations = []
        def rotate_after_read(gate, message):
            value = original(gate, message)
            if message["op"] == "read":
                old = gate.claim["token"]
                changed = gate.rotate_credentials()
                self.assertNotEqual(old, changed.token)
                intent = Intent(gate.claim["run_id"], "artifact.write", gate.claim["task"]["output"], gate.claim["output_version"], gate.claim["run_id"]+".write", gate.claim["fence"], {"content": "ALPHA"})
                with self.assertRaises(GuardError):
                    gate.runtime.execute(intent, old)
                rotations.append((old, changed.token))
            return value
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.sqlite"
            make_chain(path, 3)
            with patch.object(WorkerGate, "handle", rotate_after_read):
                reports = run_pool(path, workers=2)
            self.assertEqual(len(rotations), 3)
            self.assertTrue(all(job["verification"]["accepted_for_gate"] for r in reports for job in r["results"]))
            with Runtime(path) as rt:
                exported = str(rt.snapshot())
                self.assertFalse(any(token in exported for pair in rotations for token in pair))
                self.assertEqual(rt.db.execute("SELECT count(*) FROM events WHERE action='credential.rotate'").fetchone()[0], 3)
                self.assertTrue(rt.check_journal())

    def test_done_refused_when_committed_run_scope_was_revoked(self):
        with tempfile.TemporaryDirectory() as temp, Runtime(Path(temp)/"state.sqlite") as rt:
            rt.put_resource("input", "x");rt.put_resource("output", "")
            rt.add_task("T", "input", "output", "copy", digest("x"))
            claim=rt.claim("owner")
            gate=WorkerGate(rt, claim)
            rt.execute(Intent(claim["run_id"],"artifact.write","output",1,claim["run_id"]+".write",claim["fence"],{"content":"x"}),claim["token"])
            rt.revoke(claim["run_id"])
            with self.assertRaises(GuardError):
                gate.handle({"version":1,"request_id":1,"job_id":claim["run_id"],"op":"done"})
            self.assertEqual(rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0],0)

    def test_v2_migration_keeps_existing_task_pinned_and_rollback_restores_v2(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"v2.sqlite"
            with closing(sqlite3.connect(path)) as db, db:
                db.executescript(SCHEMA)
                db.execute("INSERT INTO resources VALUES('i','x',1,?)",(digest('x'),))
                db.execute("INSERT INTO resources VALUES('o','',1,?)",(digest(''),))
                db.execute("INSERT INTO tasks(id,input,output,action,expected_sha,input_version,status) VALUES('T','i','o','copy',?,1,'READY')",(digest('x'),))
            with patch.object(Runtime, "_event", side_effect=RuntimeError("migration_rollback")):
                with self.assertRaises(RuntimeError):Runtime(path)
            with closing(sqlite3.connect(path)) as db, db:
                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0],2)
                self.assertNotIn("input_mode",{r[1] for r in db.execute("PRAGMA table_info(tasks)")})
                self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='run_input_bindings'").fetchone())
            with Runtime(path) as rt:
                self.assertEqual(rt.task("T")["input_mode"],"PINNED_VERSION")
                self.assertEqual(rt.task("T")["input_version"],1)
                self.assertEqual(rt.snapshot()["schema_version"],4)
                self.assertTrue(rt.check_journal())

    def test_migration_process_crash_is_atomic(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"v2.sqlite"
            db=sqlite3.connect(path)
            try:db.executescript(SCHEMA)
            finally:db.close()
            program="""import os,sys
from universal.core import Runtime
def crash(*args,**kwargs):os._exit(79)
Runtime._event=crash
Runtime(sys.argv[1])
"""
            p=subprocess.run([sys.executable,"-B","-c",program,str(path)],capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,79)
            db=sqlite3.connect(path)
            try:
                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0],2)
                self.assertNotIn("input_mode",{r[1] for r in db.execute("PRAGMA table_info(tasks)")})
            finally:db.close()
            with Runtime(path) as rt:self.assertEqual(rt.snapshot()["schema_version"],4)

    def test_integer_clock_audit_roundtrip_remains_consistent(self):
        with tempfile.TemporaryDirectory() as temp, Runtime(Path(temp)/"state.sqlite",clock=lambda:1000) as rt:
            rt.put_resource("i","x")
            self.assertTrue(rt.check_journal())

    def test_claimed_binding_cannot_be_verified_in_another_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"state.sqlite";make_chain(path,2)
            with Runtime(path) as rt:
                a=rt.claim("owner",environment="env-a")
                rt.execute(Intent(a["run_id"],"artifact.write","r1",1,a["run_id"]+".write",a["fence"],{"content":"ALPHA"}),a["token"])
                rt.verify(a["task"]["id"],"env-a")
                b=rt.claim("owner",environment="env-a")
                rt.execute(Intent(b["run_id"],"artifact.write","r2",1,b["run_id"]+".write",b["fence"],{"content":"ALPHA"}),b["token"])
                with self.assertRaises(GuardError):rt.verify(b["task"]["id"],"env-b")
                self.assertEqual(rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0],1)

    def test_dynamic_batch_forward_references_and_ambiguity_rollback(self):
        with tempfile.TemporaryDirectory() as temp, Runtime(Path(temp)/"state.sqlite") as rt:
            for name,text in [('i','x'),('mid',''),('o','')]:rt.put_resource(name,text)
            producer={"id":"A","source":"i","output":"mid","action":"copy","expected_sha":digest('x')}
            consumer={"id":"B","source":"mid","output":"o","action":"copy","expected_sha":digest('x'),"dependencies":["A"],"input_mode":MODE,"producer":"A","source_expected_sha":digest('x')}
            self.assertEqual(rt.add_tasks_batch([consumer,producer]),['B','A'])
            self.assertEqual(rt.task('B')['producer'],'A')
            rt.add_task('P','i','mid','copy',digest('x'))
            with self.assertRaises(GuardError):rt.add_dependency('B','P',expected_revision=1)
            self.assertEqual(rt.task('B')['revision'],1)

    def test_broker_crash_after_dynamic_commit_preserves_binding_on_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"state.sqlite";make_chain(path,3)
            program="""import os,sys
from universal.broker import WorkerGate,run_pool
original=WorkerGate.handle
def crash(self,message):
 result=original(self,message)
 if message['op']=='write' and self.claim['task']['input_mode']=='VERIFIED_UPSTREAM_OUTPUT':os._exit(82)
 return result
WorkerGate.handle=crash
run_pool(sys.argv[1],workers=1)
"""
            p=subprocess.run([sys.executable,'-B','-c',program,str(path)],capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,82,p.stderr)
            reports=run_pool(path,workers=1)
            self.assertTrue(all(job['verification']['accepted_for_gate'] for r in reports for job in r['results']))
            with Runtime(path) as rt:
                self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0],3)
                self.assertEqual(rt.db.execute("SELECT count(*) FROM runs").fetchone()[0],3)
                self.assertEqual(rt.db.execute("SELECT count(*) FROM run_input_bindings").fetchone()[0],2)
                self.assertEqual(rt.task('T002')['status'],'VERIFIED')


class BrokerBudgetTests(unittest.TestCase):
    def test_request_budget_cannot_grow_under_unique_monotone_ids(self):
        with tempfile.TemporaryDirectory() as temp,Runtime(Path(temp)/'state.sqlite') as rt:
            rt.put_resource('input','x');rt.put_resource('output','')
            rt.add_task('T','input','output','copy',digest('x'));claim=rt.claim('owner')
            gate=WorkerGate(rt,claim)
            for n in range(1,gate.MAX_REQUESTS_PER_JOB+1):
                gate.handle({'version':1,'request_id':n,'job_id':claim['run_id'],'op':'read','resource':'input','expected_version':1,'key':claim['run_id']+'.read','fence':claim['fence'],'args':{}})
            with self.assertRaises(GuardError):
                gate.handle({'version':1,'request_id':9,'job_id':claim['run_id'],'op':'read','resource':'input','expected_version':1,'key':claim['run_id']+'.read','fence':claim['fence'],'args':{}})
            self.assertEqual(rt.resource('output')['version'],1)

    def test_actual_revoked_channel_stops_without_stopping_independent_task(self):
        original=WorkerGate.handle
        def revoke_after_read(gate,message):
            result=original(gate,message)
            if message['op']=='read' and gate.claim['task']['id']=='A':gate.runtime.revoke(gate.claim['run_id'])
            return result
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'state.sqlite'
            with Runtime(path) as rt:
                for suffix in ('a','b'):
                    rt.put_resource('in-'+suffix,'x');rt.put_resource('out-'+suffix,'')
                    rt.add_task(suffix.upper(),'in-'+suffix,'out-'+suffix,'copy',digest('x'))
            with patch.object(WorkerGate,'handle',revoke_after_read):reports=run_pool(path,workers=2)
            with Runtime(path) as rt:
                self.assertEqual(rt.task('A')['status'],'BLOCKED')
                self.assertEqual(rt.resource('out-a')['version'],1)
                self.assertEqual(rt.task('B')['status'],'VERIFIED')
                self.assertEqual(rt.db.execute("SELECT count(*) FROM events WHERE action='ipc.refused'").fetchone()[0],1)
                self.assertTrue(rt.check_journal())


class BoundBackupTests(unittest.TestCase):
    def test_backup_restores_existing_bound_run_and_accepted_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'state.sqlite';make_chain(path,3)
            run_pool(path,workers=2)
            backup=Path(temp)/'backup.sqlite'
            with Runtime(path) as rt:
                rt.backup(backup)
                original=list(rt.db.execute('SELECT * FROM run_input_bindings ORDER BY run'))
            with Runtime(backup) as restored:
                current=list(restored.db.execute('SELECT * FROM run_input_bindings ORDER BY run'))
                self.assertEqual([tuple(r) for r in current],[tuple(r) for r in original])
                for row in restored.db.execute('SELECT id FROM evidence'):
                    self.assertTrue(restored.proof_is_accepted_for_gate(row['id'],environment_identity()))
                self.assertEqual(restored.db.execute('SELECT count(*) FROM effects').fetchone()[0],3)
                self.assertTrue(restored.check_journal())
