"""Unknown output hashes require independent real policy checks and lineage."""
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from universal.broker import environment_identity, WorkerGate
from universal.core import GuardError, Intent, Runtime, canonical, digest
from universal.generative import GenerativeValidator, MODE
from universal.worker import run_pool


def policy():
    return {"version":1,"entrypoint":"candidate.py","function":"solve",
            "tests":[{"args":[-1],"expected":1},{"args":[0],"expected":3},{"args":[4],"expected":11}],
            "allowed_licenses":["MIT"],"forbidden_markers":["PRIVATE_FIXTURE_CANARY"],"max_seconds":3.0}


def candidate(code="def solve(x):\n    return x * 2 + 3\n"):
    return canonical({"files":{"candidate.py":code,"LICENSE":"SPDX-License-Identifier: MIT\n"}})


def gen_crash(path,task,run,point):
    with Runtime(path,clock=lambda:1000.0) as rt:
        validator=GenerativeValidator(rt)
        def crash(where):
            if where==point:os._exit(84)
        validator.verify(task,environment_identity(),expected_run_id=run,crash_hook=crash)


class GenerativeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'owner.sqlite'
        self.now=[1000.0];self.rt=Runtime(self.path,clock=lambda:self.now[0]);self.validator=GenerativeValidator(self.rt)
        self.validator.register_policy('affine',policy())
        self.rt.put_resource('mission','Implement solve(x)=2*x+3');self.rt.put_resource('artifact','')
        self.rt.source_snapshot('mission-owner','mission','owner_contract')
    def tearDown(self):self.rt.close();self.temp.cleanup()
    def add(self,name='G',source='mission',output='artifact',**kwargs):
        self.rt.add_task(name,source,output,'candidate',None,validation_mode=MODE,policy_id='affine',**kwargs)
    def submit(self,name='G',content=None):
        claim=self.rt.claim('candidate-fixture',ttl=60,environment=environment_identity(),supported_actions=['candidate'])
        self.assertEqual(claim['task']['id'],name)
        intent=Intent(claim['run_id'],'artifact.write',claim['task']['output'],claim['output_version'],claim['run_id']+'.write',claim['fence'],{'content':candidate() if content is None else content})
        self.rt.execute(intent,claim['token']);return claim
    def verify(self,claim,**kwargs):
        return self.validator.verify(claim['task']['id'],environment_identity(),expected_run_id=claim['run_id'],**kwargs)
    def test_strict_default_still_requires_sha_and_registered_action(self):
        for action in ['copy','candidate']:
            with self.assertRaises(GuardError):self.rt.add_task('bad','mission','artifact',action,None)
        self.rt.add_task('strict','mission','artifact','copy',digest('Implement solve(x)=2*x+3'))
        self.assertEqual(self.rt.task('strict')['validation_mode'],'DETERMINISTIC_EXACT_SHA')
    def test_generative_requires_mode_policy_action_and_absent_expected_sha(self):
        for extra in [{'policy_id':None},{'policy_id':'absent'},{'expected_sha':digest(candidate())},{'action':'copy'},{'validation_mode':'UNKNOWN'}]:
            args={'validation_mode':MODE,'policy_id':'affine','expected_sha':None,'action':'candidate',**extra}
            with self.assertRaises(GuardError):self.rt.add_task('bad','mission','artifact',args.pop('action'),args.pop('expected_sha'),**args)
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM tasks').fetchone()[0],0)
    def test_new_unknown_code_accepts_independent_tests_and_actual_git_tree(self):
        self.add();self.assertIsNone(self.rt.task('G')['expected_sha'])
        self.assertIsNone(self.rt.snapshot()['tasks'][0]['expected_sha'])
        claim=self.submit();result=self.verify(claim)
        self.assertEqual(result['outcome'],'PASS');self.assertTrue(result['accepted_for_gate'])
        self.assertEqual(len(result['tree_sha']),40)
        self.assertEqual(self.rt._evidence(result['evidence'])['method'],'independent_generative_policy_v1')
        self.assertTrue(self.rt.check_journal())
    def test_two_different_unknown_implementations_satisfy_same_policy(self):
        proofs=[]
        for name,code in [('A','def solve(x):\n    return x + x + 3\n'),('B','def solve(x):\n    return 3 + 2 * x\n')]:
            self.rt.put_resource(name+'out','');self.add(name,output=name+'out')
            proofs.append(self.verify(self.submit(name,candidate(code))))
        self.assertTrue(all(p['accepted_for_gate'] for p in proofs))
        self.assertNotEqual(proofs[0]['tree_sha'],proofs[1]['tree_sha'])
    def test_caller_sha_verifier_cannot_certify_generative_candidate(self):
        self.add();claim=self.submit()
        with self.assertRaises(GuardError):self.rt.verify('G',environment_identity(),expected_run_id=claim['run_id'])
        self.assertEqual(self.rt.task('G')['status'],'RESULT_READY')
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0],0)
    def test_worker_pass_or_bad_result_does_not_satisfy_behavior_policy(self):
        self.add();claim=self.submit(content=candidate('def solve(x):\n    return "PASS"\n'))
        result=self.verify(claim)
        self.assertEqual(result['outcome'],'FAIL');self.assertFalse(result['accepted_for_gate'])
        self.assertEqual(self.rt.task('G')['status'],'FAILED')
        self.assertTrue(self.rt.proof_is_fresh(result['evidence']))
    def test_missing_license_and_literal_secret_marker_fail_real_file_checks(self):
        for name,files in [('L',{'candidate.py':'def solve(x):\n    return x*2+3\n'}),('S',{'candidate.py':'# PRIVATE_FIXTURE_CANARY\ndef solve(x):\n    return x*2+3\n','LICENSE':'SPDX-License-Identifier: MIT\n'})]:
            self.rt.put_resource(name+'out','');self.add(name,output=name+'out')
            result=self.verify(self.submit(name,canonical({'files':files})))
            self.assertEqual(result['outcome'],'UNKNOWN' if name=='L' else 'FAIL');self.assertFalse(result['accepted_for_gate'])
    def test_candidate_envelope_duplicate_keys_traversal_and_extra_pass_denied(self):
        from universal.generative import candidate_files
        for text in ['{"files":{},"files":{}}',canonical({'files':{'../owner.sqlite':'data'}}),canonical({'files':{'candidate.py':'x'},'outcome':'PASS'})]:
            with self.assertRaises((GuardError,ValueError)):candidate_files(text)
    def test_actual_environment_and_run_identity_required(self):
        self.add();claim=self.submit()
        with self.assertRaises(GuardError):self.validator.verify('G','claimed-environment',expected_run_id=claim['run_id'])
        with self.assertRaises(GuardError):self.validator.verify('G',environment_identity(),expected_run_id='other')
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0],0)
    def test_source_drift_after_checks_cannot_sign_current_evidence(self):
        self.add();claim=self.submit()
        def drift(point):
            if point=='after_checks_before_commit':self.rt.put_resource('mission','changed',1)
        with self.assertRaises(GuardError):self.verify(claim,crash_hook=drift)
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0],0)
    def test_contract_drift_after_checks_refused_even_if_bytes_same(self):
        self.add();claim=self.submit()
        def drift(point):
            if point=='after_checks_before_commit':
                with self.rt.transaction():self.rt.db.execute("UPDATE tasks SET revision=revision+1 WHERE id='G'")
        with self.assertRaises(GuardError):self.verify(claim,crash_hook=drift)
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM generative_evaluations').fetchone()[0],0)
    def test_revocation_or_expiry_during_checks_prevents_acceptance(self):
        for name,operation in [('R',lambda claim:self.rt.revoke(claim['run_id'])),('E',lambda claim:self.now.__setitem__(0,1061.0))]:
            self.rt.put_resource(name+'out','');self.add(name,output=name+'out');claim=self.submit(name)
            def invalidate(point):
                if point=='after_checks_before_commit':operation(claim)
            with self.assertRaises(GuardError):self.verify(claim,crash_hook=invalidate)
            self.assertEqual(self.rt.task(name)['status'],'RESULT_READY')
    def test_policy_immutable_revocation_blocks_acceptance_and_future_claim(self):
        altered=policy();altered['tests'][0]['expected']=0
        with self.assertRaises(GuardError):self.validator.register_policy('affine',altered)
        self.add();claim=self.submit();proof=self.verify(claim)
        self.validator.revoke_policy('affine')
        self.assertFalse(self.rt.proof_is_accepted_for_gate(proof['evidence'],environment_identity()))
        with self.assertRaises(GuardError):self.add('new')
    def test_epoch_rotation_invalidates_existing_generative_evidence(self):
        self.add();proof=self.verify(self.submit());self.validator.rotate_signing_key()
        self.assertFalse(self.rt.proof_is_accepted_for_gate(proof['evidence'],environment_identity()))
        self.assertEqual(self.rt.task('G')['status'],'PARTIAL')
    def test_generative_to_generative_chain_captures_unknown_verified_sha(self):
        self.rt.put_resource('final','');self.add('A')
        self.add('B',source='artifact',output='final',dependencies=['A'],input_mode='VERIFIED_UPSTREAM_POLICY_OUTPUT',producer='A',source_policy_id='affine')
        self.assertIsNone(self.rt.task('B')['source_expected_sha'])
        first=self.verify(self.submit('A'));second=self.verify(self.submit('B',candidate('def solve(x):\n    return 3+2*x\n')))
        self.assertTrue(first['accepted_for_gate'] and second['accepted_for_gate'])
        binding=self.rt.db.execute('SELECT * FROM run_input_bindings').fetchone()
        self.assertEqual(binding['sha'],self.rt.resource('artifact')['sha'])
        self.assertEqual(binding['producer_policy_sha'],self.rt.db.execute("SELECT sha FROM validation_policies WHERE id='affine'").fetchone()[0])
        self.assertEqual(binding['producer_epoch'],1)
        self.validator.revoke_policy('affine')
        self.assertFalse(self.rt.proof_is_accepted_for_gate(second['evidence'],environment_identity()))
    def test_producer_policy_ambiguity_and_sha_mode_mix_denied(self):
        self.add('A');self.add('C')
        self.rt.put_resource('final','')
        for kwargs in [{'dependencies':['A','C'],'producer':'A','source_policy_id':'affine'}, {'dependencies':['A'],'producer':'A','source_policy_id':'affine','source_expected_sha':digest('x')}]:
            with self.assertRaises(GuardError):self.add('B',source='artifact',output='final',input_mode='VERIFIED_UPSTREAM_POLICY_OUTPUT',**kwargs)
        with self.assertRaises(GuardError):self.rt.add_task('exact','artifact','final','copy',digest(candidate()),['A'],input_mode='VERIFIED_UPSTREAM_OUTPUT',producer='A',source_expected_sha=digest(candidate()))
    def test_equal_byte_new_version_invalidates_policy_binding(self):
        self.rt.put_resource('final','');self.add('A');self.add('B',source='artifact',output='final',dependencies=['A'],input_mode='VERIFIED_UPSTREAM_POLICY_OUTPUT',producer='A',source_policy_id='affine')
        self.verify(self.submit('A'));claim=self.rt.claim('next',ttl=60,environment=environment_identity())
        self.rt.put_resource('artifact',self.rt.resource('artifact')['content'],2)
        with self.assertRaises(GuardError):self.rt.execute(Intent(claim['run_id'],'artifact.write','final',1,'child.write',claim['fence'],{'content':candidate()}),claim['token'])
        self.assertEqual(self.rt.resource('final')['version'],1)
    def test_deterministic_pool_skips_unclaimed_and_pending_generative_tasks(self):
        self.add('A');self.rt.put_resource('strictout','');self.rt.add_task('Z','mission','strictout','copy',digest('Implement solve(x)=2*x+3'))
        first=run_pool(self.path,workers=1,max_jobs=4)
        self.assertEqual(len(first[0]['results']),1);self.assertEqual(self.rt.task('A')['status'],'READY')
        claim=self.submit('A');second=run_pool(self.path,workers=1,max_jobs=4)
        self.assertFalse(second[0]['results']);self.assertEqual(self.rt.task('A')['status'],'RESULT_READY')
        self.assertTrue(self.verify(claim)['accepted_for_gate'])
    def test_worker_ipc_can_submit_candidate_but_not_verify_or_select_policy(self):
        self.add();claim=self.rt.claim('worker',ttl=60);gate=WorkerGate(self.rt,claim)
        body={'version':1,'job_id':claim['run_id'],'request_id':1,'op':'verify','outcome':'PASS'}
        from universal.protocol import ProtocolError
        with self.assertRaises(ProtocolError):gate.handle(body)
        message={'version':1,'job_id':claim['run_id'],'request_id':1,'op':'write','resource':'artifact','expected_version':1,'key':claim['run_id']+'.write','fence':claim['fence'],'args':{'content':candidate()}}
        self.assertEqual(gate.handle(message)['version'],2)
        self.assertEqual(self.rt.task('G')['status'],'RESULT_READY')
    def test_backup_restores_policies_signed_evidence_and_lineage(self):
        self.add();proof=self.verify(self.submit());backup=Path(self.temp.name)/'backup.sqlite';self.rt.backup(backup)
        with Runtime(backup,clock=lambda:1000.0) as restored:
            self.assertTrue(restored.proof_is_accepted_for_gate(proof['evidence'],environment_identity()))
            self.assertNotIn('secret',str(restored.snapshot()))
    def test_policy_and_evaluation_rows_immutable(self):
        self.add();self.verify(self.submit())
        for sql in ['UPDATE validation_policies SET body="{}"','DELETE FROM generative_evaluations']:
            with self.assertRaises(sqlite3.IntegrityError),self.rt.transaction():self.rt.db.execute(sql)
    def test_verifier_crash_before_and_after_commit_preserves_candidate(self):
        ctx=multiprocessing.get_context('spawn')
        for index,point in enumerate(['before_verification_commit','after_verification_commit']):
            name='C'+str(index);self.rt.put_resource(name+'out','');self.add(name,output=name+'out');claim=self.submit(name)
            child=ctx.Process(target=gen_crash,args=(str(self.path),name,claim['run_id'],point));child.start();child.join(15)
            if child.is_alive():child.terminate();child.join(3)
            self.assertEqual(child.exitcode,84)
            if point=='before_verification_commit':
                self.assertEqual(self.rt.task(name)['status'],'RESULT_READY');proof=self.verify(claim)
            else:
                self.assertEqual(self.rt.task(name)['status'],'VERIFIED');evidence=self.rt.db.execute('SELECT id FROM evidence WHERE task=?',(name,)).fetchone()[0]
                self.assertTrue(self.rt.proof_is_accepted_for_gate(evidence,environment_identity()))
            self.assertEqual(self.rt.resource(name+'out')['version'],2)
            self.assertEqual(self.rt.db.execute('SELECT count(*) FROM effects WHERE resource=?',(name+'out',)).fetchone()[0],1)

    def test_expiry_during_final_git_recheck_is_denied_before_signature(self):
        from universal import generative
        self.add();claim=self.submit();original=generative.candidate_files
        def delayed(content):
            result=original(content);self.now[0]=1061.0;return result
        def hook(point):
            if point=='after_checks_before_commit':generative.candidate_files=delayed
        try:
            with self.assertRaises(GuardError):self.verify(claim,crash_hook=hook)
        finally:generative.candidate_files=original
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0],0)
        self.assertEqual(self.rt.task('G')['status'],'RESULT_READY')
    def test_lease_replacement_or_fence_change_during_checks_denied(self):
        self.add();claim=self.submit()
        def change(point):
            if point=='after_checks_before_commit':
                with self.rt.transaction():self.rt.db.execute('UPDATE leases SET fence=fence+1 WHERE run=?',(claim['run_id'],))
        with self.assertRaises(GuardError):self.verify(claim,crash_hook=change)
        self.assertEqual(self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0],0)
    def test_owner_source_pin_required_and_later_reclassification_invalidates(self):
        self.add();claim=self.submit()
        self.rt.source_snapshot('mission-owner','mission','untrusted')
        with self.assertRaises(GuardError):self.verify(claim)
        self.rt.source_snapshot('mission-owner','mission','owner_contract');proof=self.verify(claim)
        self.assertTrue(proof['accepted_for_gate'])
        self.rt.source_snapshot('mission-owner','mission','untrusted')
        self.assertFalse(self.rt.proof_is_accepted_for_gate(proof['evidence'],environment_identity()))

    def test_owner_ack_loss_replay_observes_same_current_proof_without_checks(self):
        self.add();claim=self.submit();first=self.verify(claim)
        before=(self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0],self.rt.db.execute('SELECT count(*) FROM events').fetchone()[0])
        with patch('universal.policy_runner.run_policy_checks',side_effect=AssertionError('must_not_rerun')):
            again=self.verify(claim)
        self.assertEqual(again['evidence'],first['evidence']);self.assertTrue(again['replayed'])
        self.assertEqual((self.rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0],self.rt.db.execute('SELECT count(*) FROM events').fetchone()[0]),before)
        self.validator.rotate_signing_key()
        with self.assertRaises(GuardError):self.verify(claim)


if __name__=='__main__':unittest.main()
