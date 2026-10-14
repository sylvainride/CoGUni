"""Authenticated six-criterion gate contracts using explicit synthetic checks."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from universal.core import GuardError, Intent, Runtime, digest
from universal.gates import CheckResult, CRITERIA, GateEngine


def changed_fixture(observations, context, now):
    return CheckResult('PASS','different_fixture')


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'state.sqlite'
        self.now=[1000.0];self.rt=Runtime(self.path,clock=lambda:self.now[0])
        self.rt.put_resource('input','alpha');self.rt.put_resource('output','')
        self.rt.add_task('T','input','output','uppercase',digest('ALPHA'))
        self.claim=self.rt.claim('owner')
        self.rt.execute(Intent(self.claim['run_id'],'artifact.write','output',1,'artifact-effect',self.claim['fence'],{'content':'ALPHA'}),self.claim['token'])
        self.proof=self.rt.verify('T','env')
        self.gate=GateEngine(self.rt);self.verifiers=self.gate.register_synthetic_verifiers()
        self.contract=self.gate.define_contract('T',self.claim['run_id'],self.proof['evidence'],'env',self.verifiers)
    def tearDown(self):self.rt.close();self.temp.cleanup()
    def observation(self,criterion):
        context=self.gate.contract_context(self.contract)
        values={'tests':{'cases':[True,True]},'licenses':{'licenses':['MIT'],'allowed':['MIT','BSD-3-Clause']},
                'secrets':{'artifact_content':'ALPHA','forbidden_markers':['PRIVATE_FIXTURE_KEY']},
                'provenance':{'source':{'id':'input','version':1,'sha':digest('alpha'),'origin':'owner_fixture'}},
                'consent':{'approved':True,'contract_id':self.contract,'scope':'local_validation_only','expires_at':1100.0},
                'environment':{'environment':'env'}}
        return {'executed':True,'artifact_sha':context['artifact_sha'],**values[criterion]}
    def check_all(self):
        return {criterion:self.gate.run_check(self.contract,criterion,self.observation(criterion)) for criterion in CRITERIA}
    def accepted(self):return self.gate.evaluate(self.contract,'env')['accepted']
    def test_all_six_positive_fixture_checks_accept_local_gate_only(self):
        self.check_all();value=self.gate.evaluate(self.contract,'env')
        self.assertTrue(value['accepted']);self.assertEqual(value['purpose'],'local_validation_only')
        self.assertEqual(value['criteria'],{key:'PASS' for key in CRITERIA})
        self.assertTrue(self.rt.check_journal())
    def test_missing_each_mandatory_criterion_blocks(self):
        for missing in CRITERIA:
            contract=self.gate.define_contract('T',self.claim['run_id'],self.proof['evidence'],'env',self.verifiers)
            for criterion in CRITERIA-{missing}:
                value=self.observation(criterion)
                if criterion=='consent':value['contract_id']=contract
                self.gate.run_check(contract,criterion,value)
            result=self.gate.evaluate(contract,'env')
            self.assertFalse(result['accepted']);self.assertEqual(result['criteria'][missing],'missing')
    def test_omitting_criteria_from_contract_is_rejected(self):
        with self.assertRaises(GuardError):self.gate.define_contract('T',self.claim['run_id'],self.proof['evidence'],'env',{'tests':self.verifiers['tests']})
    def test_claimed_pass_without_execution_remains_unknown(self):
        self.check_all();row=self.gate.run_check(self.contract,'tests',{'executed':False,'outcome':'PASS','artifact_sha':digest('ALPHA')})
        self.assertEqual(row['outcome'],'UNKNOWN');self.assertFalse(self.accepted())
    def test_signed_fail_latest_cannot_use_previous_pass(self):
        self.check_all();row=self.gate.run_check(self.contract,'tests',{**self.observation('tests'),'cases':[True,False]})
        self.assertEqual(row['outcome'],'FAIL');self.assertFalse(self.accepted())
    def test_license_fixture_disallowed_blocks(self):
        self.check_all();self.gate.run_check(self.contract,'licenses',{**self.observation('licenses'),'licenses':['unapproved-fixture']})
        self.assertFalse(self.accepted())
    def test_secret_marker_fixture_blocks(self):
        self.check_all();self.gate.run_check(self.contract,'secrets',{**self.observation('secrets'),'forbidden_markers':['ALPHA']})
        self.assertFalse(self.accepted())
    def test_untrusted_source_provenance_fixture_blocks(self):
        self.check_all();value=self.observation('provenance');value['source']['origin']='worker_claim'
        self.gate.run_check(self.contract,'provenance',value);self.assertFalse(self.accepted())
    def test_consent_expiration_blocks_without_rewriting_signed_outcome(self):
        self.check_all();self.now[0]=1101.0
        self.assertFalse(self.accepted())
    def test_wrong_scope_consent_blocks(self):
        self.check_all();self.gate.run_check(self.contract,'consent',{**self.observation('consent'),'scope':'publish'})
        self.assertFalse(self.accepted())
    def test_wrong_environment_blocks_and_is_not_worker_selected(self):
        self.check_all();self.assertFalse(self.gate.evaluate(self.contract,'other-env')['accepted'])
    def test_output_or_source_drift_invalidates_signed_contract(self):
        self.check_all();self.rt.put_resource('output','ALPHA',2)
        self.assertFalse(self.accepted())
        with self.assertRaises(GuardError):self.gate.run_check(self.contract,'tests',self.observation('tests'))
    def test_terminal_proof_revocation_invalidates_gate(self):
        self.check_all();self.rt.revoke_evidence(self.proof['evidence'],'owner_withdrawal')
        self.assertFalse(self.accepted())
    def test_wrong_terminal_run_or_task_refuses_contract(self):
        with self.assertRaises(GuardError):self.gate.define_contract('T','different-run',self.proof['evidence'],'env',self.verifiers)
    def test_revoked_attestation_is_immutable_and_blocks(self):
        attestations=self.check_all();aid=attestations['licenses']['attestation']
        self.assertTrue(self.gate.revoke_attestation(aid));self.assertFalse(self.gate.revoke_attestation(aid))
        self.assertFalse(self.accepted())
        with self.assertRaises(sqlite3.IntegrityError):self.rt.db.execute('DELETE FROM gate_revocations')
    def test_signing_epoch_rotation_invalidates_old_contract(self):
        self.check_all();self.assertEqual(self.gate.rotate_signing_key(),2)
        self.assertFalse(self.accepted())
    def test_forged_attestation_signature_never_accepts(self):
        self.check_all()
        row=self.rt.db.execute("SELECT * FROM gate_attestations WHERE criterion='tests'").fetchone()
        body=json.loads(row['body']);body['attestation_id']='forged'
        self.rt.db.execute('INSERT INTO gate_attestations(id,contract_id,criterion,epoch,body,signature) VALUES(?,?,?,?,?,?)',('forged',self.contract,'tests',1,json.dumps(body),'0'*64))
        self.assertFalse(self.accepted())
    def test_registered_verifier_source_change_refused(self):
        self.gate.runners['synthetic-tests']=changed_fixture
        with self.assertRaises(GuardError):self.gate.run_check(self.contract,'tests',self.observation('tests'))
    def test_backup_and_restore_keep_signatures_and_require_reloaded_runners(self):
        self.check_all();backup=Path(self.temp.name)/'backup.sqlite';self.rt.backup(backup)
        with Runtime(backup,clock=lambda:1000.0) as restored:
            engine=GateEngine(restored)
            self.assertTrue(engine.evaluate(self.contract,'env')['accepted'])
            unknown=engine.run_check(self.contract,'tests',self.observation('tests'))
            self.assertEqual(unknown['outcome'],'UNKNOWN')
            self.assertFalse(engine.evaluate(self.contract,'env')['accepted'])
    def test_export_omits_signer_secrets_and_tokens(self):
        self.check_all();text=json.dumps(self.rt.snapshot())
        key=self.rt.db.execute('SELECT secret FROM gate_keys').fetchone()[0]
        self.assertNotIn(key.hex(),text);self.assertNotIn(self.claim['token'],text)
        self.assertNotIn('gate_keys',text)
    def test_invalid_or_oversized_observations_never_attest_pass(self):
        for obs in ({'x':'a'*100000},{'x':float('nan')},{'x':chr(0xd800)}):
            with self.assertRaises(GuardError):self.gate.run_check(self.contract,'tests',obs)
        self.assertFalse(self.accepted())
