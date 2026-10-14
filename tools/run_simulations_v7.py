#!/usr/bin/env python3
"""400 distinct local control simulations; no inference/model or external API.

16 reviewed fixture families x 25 varying inputs. Expected decisions are explicit
behavioral oracles, not supplied to Runtime and not its private predicates. This
is not 400 domains or 400 reasoning benchmarks. OS process confinement is tested
separately by the production-pool tests; this harness uses trusted owner fixtures.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from universal.core import GuardError, Intent, Runtime, digest
from universal.credentials import rotate_run_token
from universal.gates import GateEngine, CRITERIA
from universal.outbox import FakeAdapter, Outbox

ENV='simulations-v7-owner-fixture'
MODE='VERIFIED_UPSTREAM_OUTPUT'
FAMILIES=('flow_two','flow_three','pinned_drift','producer_fail','upstream_equal_bytes_drift','revoked_parent_after_claim',
          'rotation_old_token','rotation_replay','revoked_tokens','fake_ack_loss','fake_before_effect','fake_compensation',
          'gate_all_pass','gate_unknown','gate_fail','gate_stale')


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def finish(rt, claim, content, *, env=ENV):
    read=Intent(claim['run_id'],'artifact.read',claim['task']['input'],claim['task']['input_version'],claim['run_id']+'.read',claim['fence'],{})
    actual=rt.execute(read,claim['token'])
    write=Intent(claim['run_id'],'artifact.write',claim['task']['output'],claim['output_version'],claim['run_id']+'.write',claim['fence'],{'content':content})
    receipt=rt.execute(write,claim['token'])
    proof=rt.verify(claim['task']['id'],env,expected_run_id=claim['run_id'])
    return actual,receipt,proof


def refused(call):
    try:call()
    except GuardError:return True
    raise AssertionError('expected refusal, operation succeeded')


def chain(rt,content,count,*,dynamic=True):
    expected=content.upper();rt.put_resource('r0',content)
    for i in range(1,count+1):rt.put_resource('r'+str(i),'')
    for i in range(count):
        extra={'dependencies':['T'+str(i-1)]} if i else {}
        if i and dynamic:extra.update(input_mode=MODE,producer='T'+str(i-1),source_expected_sha=digest(expected))
        rt.add_task('T'+str(i),'r'+str(i),'r'+str(i+1),'uppercase' if i==0 else 'copy',digest(expected),**extra)
    return expected


def gate_fixture(rt,claim,proof,content):
    engine=GateEngine(rt);verifiers=engine.register_synthetic_verifiers()
    contract=engine.define_contract(claim['task']['id'],claim['run_id'],proof['evidence'],ENV,verifiers)
    context=engine.contract_context(contract)
    observations={
      'tests':{'cases':[True,True]},'licenses':{'licenses':['MIT'],'allowed':['MIT']},
      'secrets':{'artifact_content':content,'forbidden_markers':['NEVER_MATCH_PRIVATE_FIXTURE']},
      'provenance':{'source':{'id':context['source_id'],'version':context['source_version'],'sha':context['source_sha'],'origin':'owner_fixture'}},
      'consent':{'approved':True,'contract_id':contract,'scope':'local_validation_only','expires_at':2000.0},
      'environment':{'environment':ENV}}
    return engine,contract,{k:{'executed':True,'artifact_sha':digest(content),**v} for k,v in observations.items()}


def run_case(family,variant):
    started=time.perf_counter();label=f'V7-{family}-{variant:02d}'
    content='alpha '+str(variant)+' épreuve '+('x'*variant)
    row={'id':label,'family':family,'variant':variant,'scope':'LOCAL_SYNTHETIC_CONTROL_NO_MODEL',
         'fixture_input_sha256':digest(content),'status':'FAIL'}
    try:
      with tempfile.TemporaryDirectory(prefix='cup-simulation-v7-') as temp, Runtime(Path(temp)/'owner.sqlite',clock=lambda:1000.0) as rt:
        expected=chain(rt,content,3 if family=='flow_three' else 2 if family in ('flow_two','pinned_drift','producer_fail','upstream_equal_bytes_drift','revoked_parent_after_claim') else 1,dynamic=family!='pinned_drift')
        claim=rt.claim('owner-fixture',environment=ENV)
        if family in ('flow_two','flow_three'):
            stages=3 if family=='flow_three' else 2
            for i in range(stages):
                if i:claim=rt.claim('owner-fixture',environment=ENV)
                assert claim is not None and claim['task']['id']=='T'+str(i)
                source,receipt,proof=finish(rt,claim,expected)
                if i:assert source['content']==expected and source['version']==2
                assert proof['outcome']=='PASS' and rt.proof_is_accepted_for_gate(proof['evidence'],ENV)
            assert rt.resource('r'+str(stages))['content']==expected
            row['observed']='VERIFIED_CHAIN';row['expected']='VERIFIED_CHAIN'
        elif family in ('pinned_drift','producer_fail','upstream_equal_bytes_drift'):
            source,receipt,proof=finish(rt,claim,'incorrect' if family=='producer_fail' else expected)
            if family=='upstream_equal_bytes_drift':rt.put_resource('r1',expected,2)
            assert rt.claim('consumer',environment=ENV) is None
            assert rt.resource('r2')['version']==1
            if family=='producer_fail':assert proof['outcome']=='FAIL'
            row['observed']=row['expected']='BLOCK_CONSUMER_NO_EFFECT'
        elif family=='revoked_parent_after_claim':
            _,_,parent=finish(rt,claim,expected);child=rt.claim('consumer',environment=ENV)
            rt.revoke_evidence(parent['evidence'],'owner_withdrawal')
            refused(lambda:rt.execute(Intent(child['run_id'],'artifact.write','r2',1,child['run_id']+'.write',child['fence'],{'content':expected}),child['token']))
            assert rt.resource('r2')['version']==1
            row['observed']=row['expected']='DENY_STALE_LINEAGE'
        elif family in ('rotation_old_token','rotation_replay','revoked_tokens'):
            intent=Intent(claim['run_id'],'artifact.write','r1',1,'one-local-effect',claim['fence'],{'content':expected})
            if family=='rotation_replay':rt.execute(intent,claim['token'])
            rotated=rotate_run_token(rt,claim['run_id'],claim['token'],expected_fence=claim['fence'])
            refused(lambda:rt.execute(intent,claim['token']))
            if family=='revoked_tokens':
                rt.revoke(claim['run_id']);refused(lambda:rt.execute(intent,rotated.token));assert rt.resource('r1')['version']==1
            else:
                result=rt.execute(intent,rotated.token);assert result['replayed']==(family=='rotation_replay')
                assert rt.resource('r1')['version']==2 and rt.db.execute('SELECT count(*) FROM effects').fetchone()[0]==1
            row['observed']=row['expected']='DENY_OLD_RIGHTS_NO_DUPLICATE'
        elif family.startswith('fake_'):
            box=Outbox(rt);intent=Intent(claim['run_id'],'artifact.write','r1',1,'fake-business-effect',claim['fence'],{'content':expected})
            prepared=box.prepare(intent,claim['token'],budget=2)
            with FakeAdapter(Path(temp)/'fake.sqlite') as adapter:
                if family in ('fake_ack_loss','fake_before_effect'):
                    point='after_effect_before_ack' if family=='fake_ack_loss' else 'after_attempt_before_effect'
                    def fail(where):
                        if where==point:raise RuntimeError('controlled_interruption')
                    try:box.dispatch(prepared['key'],claim['token'],prepared['revision'],adapter,crash_hook=fail)
                    except RuntimeError:pass
                    else:raise AssertionError('failure hook missing')
                    uncertain=box.status(prepared['key'])
                    if uncertain['state']=='INFLIGHT':uncertain=box.recover_uncertain(uncertain['key'],uncertain['revision'])
                    assert uncertain['state']=='UNKNOWN'
                    with FakeAdapter(Path(temp)/'wrong-fake.sqlite') as wrong:
                        refused(lambda:box.reconcile(uncertain['key'],uncertain['revision'],wrong))
                        assert box.status(uncertain['key'])==uncertain and wrong.statistics()['calls']=={}
                    row['wrong_store_reconciliation']='DENIED_NO_CALL_NO_STATE_CHANGE'
                    resolved=box.reconcile(uncertain['key'],uncertain['revision'],adapter)
                    if resolved['state']=='PREPARED':resolved=box.dispatch(resolved['key'],claim['token'],resolved['revision'],adapter)
                    assert resolved['state']=='COMMITTED'
                else:
                    resolved=box.dispatch(prepared['key'],claim['token'],prepared['revision'],adapter)
                    with FakeAdapter(Path(temp)/'wrong-fake.sqlite') as wrong:
                        refused(lambda:box.compensate(resolved['key'],'fake-compensation',claim['token'],resolved['revision'],wrong))
                        assert wrong.statistics()['calls']=={}
                    row['wrong_store_compensation']='DENIED_NO_CALL'
                    for _ in range(2):box.compensate(resolved['key'],'fake-compensation',claim['token'],resolved['revision'],adapter)
                    assert adapter.statistics()['compensations']==1
                assert adapter.statistics()['semantic_effects']==1
                assert rt.resource('r1')['version']==1 and not rt.db.execute('SELECT 1 FROM evidence').fetchone()
                row['fake_statistics']=adapter.statistics()
            row['observed']=row['expected']='RECONCILED_ONE_FAKE_EFFECT'
        else:
            _,_,proof=finish(rt,claim,expected)
            engine,contract,observations=gate_fixture(rt,claim,proof,expected)
            for criterion,observation in observations.items():engine.run_check(contract,criterion,observation)
            assert engine.evaluate(contract,ENV)['accepted'] is True
            if family=='gate_unknown':
                criterion=sorted(CRITERIA)[variant%len(CRITERIA)]
                engine.run_check(contract,criterion,{**observations[criterion],'executed':False,'outcome':'PASS'})
            elif family=='gate_fail':engine.run_check(contract,'tests',{**observations['tests'],'cases':[True,False]})
            elif family=='gate_stale':
                if variant%3==0:rt.put_resource('r1',expected,2)
                elif variant%3==1:rt.revoke_evidence(proof['evidence'],'withdrawn')
                else:engine.rotate_signing_key()
            verdict=engine.evaluate(contract,ENV)
            assert verdict['accepted']==(family=='gate_all_pass')
            row['observed']=row['expected']='PASS_ALL_REQUIRED' if family=='gate_all_pass' else 'BLOCK_REQUIRED_CRITERION'
            row['gate_decision']=verdict['decision']
        assert rt.check_journal()
        row['state']={'effects':rt.db.execute('SELECT count(*) FROM effects').fetchone()[0],
                      'proofs':rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0],
                      'bindings':rt.db.execute('SELECT count(*) FROM run_input_bindings').fetchone()[0],
                      'journal_valid':True}
        row['status']='PASS'
    except Exception as error:
        row['failure']={'type':type(error).__name__,'message':str(error)}
    row['duration_seconds']=time.perf_counter()-started
    return row


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    files={str(p.relative_to(ROOT)):sha(p) for p in sorted((ROOT/'universal').glob('*.py'))}
    started=time.perf_counter();rows=[run_case(family,variant) for family in FAMILIES for variant in range(25)]
    after={str(p.relative_to(ROOT)):sha(p) for p in sorted((ROOT/'universal').glob('*.py'))}
    assert files==after
    matrix=args.out/'SIMULATIONS_V7_400.jsonl'
    matrix.write_text(''.join(json.dumps(row,ensure_ascii=False,sort_keys=True)+'\n' for row in rows))
    summary={'created_utc':datetime.now(timezone.utc).isoformat(),'rows':len(rows),'families':16,'variants_per_family':25,
             'status_counts':dict(Counter(row['status'] for row in rows)),'source_files':files,'sources_stable':files==after,
             'harness_sha256':sha(Path(__file__)),'matrix_sha256':sha(matrix),'elapsed_seconds':time.perf_counter()-started,
             'scope':'400 distinct local fixtures, 16 families. Owner APIs, two fake SQLite stores, no LLM/self-inference, real API, domain validation, or superiority benchmark. Production IPC/OS separately exercised in unit integration tests.',
             'external_calls':0,'model_inference_calls':0,'paid_ai_calls':0}
    (args.out/'SIMULATIONS_V7_SUMMARY.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:summary[k] for k in ('rows','families','status_counts','elapsed_seconds','sources_stable','paid_ai_calls')},ensure_ascii=False))
    return 0 if summary['status_counts']=={'PASS':400} else 1


if __name__=='__main__':raise SystemExit(main())
