#!/usr/bin/env python3
"""Forty real bounded candidate workflows. No model inference or paid API.

Eight behavioral families with five varying Python implementations/contracts.
These supplement the separate seeded continuity campaign, not its test count.
"""
import argparse
from collections import Counter
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from universal.core import Runtime,Intent,GuardError,canonical
from universal.broker import environment_identity
from universal.generative import GenerativeValidator,MODE

FAMILIES=('unknown_code_pass','incorrect_result','source_drift','policy_withdrawn',
          'upstream_withdrawn','license_unknown','timeout_blocks','same_bytes_new_version')


def finish(rt,claim,content):
    return rt.execute(Intent(claim['run_id'],'artifact.write',claim['task']['output'],claim['output_version'],claim['run_id']+'.write',claim['fence'],{'content':content}),claim['token'])


def run_case(family,variant):
    started=time.perf_counter();row={'id':f'GEN-V8-{family}-{variant:02d}','family':family,'variant':variant,'status':'FAIL','scope':'REAL_CONFINED_PYTHON_FIXTURE_NO_MODEL'}
    a,b=variant+2,variant+3
    policy={'version':1,'entrypoint':'candidate.py','function':'solve','tests':[{'args':[x],'expected':a*x+b} for x in [-1,0,4]],'allowed_licenses':['MIT'],'forbidden_markers':['FORBIDDEN_OWNER_FIXTURE'],'max_seconds':3.0}
    code=f'def solve(x):\n    return {a} * x + {b}\n'
    if family=='incorrect_result':code=f'def solve(x):\n    return {a+1} * x + {b}\n'
    if family=='timeout_blocks':
        code='def solve(x):\n    while True:\n        pass\n';policy['max_seconds']=0.08
    files={'candidate.py':code,'LICENSE':'SPDX-License-Identifier: MIT\n'}
    if family=='license_unknown':files.pop('LICENSE')
    content=canonical({'files':files});row['candidate_sha256']=hashlib.sha256(content.encode()).hexdigest()
    try:
      with tempfile.TemporaryDirectory(prefix='cup-gen-v8-') as temp,Runtime(Path(temp)/'owner.sqlite',clock=lambda:1000.0) as rt:
        validator=GenerativeValidator(rt);validator.register_policy('P',policy)
        rt.put_resource('mission','Implement the declared affine behavior');rt.put_resource('out','')
        rt.source_snapshot('mission-owner','mission','owner_contract')
        rt.add_task('A','mission','out','candidate',None,validation_mode=MODE,policy_id='P')
        if family=='upstream_withdrawn':
            rt.put_resource('next','');rt.add_task('B','out','next','candidate',None,['A'],validation_mode=MODE,policy_id='P',input_mode='VERIFIED_UPSTREAM_POLICY_OUTPUT',producer='A',source_policy_id='P')
        env=environment_identity();claim=rt.claim('fixture',ttl=60,environment=env)
        finish(rt,claim,content)
        if family=='source_drift':rt.put_resource('mission','changed',1)
        if family=='policy_withdrawn':validator.revoke_policy('P')
        try:
            proof=validator.verify('A',env,expected_run_id=claim['run_id'])
        except GuardError as error:
            assert family in {'source_drift','policy_withdrawn','timeout_blocks'},error.reason
            row['decision']=error.decision;row['reason']=error.reason;proof=None
        if family in {'source_drift','policy_withdrawn'}:
            assert proof is None and rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0]==0
            row['expected']=row['observed']='REFUSE_STALE_OR_REVOKED_NO_PROOF'
        elif family in {'incorrect_result','license_unknown','timeout_blocks'}:
            if proof:assert proof['outcome']!='PASS' and not proof['accepted_for_gate']
            row['expected']=row['observed']='NO_ACCEPTANCE'
        else:
            assert proof and proof['accepted_for_gate'] and proof['outcome']=='PASS'
            if family=='upstream_withdrawn':
                child=rt.claim('consumer',ttl=60,environment=env);assert child
                rt.revoke_evidence(proof['evidence'],'owner_withdrawal')
                try:finish(rt,child,content)
                except GuardError:pass
                else:raise AssertionError('withdrawn producer accepted')
                assert rt.resource('next')['version']==1
                row['expected']=row['observed']='REFUSE_WITHDRAWN_PRODUCER'
            elif family=='same_bytes_new_version':
                rt.put_resource('out',content,2)
                assert not rt.proof_is_accepted_for_gate(proof['evidence'],env)
                row['expected']=row['observed']='BLOCK_NEW_VERSION_SAME_BYTES'
            else:
                repeat=validator.verify('A',env,expected_run_id=claim['run_id'])
                assert repeat['replayed'] and repeat['evidence']==proof['evidence']
                row['expected']=row['observed']='ACCEPT_UNKNOWN_CODE_ONE_PROOF'
            row['tree_sha']=proof['tree_sha']
        assert rt.check_journal()
        row['state']={'task':rt.task('A')['status'],'effects':rt.db.execute('SELECT count(*) FROM effects').fetchone()[0],'proofs':rt.db.execute('SELECT count(*) FROM evidence').fetchone()[0],'journal_valid':True}
        row['status']='PASS'
    except Exception as error:row['error']={'type':type(error).__name__,'message':str(error)}
    row['elapsed_seconds']=time.perf_counter()-started
    return row


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    args.out.mkdir(parents=True,exist_ok=True)
    files={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'universal').glob('*.py'))}
    rows=[run_case(family,variant) for family in FAMILIES for variant in range(5)]
    after={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'universal').glob('*.py'))}
    matrix=args.out/'cases.jsonl'
    with matrix.open('x') as stream:stream.write(''.join(json.dumps(row,ensure_ascii=False,sort_keys=True)+'\n' for row in rows))
    summary={'created_utc':datetime.now(timezone.utc).isoformat(),'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'rows':40,'families':8,'status_counts':dict(Counter(row['status'] for row in rows)),'source_sha256':files,'sources_stable':files==after,'matrix_sha256':hashlib.sha256(matrix.read_bytes()).hexdigest(),'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope':'Forty bounded Python candidate workflows using real sandbox cases. No model inference, general repository/domain validation or Codex benchmark.'}
    with (args.out/'summary.json').open('x') as stream:json.dump(summary,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print(json.dumps({k:summary[k] for k in ['commit','rows','status_counts','sources_stable']},ensure_ascii=False))
    return 0 if summary['status_counts']=={'PASS':40} and summary['sources_stable'] else 1


if __name__=='__main__':raise SystemExit(main())
