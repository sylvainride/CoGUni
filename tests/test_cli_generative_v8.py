"""Actual public CLI path admits unknown code only through owner policy checks."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.test_generative_v8 import policy,candidate


class GenerativeCliTests(unittest.TestCase):
    def test_new_code_without_anticipated_sha_is_submitted_and_verified_via_cli(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);db=root/'state.sqlite';p=root/'policy.json';artifact=root/'candidate.json'
            p.write_text(json.dumps(policy()));artifact.write_text(candidate())
            def call(*args):
                result=subprocess.run([sys.executable,'-B','-m','universal','--db',str(db),*args],capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr)
                return json.loads(result.stdout)
            self.assertEqual(call('init')['schema'],4)
            call('put','mission','--text','Implement solve(x)=2*x+3');call('put','artifact','--text','')
            call('source-snapshot','mission-owner','mission','--classification','owner_contract')
            call('policy','affine','--file',str(p))
            task=call('task','G','--source','mission','--output','artifact','--action','candidate','--validation-mode','GENERATIVE_POLICY_VALIDATED','--policy-id','affine')
            self.assertIsNone(task['expected_sha'])
            submission=call('candidate','G','--file',str(artifact))
            self.assertEqual(submission['verification'],'NOT_RUN')
            self.assertNotIn('token',submission)
            proof=call('verify-candidate','G','--run',submission['run_id'])
            self.assertTrue(proof['accepted_for_gate']);self.assertEqual(proof['outcome'],'PASS')
            replay=call('verify-candidate','G','--run',submission['run_id'])
            self.assertTrue(replay['replayed']);self.assertEqual(replay['evidence'],proof['evidence'])
            status=call('status');self.assertEqual(status['tasks'][0]['status'],'VERIFIED')
    def test_default_cli_missing_sha_remains_refused_without_any_task(self):
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'state.sqlite'
            prefix=[sys.executable,'-B','-m','universal','--db',str(db)]
            for args in [('put','source','--text','alpha'),('put','output','--text','')]:
                result=subprocess.run(prefix+list(args),capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run(prefix+['task','bad','--source','source','--output','output','--action','copy'],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2)
            self.assertIn('invalid task contract',result.stderr)


if __name__=='__main__':unittest.main()
