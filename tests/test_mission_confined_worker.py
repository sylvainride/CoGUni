"""P30 existing bwrap project runner is required; no owner-side worker fallback."""
import copy
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tests.test_mission_contracts import mission
from tests.test_python_project import files as project_files, policy as project_policy
from universal.continuity import ContinuityJournal
from universal.core import GuardError
from universal.mission_admission import admit_synthetic
from universal.mission_confined_worker import inspect_synthetic_candidate
from universal.mission_contracts import canonical
from universal.policy_runner import git_tree_sha


class ConfinedMissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mission-worker-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = [150]
        self.journal = ContinuityJournal(self.root/'owner.sqlite', clock=lambda: self.clock[0])
        self.addCleanup(self.journal.close)
        self.src = self.root/'owner.txt'; self.src.write_bytes(b'trusted-fixture-source')
        self.envelope = mission('fixture-A')
        self.envelope['source_sha256'] = hashlib.sha256(self.src.read_bytes()).hexdigest()
        self.task = admit_synthetic(self.journal, canonical(self.envelope), now_unix=150,
                          source_path=str(self.src), output_path=str(self.root/'output.txt'))

    def run_check(self, **kwargs):
        claim = self.task
        args = dict(now_unix=150, expected_owner='owner',
                    expected_revision=claim['revision'], expected_fence=claim['fence'])
        args.update(kwargs)
        return inspect_synthetic_candidate(self.journal, claim['id'], canonical(self.envelope),
                                           project_files(), project_policy(), **args)

    def claim(self):
        self.task = self.journal.claim(self.task['id'], 'owner', 'offline_fixture',
                            expected_revision=self.task['revision'], key='claim', ttl=60)

    def test_unclaimed_or_cross_owner_cannot_dispatch(self):
        with self.assertRaises(GuardError):
            self.run_check()
        self.claim()
        with self.assertRaises(GuardError):
            self.run_check(expected_owner='other')
        with self.assertRaises(GuardError):
            self.run_check(expected_revision=self.task['revision']-1)
        with self.assertRaises(GuardError):
            self.run_check(expected_fence=self.task['fence']-1)

    def test_expired_or_changed_source_prevents_candidate_launch(self):
        self.claim()
        self.src.write_bytes(b'changed')
        with self.assertRaises(GuardError):
            self.run_check()
        self.src.write_bytes(b'trusted-fixture-source')
        self.clock[0] = 211
        with self.assertRaises(GuardError):
            self.run_check()

    def test_private_and_external_missions_refused(self):
        self.claim()
        for update in ('privacy', 'kind', 'cost'):
            changed = copy.deepcopy(self.envelope)
            if update == 'privacy':
                changed['privacy']='PRIVATE_OWNER'; changed['contract']['artifact_policy']='private_owner'
            elif update == 'kind':
                changed['project']['kind']='github'
            else:
                changed['contract']['max_external_cost']=3
            with self.subTest(update=update), self.assertRaises(GuardError):
                inspect_synthetic_candidate(self.journal,self.task['id'],canonical(changed),
                              project_files(),project_policy(),now_unix=150,expected_owner='owner',
                              expected_revision=self.task['revision'],expected_fence=self.task['fence'])

    def test_isolation_unavailable_is_not_pass(self):
        self.claim()
        real_which = shutil.which
        with patch('universal.isolation.shutil.which',side_effect=lambda n,*a,**k: None if n=='bwrap' else real_which(n,*a,**k)):
            row = self.run_check()
        self.assertEqual(row.observation_state,'NOT_RUN')
        self.assertEqual(row.criteria['environment'],'NOT_RUN')
        self.assertFalse(row.accepted_for_gate)
        self.assertFalse(row.execution_authorized)

    def test_positive_requires_real_bwrap_and_independent_cases(self):
        self.claim()
        row = self.run_check()
        if not shutil.which('bwrap'):
            self.assertEqual(row.observation_state,'NOT_RUN')
            self.assertNotEqual(row.criteria['environment'],'PASS')
        else:
            self.assertEqual(row.observation_state,'CHECKS_OBSERVED_ONLY')
            self.assertTrue(all(value=='PASS' for value in row.criteria.values()))
            self.assertEqual(row.candidate_tree_sha,git_tree_sha(project_files()))
        self.assertFalse(row.accepted_for_gate)
        self.assertFalse(row.execution_authorized)
        self.assertEqual(self.journal.get(self.task['id'])['state'],'RUNNING')

    def test_fenced_while_checks_run_discards_observation(self):
        self.claim()
        from universal import mission_confined_worker as bridge
        def forged_check(*args,**kwargs):
            self.clock[0]=211
            self.journal.recover(self.task['id'],expected_revision=self.task['revision'],key='recover')
            return {'criteria':{name:{'outcome':'PASS'} for name in bridge.CRITERIA},'tree_sha':'a'*40}
        with patch.object(bridge,'run_project_checks',side_effect=forged_check):
            row = self.run_check()
        self.assertEqual(row.observation_state,'STALE_AFTER_CHECKS')
        self.assertIsNone(row.candidate_tree_sha)
        self.assertFalse(row.accepted_for_gate)


if __name__=='__main__':
    unittest.main()
