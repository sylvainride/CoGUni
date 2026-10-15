"""P31 synthetic correlation is never independent acceptance or signing."""
from dataclasses import replace
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from tests.test_mission_contracts import mission, receipt
from universal.mission_confined_worker import ConfinedInspection, CRITERIA
from universal.mission_contracts import canonical, MissionContractError
from universal.mission_result_review import correlate_synthetic_result


class ResultReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='result-review-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.file = self.root/'artifact.bin'
        self.file.write_bytes(b'candidate output fixture\n')
        self.mission = mission('fixture-A')
        self.receipt = receipt()
        self.receipt['artifact_sha256'] = hashlib.sha256(self.file.read_bytes()).hexdigest()
        self.tree = 'b'*40
        self.observation = ConfinedInspection('fixture-A', 'run-1',
                             self.mission['source_sha256'], self.tree,
                             {c:'PASS' for c in CRITERIA}, 'CHECKS_OBSERVED_ONLY')

    def check(self, obs=None, m=None, r=None, **changes):
        args=dict(now_unix=150, owner_run_id='run-1', owner_project_version='v1',
                  owner_candidate_tree_sha=self.tree, root=str(self.root), path=str(self.file))
        args.update(changes)
        return correlate_synthetic_result(self.observation if obs is None else obs,
                          canonical(self.mission if m is None else m),
                          canonical(self.receipt if r is None else r), **args)

    def test_matching_observations_yield_review_required_never_pass(self):
        got=self.check()
        self.assertEqual(got.artifact_sha256, self.receipt['artifact_sha256'])
        self.assertEqual(got.candidate_tree_sha, self.tree)
        self.assertEqual(got.state, 'OWNER_REVIEW_REQUIRED')
        self.assertFalse(got.accepted)
        self.assertFalse(got.evidence_signed)
        self.assertFalse(got.application_authorized)

    def test_spoofed_pass_accepted_flag_and_worker_authority_denied(self):
        for changed in (replace(self.observation, accepted_for_gate=True),
                        replace(self.observation, execution_authorized=True),
                        replace(self.observation, observation_state='PASS'),
                        replace(self.observation, criteria={'tests':'PASS'}),
                        replace(self.observation, criteria={c:'NOT_RUN' if c=='environment' else 'PASS' for c in CRITERIA})):
            with self.subTest(changed=changed), self.assertRaises(MissionContractError):
                self.check(obs=changed)

    def test_foreign_run_project_source_version_and_tree_denied(self):
        for args in ({'owner_run_id':'run-B'}, {'owner_project_version':'v2'},
                     {'owner_candidate_tree_sha':'c'*40}, {'owner_candidate_tree_sha':'INVALID'}):
            with self.subTest(args=args), self.assertRaises(MissionContractError):
                self.check(**args)
        for changed in (replace(self.observation, project_id='fixture-B'),
                        replace(self.observation, run_id='run-B'),
                        replace(self.observation, source_sha256='c'*64),
                        replace(self.observation, candidate_tree_sha='d'*40)):
            with self.subTest(changed=changed), self.assertRaises(MissionContractError):
                self.check(obs=changed)

    def test_receipt_unknown_effect_claimed_pass_and_wrong_digest_denied(self):
        for patch in ({'result_state':'UNKNOWN_EFFECT'}, {'acceptance_status':'PASS_SCOPED'},
                      {'artifact_sha256':'a'*64}, {'run_id':'run-B'}):
            changed=copy.deepcopy(self.receipt); changed.update(patch)
            with self.subTest(patch=patch), self.assertRaises(MissionContractError):
                self.check(r=changed)

    def test_symlink_replace_or_changed_bytes_refused(self):
        self.file.write_bytes(b'changed')
        with self.assertRaises(MissionContractError):
            self.check()
        self.file.unlink()
        target=self.root/'target.bin';target.write_bytes(b'candidate output fixture\n')
        self.file.symlink_to(target)
        with self.assertRaises(MissionContractError):
            self.check()

    def test_private_and_mismatched_mission_denied(self):
        private=copy.deepcopy(self.mission)
        private['privacy']='PRIVATE_OWNER'
        private['contract']['artifact_policy']='private_owner'
        with self.assertRaises(MissionContractError):
            self.check(m=private)
        crossed=copy.deepcopy(self.mission); crossed['project']['id']='fixture-B'
        with self.assertRaises(MissionContractError):
            self.check(m=crossed)


if __name__=='__main__':
    unittest.main()
