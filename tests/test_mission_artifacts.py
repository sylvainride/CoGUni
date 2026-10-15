"""P15 artifact integrity proof is strictly weaker than acceptance/effect proof."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from tests.test_mission_contracts import mission, receipt
from universal.mission_contracts import canonical, MissionContractError
from universal.mission_artifacts import inspect_synthetic_artifact


class MissionArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='artifact-owner-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.file = self.root/'fixture-A.txt'
        self.data = b'deterministic artifact\n'
        self.file.write_bytes(self.data)
        self.m = mission('fixture-A')
        self.r = receipt()
        self.r['artifact_sha256'] = hashlib.sha256(self.data).hexdigest()

    def check(self, m=None, r=None, *, root=None, path=None, max_bytes=1024,
              expected_run_id='run-1', expected_project_version='v1'):
        return inspect_synthetic_artifact(canonical(self.m if m is None else m),
                                           canonical(self.r if r is None else r),
                                           now_unix=150, root=str(self.root if root is None else root),
                                           path=str(self.file if path is None else path), max_bytes=max_bytes,
                                           expected_run_id=expected_run_id,
                                           expected_project_version=expected_project_version)

    def test_matching_bytes_are_integrity_only_never_owner_pass(self):
        result = self.check()
        self.assertEqual(result.artifact_sha256, self.r['artifact_sha256'])
        self.assertEqual(result.size, len(self.data))
        self.assertFalse(result.accepted)
        self.assertFalse(result.application_authorized)

    def test_owner_run_and_project_version_must_bind_exactly(self):
        with self.assertRaises(MissionContractError):
            self.check(expected_run_id='run-B')
        with self.assertRaises(MissionContractError):
            self.check(expected_project_version='other-version')
        forged = copy.deepcopy(self.r)
        forged['run_id'] = 'run-B'
        with self.assertRaises(MissionContractError):
            self.check(r=forged)

    def test_refuse_project_source_and_claimed_pass(self):
        for field, value in (('project_id', 'fixture-B'), ('source_sha256', 'b'*64),
                             ('application_status', 'APPLIED'), ('acceptance_status', 'PASS_SCOPED'),
                             ('result_state', 'UNKNOWN_EFFECT')):
            with self.subTest(field=field):
                v = copy.deepcopy(self.r); v[field] = value
                with self.assertRaises(MissionContractError):
                    self.check(r=v)
        private = copy.deepcopy(self.m); private['privacy'] = 'PRIVATE_OWNER'; private['contract']['artifact_policy'] = 'private_owner'
        with self.assertRaises(MissionContractError):
            self.check(m=private)

    def test_tampered_bytes_and_tampered_manifest_denied(self):
        self.file.write_bytes(b'not the fixture')
        with self.assertRaises(MissionContractError):
            self.check()
        self.file.write_bytes(self.data)
        tampered = copy.deepcopy(self.r); tampered['artifact_sha256'] = 'a'*64
        with self.assertRaises(MissionContractError):
            self.check(r=tampered)

    def test_outside_symlink_and_directory_are_denied(self):
        outside = self.root.parent/'unrelated-do-not-read'
        with self.assertRaises(MissionContractError):
            self.check(path=outside)
        self.file.unlink()
        linked = self.root/'data.txt'; linked.write_bytes(self.data)
        self.file.symlink_to(linked)
        with self.assertRaises(MissionContractError):
            self.check()
        self.file.unlink()
        self.file.mkdir()
        with self.assertRaises(MissionContractError):
            self.check()

    def test_parent_symlink_and_size_limit_denied(self):
        safe = self.root/'safe'; safe.mkdir(); artifact = safe/'a.txt'; artifact.write_bytes(self.data)
        link = self.root/'redirect'; link.symlink_to(safe, target_is_directory=True)
        with self.assertRaises(MissionContractError):
            self.check(path=link/'a.txt')
        with self.assertRaises(MissionContractError):
            self.check(path=artifact, max_bytes=3)

    def test_refuse_zero_and_truthy_budgets_and_cross_root(self):
        for max_bytes in (0, True, -1, 1048577):
            with self.subTest(max_bytes=max_bytes), self.assertRaises(MissionContractError):
                self.check(max_bytes=max_bytes)
        other = self.root/'other'; other.mkdir()
        with self.assertRaises(MissionContractError):
            self.check(root=other)


if __name__ == '__main__':
    unittest.main()
