"""Negative probes for a gate that must never turn missing work green."""
from io import StringIO
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools.run_ci_checks import RecordedResult, checks_passed, source_identity


def probe(behavior, expected_failure=False):
    class SyntheticCase(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            if behavior == "class_error":
                raise ValueError("synthetic class setup error")

        def runTest(self):
            if behavior == "skip":
                self.skipTest("synthetic unavailable host")
            elif behavior == "fail":
                self.fail("synthetic wrong output")
            elif behavior == "error":
                raise ValueError("synthetic error")
            elif behavior == "subtest":
                with self.subTest(case=1):
                    self.assertEqual(1, 2)
            elif behavior == "subtest_skip":
                with self.subTest(case=1):
                    self.skipTest("synthetic skipped case")
    if expected_failure:
        SyntheticCase.runTest = unittest.expectedFailure(SyntheticCase.runTest)
    case = SyntheticCase()
    result = unittest.TextTestRunner(stream=StringIO(), resultclass=RecordedResult).run(unittest.TestSuite([case]))
    return result, [case.id()]


class TestCIChecks(unittest.TestCase):
    def test_completed_positive_campaign_is_accepted(self):
        result, identities = probe("pass")
        self.assertTrue(checks_passed(result, identities, True))

    def test_unittest_success_with_skip_is_not_a_passing_gate(self):
        result, identities = probe("skip")
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(result.records[0]["status"], "NOT_RUN")
        self.assertFalse(checks_passed(result, identities, True))

    def test_errors_failures_and_failed_subtests_are_not_green(self):
        for behavior in ("fail", "error", "subtest"):
            with self.subTest(behavior=behavior):
                result, identities = probe(behavior)
                self.assertFalse(checks_passed(result, identities, True))
                self.assertIn(result.records[0]["status"], {"FAIL", "ERROR"})

    def test_skipped_subtest_does_not_become_pass(self):
        result, identities = probe("subtest_skip")
        self.assertEqual(result.records[0]["status"], "NOT_RUN")
        self.assertFalse(checks_passed(result, identities, True))

    def test_class_setup_failure_is_recorded_and_refused(self):
        result, identities = probe("class_error")
        self.assertEqual(result.testsRun, 0)
        self.assertEqual(result.records[0]["status"], "ERROR")
        self.assertFalse(checks_passed(result, identities, True))

    def test_expected_failure_and_unexpected_success_are_not_green(self):
        for behavior in ("fail", "pass"):
            with self.subTest(behavior=behavior):
                result, identities = probe(behavior, expected_failure=True)
                self.assertFalse(checks_passed(result, identities, True))

    def test_empty_incomplete_or_drifting_campaign_is_refused(self):
        result, identities = probe("pass")
        for expected, stable in (([], True), (identities + ["missing"], True), (identities, False)):
            with self.subTest(expected=expected, stable=stable):
                self.assertFalse(checks_passed(result, expected, stable))

    def test_real_git_content_drift_and_dirty_index_are_observable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            source = root / "candidate.py"
            source.write_text("value = 1\n")
            subprocess.run(["git", "-C", str(root), "add", "--all"], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture",
                            "-c", "user.email=noreply@localhost", "commit", "--quiet", "-m", "fixture"], check=True)
            before = source_identity(root)
            self.assertTrue(before["clean"])
            source.write_text("value = 2\n")
            after = source_identity(root)
            self.assertFalse(after["clean"])
            self.assertNotEqual(before["file_sha256"], after["file_sha256"])
            subprocess.run(["git", "-C", str(root), "add", "--all"], check=True)
            self.assertFalse(source_identity(root)["clean"])
