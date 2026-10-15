"""Owner-only contract checks and separately selected real isolation checks."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from universal.broker import environment_identity
from universal.core import GuardError, Intent, Runtime, digest
from universal.isolation import IsolationUnavailable
from universal.mission_executor import DeterministicExecutor


class ExecutorFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="coguni-mvp-executor-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "owner.sqlite"
        self.executor = DeterministicExecutor(self.path)

    def counts(self):
        with Runtime(self.path) as runtime:
            return {table: runtime.db.execute("SELECT count(*) FROM " + table).fetchone()[0]
                    for table in ("resources", "tasks", "runs", "effects", "evidence", "events")}

    def committed(self, task_id, content=None):
        with Runtime(self.path) as runtime:
            claim = runtime.claim("fixture-worker", task_id=task_id, ttl=60)
            source = runtime.resource(claim["task"]["input"])["content"]
            if content is None:
                content = source.upper() if claim["task"]["action"] == "uppercase" else digest(source)
            runtime.execute(Intent(claim["run_id"], "artifact.write", claim["task"]["output"],
                                   claim["output_version"], claim["run_id"] + ".write",
                                   claim["fence"], {"content": content}), claim["token"])
            return claim["run_id"]


class MissionExecutorOwnerTests(ExecutorFixture, unittest.TestCase):
    def test_identity_and_missing_status_do_not_create_a_store(self):
        task = self.executor.task_id("mission", "alpha")
        self.assertFalse(self.path.exists())
        with self.assertRaises(GuardError):
            self.executor.result(task)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.executor.prepare("mission", "alpha"), task)

    def test_prepare_replay_is_atomic_immutable_and_has_no_parallel_store(self):
        task = self.executor.prepare("mission-1", "synthetic:alpha")
        before = self.counts()
        self.assertEqual(self.executor.prepare("mission-1", "synthetic:alpha"), task)
        self.assertEqual(self.counts(), before)
        self.assertEqual((before["resources"], before["tasks"], before["runs"]), (2, 1, 0))
        self.assertNotEqual(task, self.executor.prepare("mission-1", "synthetic:alpha", "sha256"))
        self.assertEqual({file.name for file in self.path.parent.iterdir()}, {"owner.sqlite"})
        with Runtime(self.path) as runtime:
            self.assertEqual(runtime.db.execute("PRAGMA user_version").fetchone()[0], 4)
            self.assertTrue(runtime.check_journal())

    def test_invalid_payload_action_identity_and_budget_refused_before_run(self):
        for payload in ("", "synthetic:", "synthetic:a b", "synthetic:a\n", "synthetic:../x",
                        "x" * 257, "é", "pass;exec", [], True):
            with self.subTest(payload=payload), self.assertRaises(GuardError):
                self.executor.prepare("mission", payload)
        for action in ("copy", "shell", "candidate", True):
            with self.subTest(action=action), self.assertRaises(GuardError):
                self.executor.prepare("mission", "alpha", action)
        with self.assertRaises(GuardError):
            self.executor.prepare("../foreign", "alpha")
        task = self.executor.prepare("mission", "alpha")
        for timeout in (True, 0, -1, 61, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(GuardError):
                self.executor.run(task, timeout)
        self.assertEqual(self.counts()["runs"], 0)

    def test_interrupted_provision_rolls_back_both_resources_and_contract(self):
        with patch.object(Runtime, "_insert_task", side_effect=RuntimeError("injected crash")):
            with self.assertRaises(RuntimeError):
                self.executor.prepare("mission", "alpha")
        counts = self.counts()
        self.assertEqual((counts["resources"], counts["tasks"]), (0, 0))
        self.executor.prepare("mission", "alpha")
        self.assertEqual(self.counts()["tasks"], 1)

    def test_concurrent_identical_prepare_provisions_once(self):
        with Runtime(self.path):
            pass  # Initialize the owner's schema before concurrent use.
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.executor.prepare("mission", "synthetic:alpha"), range(8)))
        self.assertEqual(len(set(results)), 1)
        self.assertEqual((self.counts()["resources"], self.counts()["tasks"]), (2, 1))

    def test_worker_pass_text_does_not_create_a_proof_or_complete_task(self):
        task = self.executor.prepare("mission", "alpha")
        with patch("universal.mission_executor.run_pool", return_value=[{"PASS": True}]) as run:
            got = self.executor.run(task, timeout=7)
        run.assert_called_once_with(self.path, workers=1, max_jobs=1, timeout=7,
                                    worker_names=["mvp-worker"], task_id=task)
        self.assertEqual(got["status"], "READY")
        self.assertFalse(got["accepted_for_gate"])
        self.assertIsNone(got["evidence_id"])

    def test_running_job_is_observed_without_new_launch_even_when_silent(self):
        task = self.executor.prepare("mission", "alpha")
        with Runtime(self.path) as runtime:
            claim = runtime.claim("still-active", ttl=60, task_id=task)
        with patch("universal.mission_executor.run_pool") as run:
            result = self.executor.run(task)
        run.assert_not_called()
        self.assertEqual((result["status"], result["run_id"]), ("RUNNING", claim["run_id"]))
        self.assertEqual(self.counts()["runs"], 1)
        self.assertFalse(result["accepted_for_gate"])

    def test_result_requires_current_environment_and_nonrevoked_owner_evidence(self):
        task = self.executor.prepare("mission", "alpha")
        run_id = self.committed(task)
        with Runtime(self.path) as runtime:
            evidence = runtime.verify(task, environment_identity(), expected_run_id=run_id)["evidence"]
        good = self.executor.result(task)
        self.assertEqual(good["status"], "COMPLETED")
        self.assertTrue(good["accepted_for_gate"])
        self.assertEqual(good["output_sha256"], digest("ALPHA"))
        self.assertNotIn("token", good)
        with patch("universal.mission_executor.environment_identity", return_value="foreign-environment"):
            self.assertFalse(self.executor.result(task)["accepted_for_gate"])
        with Runtime(self.path) as runtime:
            runtime.revoke_evidence(evidence, "owner-revoked")
        with patch("universal.mission_executor.run_pool") as run:
            got = self.executor.run(task)
        run.assert_not_called()
        self.assertEqual(got["status"], "BLOCKED")
        self.assertFalse(got["accepted_for_gate"])

    def test_wrong_output_and_foreign_or_changed_contract_cannot_complete(self):
        task = self.executor.prepare("mission", "alpha")
        run_id = self.committed(task, "worker says PASS")
        with Runtime(self.path) as runtime:
            runtime.verify(task, environment_identity(), expected_run_id=run_id)
        self.assertFalse(self.executor.result(task)["accepted_for_gate"])
        self.assertEqual(self.executor.result(task)["status"], "BLOCKED")
        with self.assertRaises(GuardError):
            self.executor.result("foreign-task")
        with Runtime(self.path) as runtime:
            runtime.put_resource(task + "-input", "beta", expected_version=1)
        with self.assertRaises(GuardError):
            self.executor.result(task)
        with self.assertRaises(GuardError):
            self.executor.prepare("mission", "alpha")

    def test_missing_bubblewrap_refuses_launch_without_unconfined_fallback(self):
        task = self.executor.prepare("mission", "alpha")
        with patch("universal.isolation.shutil.which", return_value=None):
            with self.assertRaises(IsolationUnavailable):
                self.executor.run(task)
        self.assertEqual(self.counts()["runs"], 0)
        self.assertFalse(self.executor.result(task)["accepted_for_gate"])


class MissionExecutorIsolationTests(ExecutorFixture, unittest.TestCase):
    def test_real_confined_uppercase_and_sha256_exact_tasks_then_replay(self):
        first = self.executor.prepare("mission-1", "synthetic:alpha")
        second = self.executor.prepare("mission-2", "synthetic:beta", "sha256")
        first_result = self.executor.run(first)
        self.assertEqual(first_result["content"], "SYNTHETIC:ALPHA")
        self.assertTrue(first_result["accepted_for_gate"])
        self.assertEqual(self.executor.result(second)["status"], "READY")
        before = self.counts()
        self.assertEqual(self.executor.run(first), first_result)
        self.assertEqual(self.counts(), before)
        second_result = self.executor.run(second)
        self.assertEqual(second_result["content"], digest("synthetic:beta"))
        self.assertEqual(second_result["status"], "COMPLETED")
        self.assertEqual(self.counts()["effects"], 2)

    def test_lost_ack_recovers_only_selected_committed_result_without_rewrite(self):
        first = self.executor.prepare("mission-1", "alpha")
        second = self.executor.prepare("mission-2", "beta")
        self.committed(first)
        self.committed(second)
        before = self.counts()
        result = self.executor.run(first)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(self.executor.result(second)["status"], "RESULT_READY")
        after = self.counts()
        self.assertEqual(after["effects"], before["effects"])
        self.assertEqual(after["runs"], before["runs"])
        self.assertEqual(after["evidence"], before["evidence"] + 1)

    def test_concurrent_same_task_has_one_run_and_one_committed_effect(self):
        task = self.executor.prepare("mission", "synthetic:concurrent")
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: self.executor.run(task), range(3)))
        self.assertTrue(any(result["accepted_for_gate"] for result in results))
        self.assertEqual(self.executor.result(task)["status"], "COMPLETED")
        counts = self.counts()
        self.assertEqual((counts["runs"], counts["effects"], counts["evidence"]), (1, 1, 1))


if __name__ == "__main__":
    unittest.main()
