"""Independent tests of the actual SQLite artifact runtime, with no LLM or network.

The database belongs to each test. Direct SELECTs inspect transaction outcomes;
process-exit injection interrupts the actual runtime inside its final audit call.
"""
from contextlib import closing
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from universal.core import GuardError, Intent, Runtime, digest


def _claim_process(path, barrier, queue, worker):
    runtime = Runtime(path)
    try:
        barrier.wait(timeout=10)
        result = runtime.claim(worker)
        queue.put(("CLAIM", result["run_id"] if result else None))
    except BaseException as error:
        queue.put(("ERROR", repr(error)))
    finally:
        runtime.close()


def _cas_process(path, barrier, queue, content):
    runtime = Runtime(path)
    try:
        barrier.wait(timeout=10)
        queue.put(("COMMITTED", runtime.put_resource("source", content, 1)))
    except GuardError as error:
        queue.put(("BLOCK", error.reason))
    except BaseException as error:
        queue.put(("ERROR", repr(error)))
    finally:
        runtime.close()


def _crash_write(path, intent, token, after_commit):
    runtime = Runtime(path, clock=lambda: 1000.0)
    if not after_commit:
        original_event = runtime._event

        def crash_at_final_event(actor, action, target, outcome, metadata=None):
            if action == "artifact.write":
                os._exit(73)
            return original_event(actor, action, target, outcome, metadata)

        runtime._event = crash_at_final_event
    runtime.execute(intent, token)
    os._exit(74)


def _crash_migration(path):
    original = Runtime._event

    def crash_before_commit(self, actor, action, target, outcome, metadata=None):
        if action == "migrate":
            os._exit(75)
        return original(self, actor, action, target, outcome, metadata)

    Runtime._event = crash_before_commit
    Runtime(path, clock=lambda: 1000.0)
    os._exit(76)


class TestAdversarialRuntime(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cup_actual_runtime_")
        self.path = Path(self.temp.name) / "runtime.sqlite"
        self.now = 1000.0
        self.runtime = Runtime(self.path, clock=lambda: self.now)
        self.runtime.put_resource("source", "hello")
        self.runtime.put_resource("output", "")

    def tearDown(self):
        self.runtime.close()
        self.temp.cleanup()

    def add_task(self, task="A", source="source", output="output", dependencies=()):
        self.runtime.add_task(task, source, output, "uppercase", digest("HELLO"), dependencies)

    def claimed_intent(self, claim, key="write-1", content="HELLO", fence=None):
        return Intent(claim["run_id"], "artifact.write", claim["task"]["output"], claim["output_version"], key, claim["fence"] if fence is None else fence, {"content": content})

    def complete(self, task="A"):
        claim = self.runtime.claim("worker")
        self.assertIsNotNone(claim)
        self.assertEqual(claim["task"]["id"], task)
        self.runtime.execute(self.claimed_intent(claim, "write-" + task), claim["token"])
        return self.runtime.verify(task, "unittest-sqlite-local")

    def run_concurrent(self, target, values):
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(len(values))
        queue = context.Queue()
        processes = [context.Process(target=target, args=(str(self.path), barrier, queue, value)) for value in values]
        try:
            for process in processes:
                process.start()
            results = [queue.get(timeout=15) for _ in processes]
            for process in processes:
                process.join(15)
                self.assertEqual(process.exitcode, 0)
            self.assertFalse(any(item[0] == "ERROR" for item in results), results)
            return results
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(5)
            queue.close()
            queue.join_thread()

    def test_process_claims_single_task_exactly_once(self):
        self.add_task()
        results = self.run_concurrent(_claim_process, ["worker-1", "worker-2", "worker-3", "worker-4"])
        claimed = [value for category, value in results if value is not None]
        self.assertEqual(len(claimed), 1, results)
        self.assertEqual(self.runtime.db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 1)
        self.assertEqual(self.runtime.task("A")["status"], "RUNNING")
        self.assertTrue(self.runtime.check_journal())

    def test_process_cas_has_one_winner(self):
        results = self.run_concurrent(_cas_process, ["one", "two"])
        self.assertEqual(sorted(category for category, _ in results), ["BLOCK", "COMMITTED"])
        resource = self.runtime.resource("source")
        self.assertEqual(resource["version"], 2)
        self.assertIn(resource["content"], {"one", "two"})
        self.assertTrue(self.runtime.check_journal())

    def test_process_crash_before_commit_rolls_back_whole_transition(self):
        self.add_task()
        claim = self.runtime.claim("worker", ttl=1)
        before_events = self.runtime.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        context = multiprocessing.get_context("spawn")
        process = context.Process(target=_crash_write, args=(str(self.path), self.claimed_intent(claim), claim["token"], False))
        process.start()
        process.join(15)
        if process.is_alive():
            process.terminate()
            process.join(5)
        self.assertEqual(process.exitcode, 73)
        self.runtime.close()
        self.runtime = Runtime(self.path, clock=lambda: self.now)
        self.assertEqual(self.runtime.resource("output")["version"], 1)
        self.assertEqual(self.runtime.resource("output")["content"], "")
        self.assertEqual(self.runtime.task("A")["status"], "RUNNING")
        self.assertEqual(self.runtime.db.execute("SELECT state FROM runs WHERE id=?", (claim["run_id"],)).fetchone()[0], "RUNNING")
        self.assertEqual(self.runtime.db.execute("SELECT COUNT(*) FROM effects").fetchone()[0], 0)
        self.assertEqual(self.runtime.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], before_events)
        self.now = 1002.0
        self.assertEqual(self.runtime.recover(), 1)
        self.assertEqual(self.runtime.task("A")["status"], "BLOCKED")
        self.runtime.resume("A")
        recovered = self.runtime.claim("worker-recovered")
        self.assertGreater(recovered["fence"], claim["fence"])
        self.runtime.execute(self.claimed_intent(recovered, "recovered-effect"), recovered["token"])
        self.assertEqual(self.runtime.verify("A", "recovered-local")["outcome"], "PASS")
        self.assertTrue(self.runtime.check_journal())

    def test_process_crash_after_commit_replay_has_no_second_effect(self):
        self.add_task()
        claim = self.runtime.claim("worker")
        intent = self.claimed_intent(claim)
        context = multiprocessing.get_context("spawn")
        process = context.Process(target=_crash_write, args=(str(self.path), intent, claim["token"], True))
        process.start()
        process.join(15)
        if process.is_alive():
            process.terminate()
            process.join(5)
        self.assertEqual(process.exitcode, 74)
        self.runtime.close()
        self.runtime = Runtime(self.path, clock=lambda: self.now)
        receipt = self.runtime.execute(intent, claim["token"])
        self.assertTrue(receipt["replayed"])
        self.assertEqual(self.runtime.resource("output")["version"], 2)
        self.assertEqual(self.runtime.db.execute("SELECT COUNT(*) FROM effects").fetchone()[0], 1)
        self.assertEqual(self.runtime.verify("A", "reopened-local")["outcome"], "PASS")
        self.assertTrue(self.runtime.check_journal())

    def test_revoke_between_claim_and_write_denies_mutation(self):
        self.add_task()
        claim = self.runtime.claim("worker")
        self.runtime.revoke(claim["run_id"])
        with self.assertRaisesRegex(GuardError, "revoked"):
            self.runtime.execute(self.claimed_intent(claim), claim["token"])
        self.assertEqual(self.runtime.resource("output")["version"], 1)
        self.assertEqual(self.runtime.db.execute("SELECT COUNT(*) FROM effects").fetchone()[0], 0)
        self.assertTrue(self.runtime.check_journal())

    def test_expiry_at_exact_boundary_denies_mutation(self):
        self.add_task()
        claim = self.runtime.claim("worker", ttl=1)
        self.now = 1001.0
        with self.assertRaisesRegex(GuardError, "expired"):
            self.runtime.execute(self.claimed_intent(claim), claim["token"])
        self.assertEqual(self.runtime.resource("output")["version"], 1)

    def test_wrong_fence_with_valid_credential_denies_mutation(self):
        self.add_task()
        claim = self.runtime.claim("worker")
        with self.assertRaisesRegex(GuardError, "fencing"):
            self.runtime.execute(self.claimed_intent(claim, fence=claim["fence"] + 1), claim["token"])
        self.assertEqual(self.runtime.resource("output")["version"], 1)

    def test_proof_stale_after_owner_output_cas(self):
        self.add_task()
        proof = self.complete()
        self.assertTrue(self.runtime.proof_current(proof["evidence"]))
        self.runtime.put_resource("output", "changed", 2)
        self.assertFalse(self.runtime.proof_current(proof["evidence"]))
        self.assertEqual(self.runtime.task("A")["status"], "PARTIAL")

    def test_source_changed_before_verify_blocks_evidence_creation(self):
        self.add_task()
        claim = self.runtime.claim("worker")
        self.runtime.execute(self.claimed_intent(claim), claim["token"])
        self.runtime.put_resource("source", "different", 1)
        with self.assertRaisesRegex(GuardError, "stale"):
            self.runtime.verify("A", "local")
        self.assertEqual(self.runtime.db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)

    def test_invalid_dependency_rolls_back_task_and_event(self):
        events = self.runtime.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_task(dependencies=("MISSING",))
        with self.assertRaisesRegex(GuardError, "unknown task"):
            self.runtime.task("A")
        self.assertEqual(self.runtime.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], events)

    def test_expired_lease_replacement_does_not_orphan_old_run(self):
        self.add_task("A")
        self.add_task("B")
        first = self.runtime.claim("worker-A", ttl=1)
        self.now = 1002.0
        second = self.runtime.claim("worker-B")
        self.assertEqual(second["task"]["id"], "B")
        self.assertGreater(second["fence"], first["fence"])
        self.runtime.recover()
        state = self.runtime.db.execute("SELECT state FROM runs WHERE id=?", (first["run_id"],)).fetchone()[0]
        self.assertEqual(state, "SUSPECT", "Replacing a lease must not hide a crashed run from recovery")
        self.assertEqual(self.runtime.task("A")["status"], "BLOCKED")
        self.assertEqual(self.runtime.task("B")["status"], "RUNNING")

    def test_parent_invalidation_propagates_to_verified_descendant(self):
        self.runtime.put_resource("middle", "")
        self.add_task("A")
        self.add_task("B", output="middle", dependencies=("A",))
        self.complete("A")
        child_proof = self.complete("B")
        self.assertEqual(self.runtime.task("B")["status"], "VERIFIED")
        self.runtime.put_resource("output", "changed-parent-result", 2)
        self.assertEqual(self.runtime.task("A")["status"], "PARTIAL")
        self.assertEqual(self.runtime.task("B")["status"], "PARTIAL", "Dependency evidence is stale even when B's own resources are unchanged")
        self.assertFalse(self.runtime.proof_current(child_proof["evidence"]))

    def test_parent_invalidated_after_child_claim_blocks_child_write(self):
        self.runtime.put_resource("middle", "")
        self.add_task("A")
        self.add_task("B", output="middle", dependencies=("A",))
        self.complete("A")
        child = self.runtime.claim("child-worker")
        self.assertEqual(child["task"]["id"], "B")
        self.runtime.put_resource("output", "changed-parent-result", 2)
        with self.assertRaises(GuardError):
            self.runtime.execute(self.claimed_intent(child, "child-effect"), child["token"])
        self.assertEqual(self.runtime.resource("middle")["version"], 1)

    def test_parent_invalidated_after_child_result_blocks_verification(self):
        self.runtime.put_resource("middle", "")
        self.add_task("A")
        self.add_task("B", output="middle", dependencies=("A",))
        self.complete("A")
        child = self.runtime.claim("child-worker")
        self.runtime.execute(self.claimed_intent(child, "child-effect"), child["token"])
        self.runtime.put_resource("output", "changed-parent-result", 2)
        with self.assertRaises(GuardError):
            self.runtime.verify("B", "local-child")
        self.assertEqual(self.runtime.db.execute("SELECT COUNT(*) FROM evidence WHERE task='B'").fetchone()[0], 0)

    def make_v1_fixture(self):
        """Schema v1 differs here only by missing dependency snapshots and identity.

        The controlled fixture retains actual resources/runs/events produced by
        public runtime operations, then removes the v2 additions on a closed DB.
        """
        self.runtime.close()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            for column in ("source_policy_id","policy_id","validation_mode"):
                connection.execute("ALTER TABLE tasks DROP COLUMN " + column)
            for table in ("generative_evaluations","validation_policy_revocations","generative_keys","validation_policies"):
                connection.execute("DROP TABLE " + table)
            connection.execute("DROP TABLE run_input_bindings")
            connection.execute("ALTER TABLE tasks DROP COLUMN source_expected_sha")
            connection.execute("ALTER TABLE tasks DROP COLUMN producer")
            connection.execute("ALTER TABLE tasks DROP COLUMN input_mode")
            connection.execute("DROP TABLE run_dependencies")
            connection.execute("PRAGMA application_id=0")
            connection.execute("PRAGMA user_version=1")

    def test_migration_stops_legacy_active_run_and_preserves_journal(self):
        self.add_task()
        claim = self.runtime.claim("worker")
        self.make_v1_fixture()
        self.runtime = Runtime(self.path, clock=lambda: self.now)
        self.assertEqual(self.runtime.snapshot()["schema_version"], 4)
        self.assertEqual(self.runtime.task("A")["status"], "BLOCKED")
        self.assertEqual(self.runtime.db.execute("SELECT state FROM runs WHERE id=?", (claim["run_id"],)).fetchone()[0], "SUSPECT")
        with self.assertRaises(GuardError):
            self.runtime.execute(self.claimed_intent(claim), claim["token"])
        self.assertEqual(self.runtime.resource("output")["version"], 1)
        self.assertTrue(self.runtime.check_journal())

    def test_migration_exception_rolls_back_schema_task_run_and_event(self):
        self.add_task()
        claim = self.runtime.claim("worker")
        events = self.runtime.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.make_v1_fixture()
        with patch.object(Runtime, "_event", side_effect=RuntimeError("injected-migration-failure")):
            with self.assertRaisesRegex(RuntimeError, "injected-migration-failure"):
                Runtime(self.path, clock=lambda: self.now)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='run_dependencies'").fetchone())
            self.assertEqual(connection.execute("SELECT status FROM tasks WHERE id='A'").fetchone()[0], "RUNNING")
            self.assertEqual(connection.execute("SELECT state FROM runs WHERE id=?", (claim["run_id"],)).fetchone()[0], "RUNNING")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0], events)
        self.runtime = Runtime(self.path, clock=lambda: self.now)
        self.assertTrue(self.runtime.check_journal())

    def test_process_crash_during_migration_rolls_back_atomically(self):
        self.add_task()
        claim = self.runtime.claim("worker")
        self.make_v1_fixture()
        context = multiprocessing.get_context("spawn")
        process = context.Process(target=_crash_migration, args=(str(self.path),))
        process.start()
        process.join(15)
        if process.is_alive():
            process.terminate()
            process.join(5)
        self.assertEqual(process.exitcode, 75)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='run_dependencies'").fetchone())
            self.assertEqual(connection.execute("SELECT status FROM tasks WHERE id='A'").fetchone()[0], "RUNNING")
            self.assertEqual(connection.execute("SELECT state FROM runs WHERE id=?", (claim["run_id"],)).fetchone()[0], "RUNNING")
        self.runtime = Runtime(self.path, clock=lambda: self.now)
        self.assertTrue(self.runtime.check_journal())

    def test_migration_cannot_accept_legacy_proof_without_dependency_snapshot(self):
        self.runtime.put_resource("middle", "")
        self.add_task("A")
        self.add_task("B", output="middle", dependencies=("A",))
        self.complete("A")
        child_proof = self.complete("B")
        self.make_v1_fixture()
        self.runtime = Runtime(self.path, clock=lambda: self.now)
        self.assertFalse(self.runtime.proof_current(child_proof["evidence"]), "Legacy dependencies were not version-snapshotted and cannot be treated as proven")
        self.assertNotEqual(self.runtime.task("B")["status"], "VERIFIED")
        self.assertTrue(self.runtime.check_journal())

    def test_parent_revision_changed_while_verified_blocks_claimed_child(self):
        self.runtime.put_resource("middle", "")
        self.add_task("A")
        self.add_task("B", output="middle", dependencies=("A",))
        self.complete("A")
        child = self.runtime.claim("child-worker")
        # Simulate a trusted owner contract refresh/revalidation in the fixture;
        # state VERIFIED alone must not override the captured revision.
        with self.runtime.transaction():
            self.runtime.db.execute("UPDATE tasks SET revision=revision+1 WHERE id='A'")
        self.assertEqual(self.runtime.task("A")["status"], "VERIFIED")
        with self.assertRaisesRegex(GuardError, "dependency"):
            self.runtime.execute(self.claimed_intent(child, "child-effect"), child["token"])
        self.assertEqual(self.runtime.resource("middle")["version"], 1)

    def test_result_ready_label_without_successful_run_is_not_terminal_evidence(self):
        self.add_task()
        self.runtime.claim("worker")
        # Corrupt only the administrative label in the test-owned fixture;
        # the independent verifier still requires a succeeded versioned run.
        with self.runtime.transaction():
            self.runtime.db.execute("UPDATE tasks SET status='RESULT_READY' WHERE id='A'")
        with self.assertRaises(GuardError):
            self.runtime.verify("A", "caller-claims-PASS")
        self.assertEqual(self.runtime.db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
