"""Atomic DAG provisioning and trusted controller disconnect transitions."""
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from universal.core import GuardError, Intent, Runtime, digest
from universal.dag import topological_order


def _add_opposing_dependency(path, barrier, queue, task, parent):
    with Runtime(path) as runtime:
        barrier.wait(timeout=10)
        try:
            runtime.add_dependency(task, parent, 1)
            queue.put("COMMITTED")
        except ValueError as error:
            queue.put("CYCLE" if "cycle" in str(error) else "UNEXPECTED_VALUE_ERROR")
        except BaseException as error:
            queue.put(type(error).__name__)


class DagProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "dag.sqlite"
        self.rt = Runtime(self.path)
        self.rt.put_resource("source", "hello")
        self.rt.put_resource("output", "")

    def tearDown(self):
        self.rt.close()
        self.temp.cleanup()

    def contract(self, task, parents=()):
        return {"id": task, "source": "source", "output": "output", "action": "copy",
                "expected_sha": digest("hello"), "dependencies": list(parents)}

    def add(self, task, parents=()):
        self.rt.add_task(task, "source", "output", "copy", digest("hello"), parents)

    def state_counts(self):
        return tuple(self.rt.db.execute("SELECT count(*) FROM " + table).fetchone()[0]
                     for table in ("tasks", "deps", "events"))

    def test_new_node_addition_does_not_sort_existing_graph(self):
        self.add("A")
        with patch("universal.core.topological_order", side_effect=AssertionError("global-sort-forbidden")):
            self.add("B", ("A",))
        self.assertEqual(self.rt.task("B")["status"], "READY")
        self.assertTrue(self.rt.check_journal())

    def test_new_node_self_cycle_rolls_back_task_edges_and_event(self):
        before = self.state_counts()
        with self.assertRaisesRegex(ValueError, "cycle"):
            self.add("A", ("A",))
        self.assertEqual(self.state_counts(), before)

    def test_single_task_missing_parent_and_duplicate_id_remain_atomic(self):
        self.add("A")
        before = self.state_counts()
        for task, parents in (("B", ("missing",)), ("A", ())):
            with self.assertRaises(sqlite3.IntegrityError):
                self.add(task, parents)
            self.assertEqual(self.state_counts(), before)

    def test_batch_forward_references_are_validated_once_and_kept_in_input_order(self):
        contracts = [self.contract("C", ("B",)), self.contract("A"), self.contract("B", ("A",))]
        with patch("universal.core.topological_order", wraps=topological_order) as sorter:
            created = self.rt.add_tasks_batch(contracts)
        self.assertEqual(created, ["C", "A", "B"])
        self.assertEqual(sorter.call_count, 1)
        # Schema 3 contributes one immutable migration event, in addition to
        # two resource puts and the three imported task contracts.
        self.assertEqual(self.state_counts(), (3, 2, 7))
        self.assertEqual(self.rt.claim("worker")["task"]["id"], "A")
        self.assertTrue(self.rt.check_journal())

    def test_batch_cycle_forward_refs_and_missing_parent_rollback(self):
        before = self.state_counts()
        invalid = ([self.contract("A", ("B",)), self.contract("B", ("A",))],
                   [self.contract("A", ("A",))],
                   [self.contract("A"), self.contract("B", ("missing",))],
                   [self.contract("A"), self.contract("A")])
        for contracts in invalid:
            with self.subTest(contracts=contracts):
                with self.assertRaises((ValueError, sqlite3.IntegrityError)):
                    self.rt.add_tasks_batch(contracts)
                self.assertEqual(self.state_counts(), before)

    def test_batch_invalid_schema_resource_and_action_have_no_partial_effect(self):
        before = self.state_counts()
        for value in (None, {}, [42], [dict(self.contract("A"), extra=True)],
                      [dict(self.contract("A"), action="shell")],
                      [dict(self.contract("A"), dependencies="B")],
                      [self.contract("A"), dict(self.contract("B"), source="missing")]):
            with self.subTest(value=value):
                with self.assertRaises(GuardError):
                    self.rt.add_tasks_batch(value)
                self.assertEqual(self.state_counts(), before)

    def test_batch_audit_exception_rolls_back_all_nodes_edges_and_events(self):
        before = self.state_counts()
        original_event = self.rt._event
        calls = []

        def event(*args, **kwargs):
            calls.append(args)
            if len(calls) == 2:
                raise RuntimeError("injected-batch-failure")
            return original_event(*args, **kwargs)

        with patch.object(self.rt, "_event", side_effect=event):
            with self.assertRaisesRegex(RuntimeError, "injected-batch-failure"):
                self.rt.add_tasks_batch([self.contract("A"), self.contract("B", ("A",))])
        self.assertEqual(self.state_counts(), before)
        self.assertTrue(self.rt.check_journal())

    def test_add_dependency_uses_local_iterative_reachability_and_preserves_cas(self):
        self.add("A")
        self.add("B")
        with patch("universal.core.topological_order", side_effect=AssertionError("global-sort-forbidden")):
            self.rt.add_dependency("B", "A", 1)
        self.assertEqual(self.rt.task("B")["revision"], 2)
        before = self.state_counts()
        with self.assertRaisesRegex(GuardError, "stale"):
            self.rt.add_dependency("B", "A", 1)
        with self.assertRaisesRegex(ValueError, "cycle"):
            self.rt.add_dependency("A", "B", 1)
        self.assertEqual(self.state_counts(), before)
        self.assertEqual(self.rt.task("A")["revision"], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.rt.add_dependency("B", "A", 2)
        self.assertEqual(self.rt.task("B")["revision"], 2)

    def test_active_task_contract_cannot_gain_dependency(self):
        self.add("A")
        self.add("B")
        self.rt.claim("worker")
        revision = self.rt.task("A")["revision"]
        with self.assertRaisesRegex(GuardError, "active"):
            self.rt.add_dependency("A", "B", revision)
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM deps").fetchone()[0], 0)

    def test_deep_ancestors_cycle_check_is_iterative(self):
        size = 2200
        contracts = [self.contract("T" + str(i), ("T" + str(i - 1),) if i else ()) for i in range(size)]
        self.rt.add_tasks_batch(contracts)
        self.add("Z")
        self.rt.add_dependency("Z", "T2199", 1)
        with self.assertRaisesRegex(ValueError, "cycle"):
            self.rt.add_dependency("T0", "T2199", 1)
        self.assertEqual(self.rt.task("T0")["revision"], 1)
        self.assertEqual(self.rt.task("Z")["revision"], 2)

    def test_concurrent_opposing_edges_commit_one_and_reject_cycle(self):
        self.add("A")
        self.add("B")
        context = multiprocessing.get_context("spawn")
        barrier, queue = context.Barrier(2), context.Queue()
        processes = [context.Process(target=_add_opposing_dependency,
                                     args=(str(self.path), barrier, queue, task, parent))
                     for task, parent in (("A", "B"), ("B", "A"))]
        try:
            for process in processes:
                process.start()
            results = [queue.get(timeout=15) for _ in processes]
            for process in processes:
                process.join(15)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual(sorted(results), ["COMMITTED", "CYCLE"])
            self.assertEqual(self.rt.db.execute("SELECT count(*) FROM deps").fetchone()[0], 1)
            self.assertTrue(self.rt.check_journal())
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(5)
            queue.close()
            queue.join_thread()


class DisconnectTransitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "disconnect.sqlite"
        self.now = [1000.0]
        self.rt = Runtime(self.path, clock=lambda: self.now[0])
        self.rt.put_resource("source", "hello")
        self.rt.put_resource("output", "")
        self.rt.add_task("A", "source", "output", "copy", digest("hello"))

    def tearDown(self):
        self.rt.close()
        self.temp.cleanup()

    def intent(self, claim, key="write"):
        return Intent(claim["run_id"], "artifact.write", "output", claim["output_version"],
                      key, claim["fence"], {"content": "hello"})

    def test_disconnected_active_run_blocks_effect_and_can_resume_with_new_fence(self):
        claim = self.rt.claim("worker")
        self.assertTrue(self.rt.abandon_run(claim["run_id"]))
        self.assertFalse(self.rt.abandon_run(claim["run_id"]))
        self.assertEqual(self.rt.task("A")["status"], "BLOCKED")
        self.assertEqual(self.rt.db.execute("SELECT state FROM runs WHERE id=?", (claim["run_id"],)).fetchone()[0], "SUSPECT")
        with self.assertRaisesRegex(GuardError, "revoked"):
            self.rt.execute(self.intent(claim), claim["token"])
        self.assertEqual(self.rt.resource("output")["version"], 1)
        self.rt.resume("A")
        replacement = self.rt.claim("replacement")
        self.assertGreater(replacement["fence"], claim["fence"])
        self.assertTrue(self.rt.check_journal())

    def test_disconnect_after_commit_preserves_result_for_verifier(self):
        claim = self.rt.claim("worker")
        self.rt.execute(self.intent(claim), claim["token"])
        self.assertFalse(self.rt.abandon_run(claim["run_id"]))
        self.assertEqual(self.rt.task("A")["status"], "RESULT_READY")
        self.assertEqual(self.rt.db.execute("SELECT state FROM runs WHERE id=?", (claim["run_id"],)).fetchone()[0], "SUCCEEDED")
        self.assertEqual(self.rt.verify("A", "controller-test")["outcome"], "PASS")

    def test_old_run_disconnect_does_not_expire_replacement_holder_lease(self):
        self.rt.add_task("B", "source", "output", "copy", digest("hello"))
        old = self.rt.claim("old", ttl=1)
        self.now[0] += 2
        replacement = self.rt.claim("replacement")
        self.assertEqual(replacement["task"]["id"], "B")
        before = dict(self.rt.db.execute("SELECT * FROM leases WHERE resource='output'").fetchone())
        self.rt.abandon_run(old["run_id"])
        self.assertEqual(dict(self.rt.db.execute("SELECT * FROM leases WHERE resource='output'").fetchone()), before)
        self.assertEqual(self.rt.task("B")["status"], "RUNNING")

    def test_disconnect_audit_failure_rolls_back_run_task_grants_and_lease(self):
        claim = self.rt.claim("worker")
        before = self.rt.snapshot()
        with patch.object(self.rt, "_event", side_effect=RuntimeError("disconnect-failure")):
            with self.assertRaisesRegex(RuntimeError, "disconnect-failure"):
                self.rt.abandon_run(claim["run_id"])
        self.assertEqual(self.rt.snapshot(), before)
        self.rt.execute(self.intent(claim), claim["token"])
        self.assertEqual(self.rt.verify("A", "controller-test")["outcome"], "PASS")

    def test_unknown_run_or_invalid_reason_refused_without_event(self):
        claim = self.rt.claim("worker")
        before = self.rt.snapshot()
        with self.assertRaisesRegex(GuardError, "unknown run"):
            self.rt.abandon_run("unknown-run")
        with self.assertRaisesRegex(GuardError, "identifier"):
            self.rt.abandon_run(claim["run_id"], "untrusted payload with spaces")
        self.assertEqual(self.rt.snapshot(), before)

    def test_verification_binds_exact_run_after_old_result_is_recovered_and_replaced(self):
        old = self.rt.claim("old", ttl=1)
        self.rt.execute(self.intent(old), old["token"])
        self.now[0] += 2
        self.assertEqual(self.rt.recover(), 1)
        self.rt.resume("A")
        current = self.rt.claim("current")
        self.rt.execute(self.intent(current, "replacement-write"), current["token"])
        self.assertNotEqual(current["run_id"], old["run_id"])
        for expected in (old["run_id"], "caller-claims-PASS", 42, True):
            with self.subTest(expected_run_id=expected):
                with self.assertRaisesRegex(GuardError, "run identity"):
                    self.rt.verify("A", "controller-test", expected_run_id=expected)
                self.assertEqual(self.rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)
                self.assertEqual(self.rt.task("A")["status"], "RESULT_READY")
        result = self.rt.verify("A", "controller-test", expected_run_id=current["run_id"])
        evidence_run = self.rt.db.execute("SELECT run FROM evidence WHERE id=?", (result["evidence"],)).fetchone()[0]
        self.assertEqual(evidence_run, current["run_id"])
        self.assertTrue(self.rt.proof_is_accepted_for_gate(result["evidence"], "controller-test"))


if __name__ == "__main__":
    unittest.main()
