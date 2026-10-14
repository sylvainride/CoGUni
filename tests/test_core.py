import sqlite3
import tempfile
import unittest
from pathlib import Path

from universal.core import GuardError, Intent, Runtime, digest
from universal.dag import topological_order
from universal.worker import run_pool, worker_main


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "control.sqlite"
        self.now = [1000.0]
        self.rt = Runtime(self.path, clock=lambda: self.now[0])
        self.rt.put_resource("source", "bonjour")
        self.rt.put_resource("output", "")
        self.rt.add_task("T1", "source", "output", "uppercase", digest("BONJOUR"))

    def tearDown(self):
        self.rt.close()
        self.tmp.cleanup()

    def intent(self, claim, content="BONJOUR", key="operation", version=1, resource="output", fence=None):
        return Intent(claim["run_id"], "artifact.write", resource, version, key, claim["fence"] if fence is None else fence, {"content": content})

    def test_write_replay_and_key_collision(self):
        claim = self.rt.claim("worker")
        intent = self.intent(claim)
        first = self.rt.execute(intent, claim["token"])
        second = self.rt.execute(intent, claim["token"])
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(self.rt.resource("output")["version"], 2)
        with self.assertRaisesRegex(GuardError, "collision"):
            self.rt.execute(self.intent(claim, "different"), claim["token"])
        self.assertEqual(self.rt.resource("output")["content"], "BONJOUR")

    def test_scope_token_expiry_revocation_and_schema(self):
        claim = self.rt.claim("worker")
        for intent, token in [(self.intent(claim, resource="source"), claim["token"]), (self.intent(claim), "invalid"), (Intent(claim["run_id"], "shell.exec", "output", 1, "key", 1, {}), claim["token"]), (Intent(claim["run_id"], "artifact.write", "output", True, "key", 1, {"content": "X"}), claim["token"])]:
            with self.assertRaises(GuardError):
                self.rt.execute(intent, token)
        self.rt.revoke(claim["run_id"])
        with self.assertRaises(GuardError):
            self.rt.execute(self.intent(claim), claim["token"])
        self.assertEqual(self.rt.resource("output")["version"], 1)
        self.assertTrue(self.rt.check_journal())

    def test_stale_and_fencing_denied_without_effect(self):
        claim = self.rt.claim("worker")
        for intent in [self.intent(claim, version=0), self.intent(claim, fence=0)]:
            with self.assertRaises(GuardError):
                self.rt.execute(intent, claim["token"])
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 0)

    def test_verification_is_executed_then_invalidated(self):
        with self.assertRaises(GuardError):
            self.rt.verify("T1", "test-env")
        claim = self.rt.claim("worker")
        self.rt.execute(self.intent(claim), claim["token"])
        evidence = self.rt.verify("T1", "test-env")
        self.assertEqual(evidence["outcome"], "PASS")
        self.assertEqual(self.rt.task("T1")["status"], "VERIFIED")
        self.assertTrue(self.rt.proof_current(evidence["evidence"]))
        self.rt.put_resource("source", "changed", 1)
        self.assertFalse(self.rt.proof_current(evidence["evidence"]))
        self.assertEqual(self.rt.task("T1")["status"], "PARTIAL")
        with self.assertRaises(sqlite3.IntegrityError):
            self.rt.db.execute("UPDATE evidence SET outcome='PASS'")

    def test_wrong_output_cannot_be_verified(self):
        claim = self.rt.claim("worker")
        self.rt.execute(self.intent(claim, "wrong"), claim["token"])
        self.assertEqual(self.rt.verify("T1", "test-env")["outcome"], "FAIL")
        self.assertEqual(self.rt.task("T1")["status"], "FAILED")

    def test_expired_claim_recovered_with_new_fence(self):
        first = self.rt.claim("old", ttl=1)
        self.now[0] += 2
        with self.assertRaises(GuardError):
            self.rt.execute(self.intent(first), first["token"])
        self.assertEqual(self.rt.recover(), 1)
        self.rt.resume("T1")
        second = self.rt.claim("new")
        self.assertGreater(second["fence"], first["fence"])
        self.rt.execute(self.intent(second), second["token"])

    def test_source_snapshot_and_backup_restore(self):
        self.rt.source_snapshot("SRC1", "source")
        self.assertTrue(self.rt.source_current("SRC1"))
        backup = Path(self.tmp.name) / "backup.sqlite"
        self.rt.backup(backup)
        self.rt.put_resource("source", "new", 1)
        self.assertFalse(self.rt.source_current("SRC1"))
        restored = Runtime(backup)
        try:
            self.assertEqual(restored.resource("source")["content"], "bonjour")
            self.assertTrue(restored.source_current("SRC1"))
            self.assertTrue(restored.check_journal())
        finally:
            restored.close()
        with self.assertRaises(GuardError):
            self.rt.backup(backup)

    def test_atomic_invalid_dependency_and_unknown_schema(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.rt.add_task("T2", "source", "output", "copy", digest("bonjour"), ["missing"])
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM tasks").fetchone()[0], 1)
        wrong = Path(self.tmp.name) / "foreign.sqlite"
        db = sqlite3.connect(wrong)
        db.execute("CREATE TABLE customer(value TEXT)")
        db.close()
        with self.assertRaises(GuardError):
            Runtime(wrong)

    def test_deep_iterative_graph_and_cycle(self):
        graph = {str(i): [str(i - 1)] if i else [] for i in range(30001)}
        self.assertEqual(len(topological_order(graph)), 30001)
        graph["0"] = ["30000"]
        with self.assertRaisesRegex(ValueError, "cycle"):
            topological_order(graph)


class ProcessTests(unittest.TestCase):
    def test_two_real_workers_on_durable_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "workers.sqlite"
            rt = Runtime(path)
            for i in range(8):
                rt.put_resource("source" + str(i), "entrée" + str(i))
                rt.put_resource("output" + str(i), "")
                rt.add_task("T" + str(i), "source" + str(i), "output" + str(i), "uppercase", digest("ENTRÉE" + str(i)))
            rt.close()
            results = run_pool(path, workers=2, max_jobs=8)
            self.assertEqual(len(results), 2)
            self.assertFalse(any("error_type" in result for result in results))
            rt = Runtime(path)
            try:
                self.assertEqual(rt.db.execute("SELECT count(*) FROM tasks WHERE status='VERIFIED'").fetchone()[0], 8)
                self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 8)
                self.assertTrue(rt.check_journal())
            finally:
                rt.close()


if __name__ == "__main__":
    unittest.main()
