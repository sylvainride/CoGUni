"""V6 proof contracts and connection ownership, on disposable local databases."""
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from universal.core import GuardError, Intent, Runtime, digest


class EvidenceContractTests(unittest.TestCase):
    ENVIRONMENT = "controller-independent-sha256-v6"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "evidence.sqlite"
        self.rt = Runtime(self.path)
        self.rt.put_resource("source", "hello")
        self.rt.put_resource("output", "")
        self.rt.add_task("A", "source", "output", "uppercase", digest("HELLO"))

    def tearDown(self):
        self.rt.close()
        self.temp.cleanup()

    def complete(self, task="A", content="HELLO"):
        claim = self.rt.claim("worker")
        self.assertEqual(claim["task"]["id"], task)
        self.rt.execute(Intent(claim["run_id"], "artifact.write", claim["task"]["output"],
                               claim["output_version"], "write-" + task, claim["fence"],
                               {"content": content}), claim["token"])
        result = self.rt.verify(task, self.ENVIRONMENT)
        return result["evidence"]

    def test_fresh_fail_is_diagnostic_and_never_gate_accepted(self):
        evidence = self.complete(content="incorrect")
        self.assertTrue(self.rt.proof_is_fresh(evidence))
        self.assertTrue(self.rt.proof_current(evidence), "Compatibility means freshness only")
        self.assertEqual(self.rt.task("A")["status"], "FAILED")
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))
        self.rt.close()
        self.rt = Runtime(self.path)
        self.assertTrue(self.rt.proof_is_fresh(evidence))
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))

    def test_fresh_pass_is_accepted_only_for_matching_environment(self):
        evidence = self.complete()
        self.assertTrue(self.rt.proof_is_fresh(evidence))
        self.assertTrue(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, "different-host-or-policy"))
        self.assertTrue(self.rt.proof_is_fresh(evidence), "Environment is applicability, not freshness")
        for invalid in (None, "", 42, "x" * 201):
            with self.subTest(environment=invalid):
                with self.assertRaisesRegex(GuardError, "environment"):
                    self.rt.proof_is_accepted_for_gate(evidence, invalid)

    def test_changed_input_makes_pass_stale(self):
        evidence = self.complete()
        self.rt.put_resource("source", "changed", 1)
        self.assertFalse(self.rt.proof_is_fresh(evidence))
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))

    def test_changed_output_makes_pass_stale(self):
        evidence = self.complete()
        self.rt.put_resource("output", "changed", 2)
        self.assertFalse(self.rt.proof_is_fresh(evidence))
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))

    def test_gate_requires_task_and_run_verified_not_only_pass_label(self):
        evidence = self.complete()
        with self.rt.transaction():
            self.rt.db.execute("UPDATE tasks SET status='PARTIAL' WHERE id='A'")
        self.assertTrue(self.rt.proof_is_fresh(evidence))
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))
        with self.rt.transaction():
            self.rt.db.execute("UPDATE tasks SET status='VERIFIED' WHERE id='A'")
            self.rt.db.execute("UPDATE runs SET state='FAILED' WHERE task='A'")
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))

    def test_gate_rechecks_owner_contract_against_proof(self):
        evidence = self.complete()
        # Fixture-only contract corruption: owner API has no general SQL update.
        with self.rt.transaction():
            self.rt.db.execute("UPDATE tasks SET expected_sha=? WHERE id='A'", (digest("other"),))
        self.assertTrue(self.rt.proof_is_fresh(evidence))
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))

    def test_revocation_is_durable_immutable_and_idempotent(self):
        evidence = self.complete()
        self.assertTrue(self.rt.revoke_evidence(evidence, "verification-policy-withdrawn"))
        self.assertTrue(self.rt.proof_is_fresh(evidence), "Original diagnostic snapshot remains fresh")
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))
        self.assertEqual(self.rt.task("A")["status"], "PARTIAL")
        events = self.rt.db.execute("SELECT count(*) FROM events").fetchone()[0]
        self.assertFalse(self.rt.revoke_evidence(evidence, "repeat"))
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM events").fetchone()[0], events)
        with self.assertRaises(sqlite3.IntegrityError):
            self.rt.db.execute("DELETE FROM events WHERE action='evidence.revoke'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.rt.db.execute("UPDATE evidence SET outcome='PASS' WHERE id=?", (evidence,))
        self.rt.close()
        self.rt = Runtime(self.path)
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))
        self.assertTrue(self.rt.check_journal())

    def test_parent_revocation_invalidates_verified_descendant_and_stops_claim(self):
        self.rt.put_resource("child-output", "")
        self.rt.put_resource("waiting-output", "")
        self.rt.add_task("B", "source", "child-output", "uppercase", digest("HELLO"), ("A",))
        self.rt.add_task("C", "source", "waiting-output", "uppercase", digest("HELLO"), ("B",))
        parent_proof = self.complete()
        child_proof = self.complete("B")
        self.rt.revoke_evidence(parent_proof, "parent-proof-withdrawn")
        self.assertEqual(self.rt.task("B")["status"], "PARTIAL")
        self.assertFalse(self.rt.proof_is_fresh(child_proof))
        self.assertFalse(self.rt.proof_is_accepted_for_gate(child_proof, self.ENVIRONMENT))
        self.assertIsNone(self.rt.claim("later-worker"))

    def test_revocation_rolls_back_as_one_transition_if_audit_fails(self):
        evidence = self.complete()
        before_events = self.rt.db.execute("SELECT count(*) FROM events").fetchone()[0]
        with patch.object(self.rt, "_event", side_effect=RuntimeError("injected-revocation-failure")):
            with self.assertRaisesRegex(RuntimeError, "injected-revocation-failure"):
                self.rt.revoke_evidence(evidence, "withdrawn")
        self.assertTrue(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))
        self.assertEqual(self.rt.task("A")["status"], "VERIFIED")
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM events").fetchone()[0], before_events)

    def test_unknown_evidence_and_invalid_revocation_fail_closed(self):
        for method in (self.rt.proof_is_fresh, self.rt.proof_current):
            with self.assertRaisesRegex(GuardError, "unknown evidence"):
                method("missing")
        with self.assertRaisesRegex(GuardError, "unknown evidence"):
            self.rt.proof_is_accepted_for_gate("missing", self.ENVIRONMENT)
        evidence = self.complete()
        for invalid in (None, "", 42, "x" * 201):
            with self.assertRaisesRegex(GuardError, "reason"):
                self.rt.revoke_evidence(evidence, invalid)
        self.assertTrue(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))

    def test_dependencies_must_match_captured_revision_even_if_verified(self):
        self.rt.put_resource("child-output", "")
        self.rt.add_task("B", "source", "child-output", "uppercase", digest("HELLO"), ("A",))
        self.complete()
        evidence = self.complete("B")
        with self.rt.transaction():
            self.rt.db.execute("UPDATE tasks SET revision=revision+1 WHERE id='A'")
        self.assertFalse(self.rt.proof_is_fresh(evidence))
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))

    def test_dependency_identities_cannot_be_substituted_at_equal_cardinality(self):
        self.rt.put_resource("child-output", "")
        self.rt.put_resource("other-output", "")
        self.rt.add_task("B", "source", "child-output", "uppercase", digest("HELLO"), ("A",))
        self.rt.add_task("C", "source", "other-output", "uppercase", digest("HELLO"))
        self.complete()
        evidence = self.complete("B")
        self.complete("C")
        # Test-owned administrative substitution: A and C are both VERIFIED
        # with equal revisions and the number of dependencies remains one.
        with self.rt.transaction():
            self.rt.db.execute("DELETE FROM deps WHERE task='B'")
            self.rt.db.execute("INSERT INTO deps VALUES('B','C')")
        self.assertFalse(self.rt.proof_is_fresh(evidence))
        self.assertFalse(self.rt.proof_is_accepted_for_gate(evidence, self.ENVIRONMENT))

    def test_verifier_does_not_accept_caller_outcome(self):
        with self.assertRaises(TypeError):
            self.rt.verify("A", self.ENVIRONMENT, outcome="PASS")
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)


class ConnectionOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "owned.sqlite"

    def tearDown(self):
        self.temp.cleanup()

    def assert_closed(self, connection):
        with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed"):
            connection.execute("SELECT 1")

    def capture_connect(self, captured, factory=sqlite3.Connection):
        original = sqlite3.connect

        def connect(*args, **kwargs):
            kwargs["factory"] = factory
            connection = original(*args, **kwargs)
            captured.append(connection)
            return connection

        return connect

    def test_context_manager_closes_even_if_body_fails(self):
        with self.assertRaisesRegex(RuntimeError, "body-failure"):
            with Runtime(self.path) as runtime:
                connection = runtime.db
                raise RuntimeError("body-failure")
        self.assert_closed(connection)

    def test_foreign_database_constructor_closes_owned_connection(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("CREATE TABLE foreign_table(value TEXT)")
            connection.commit()
        captured = []
        with patch("universal.core.sqlite3.connect", self.capture_connect(captured)):
            with self.assertRaisesRegex(GuardError, "foreign database"):
                Runtime(self.path)
        self.assertEqual(len(captured), 1)
        self.assert_closed(captured[0])

    def test_migration_failure_closes_connection_and_rolls_back(self):
        with Runtime(self.path) as runtime:
            runtime.put_resource("source", "data")
            runtime.put_resource("output", "")
            runtime.add_task("A", "source", "output", "copy", digest("data"))
            runtime.claim("worker")
        with closing(sqlite3.connect(self.path)) as connection:
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
            connection.commit()
        captured = []
        with patch("universal.core.sqlite3.connect", self.capture_connect(captured)):
            with patch.object(Runtime, "_event", side_effect=RuntimeError("migration-failure")):
                with self.assertRaisesRegex(RuntimeError, "migration-failure"):
                    Runtime(self.path)
        self.assert_closed(captured[0])
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='run_dependencies'").fetchone())
            self.assertEqual(connection.execute("SELECT status FROM tasks WHERE id='A'").fetchone()[0], "RUNNING")
        with Runtime(self.path) as runtime:
            self.assertTrue(runtime.check_journal())

    def test_pragma_failure_after_initial_schema_closes_connection(self):
        class FailingConnection(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if sql == "PRAGMA synchronous=FULL":
                    raise RuntimeError("setup-failure")
                return super().execute(sql, *args, **kwargs)

        captured = []
        with patch("universal.core.sqlite3.connect", self.capture_connect(captured, FailingConnection)):
            with self.assertRaisesRegex(RuntimeError, "setup-failure"):
                Runtime(self.path)
        self.assert_closed(captured[0])
        with Runtime(self.path) as runtime:
            self.assertTrue(runtime.check_journal())


if __name__ == "__main__":
    unittest.main()
