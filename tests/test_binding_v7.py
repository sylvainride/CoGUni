"""Independent behavioral oracles for explicit verified-producer input binding.

The audit's original tests deliberately reproduce a blocked PINNED_VERSION
pipeline. These tests distinguish successful opt-in pipelines from that legacy
behavior. Trusted owner fixtures write artifacts; broker isolation is tested in
the separate process suite, not asserted by this module.
"""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from universal.core import GuardError, Intent, Runtime, digest


MODE = "VERIFIED_UPSTREAM_OUTPUT"
ENV = "binding-test-environment"


class BindingV7Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "runtime.sqlite"
        self.now = [1000.0]
        self.rt = Runtime(self.path, clock=lambda: self.now[0])

    def tearDown(self):
        self.rt.close()
        self.tmp.cleanup()

    def resources(self, count):
        self.rt.put_resource("r0", "alpha")
        for index in range(1, count + 1):
            self.rt.put_resource("r" + str(index), "")

    def chain(self, count):
        self.resources(count)
        for index in range(count):
            extra = {} if index == 0 else {
                "dependencies": ["T%03d" % (index - 1)],
                "input_mode": MODE,
                "producer": "T%03d" % (index - 1),
                "source_expected_sha": digest("ALPHA"),
            }
            self.rt.add_task("T%03d" % index, "r" + str(index),
                             "r" + str(index + 1),
                             "uppercase" if index == 0 else "copy",
                             digest("ALPHA"), **extra)

    def finish(self, expected_task, content="ALPHA", environment=ENV):
        claim = self.rt.claim("worker", environment=environment)
        self.assertIsNotNone(claim)
        self.assertEqual(claim["task"]["id"], expected_task)
        source = self.rt.execute(Intent(
            claim["run_id"], "artifact.read", claim["task"]["input"],
            claim["task"]["input_version"], claim["run_id"] + ".read",
            claim["fence"], {}), claim["token"])
        if expected_task != "T000":
            self.assertEqual(source["content"], "ALPHA")
            self.assertEqual(source["sha"], digest("ALPHA"))
            self.assertEqual(source["version"], 2)
        self.rt.execute(Intent(
            claim["run_id"], "artifact.write", claim["task"]["output"],
            claim["output_version"], claim["run_id"] + ".write",
            claim["fence"], {"content": content}), claim["token"])
        proof = self.rt.verify(expected_task, environment,
                               expected_run_id=claim["run_id"])
        return claim, proof

    def assert_chain(self, count):
        self.chain(count)
        for index in range(count):
            claim, proof = self.finish("T%03d" % index)
            self.assertEqual(proof["outcome"], "PASS")
            self.assertTrue(self.rt.proof_is_accepted_for_gate(
                proof["evidence"], ENV))
            if index:
                self.assertEqual(claim["task"]["input_version"], 2)
        self.assertEqual(self.rt.resource("r" + str(count))["content"], "ALPHA")
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], count)
        self.assertTrue(self.rt.check_journal())

    def test_two_stage_verified_output_pipeline(self):
        self.assert_chain(2)

    def test_three_stage_verified_output_pipeline(self):
        self.assert_chain(3)

    def test_one_hundred_stage_verified_output_pipeline(self):
        self.assert_chain(100)

    def test_legacy_pinned_pipeline_still_blocks_source_drift(self):
        self.resources(2)
        self.rt.add_task("T000", "r0", "r1", "uppercase", digest("ALPHA"))
        self.rt.add_task("T001", "r1", "r2", "copy", digest("ALPHA"),
                         dependencies=["T000"])
        self.finish("T000")
        self.assertIsNone(self.rt.claim("second", environment=ENV))
        self.assertEqual(self.rt.task("T001")["status"], "BLOCKED")
        self.assertEqual(self.rt.task("T001")["input_version"], 1)

    def test_owner_unrelated_drift_does_not_become_verified_input(self):
        self.chain(2)
        self.finish("T000")
        self.rt.put_resource("r1", "ALPHA", 2)  # Identical bytes, different lineage.
        self.assertIsNone(self.rt.claim("second", environment=ENV))
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM runs").fetchone()[0], 1)

    def test_failed_producer_is_never_bound(self):
        self.chain(2)
        _, proof = self.finish("T000", content="wrong")
        self.assertEqual(proof["outcome"], "FAIL")
        self.assertIsNone(self.rt.claim("second", environment=ENV))

    def test_wrong_environment_cannot_accept_producer(self):
        self.chain(2)
        self.finish("T000", environment="other-environment")
        self.assertIsNone(self.rt.claim("second", environment=ENV))
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM runs").fetchone()[0], 1)

    def test_dynamic_claim_requires_explicit_environment(self):
        self.chain(2)
        self.finish("T000")
        try:
            claim = self.rt.claim("second")
        except GuardError:
            claim = None
        self.assertIsNone(claim)
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM runs").fetchone()[0], 1)

    def test_revoked_producer_blocks_before_consumer_claim(self):
        self.chain(2)
        _, proof = self.finish("T000")
        self.rt.revoke_evidence(proof["evidence"], "independent_test")
        self.assertIsNone(self.rt.claim("second", environment=ENV))

    def test_revocation_after_claim_denies_consumer_effect(self):
        self.chain(2)
        _, parent_proof = self.finish("T000")
        claim = self.rt.claim("second", environment=ENV)
        self.assertIsNotNone(claim)
        self.rt.revoke_evidence(parent_proof["evidence"], "independent_test")
        with self.assertRaises(GuardError):
            self.rt.execute(Intent(claim["run_id"], "artifact.write", "r2", 1,
                                   claim["run_id"] + ".write", claim["fence"],
                                   {"content": "ALPHA"}), claim["token"])
        self.assertEqual(self.rt.resource("r2")["version"], 1)

    def test_revocation_invalidates_already_verified_descendant(self):
        self.chain(2)
        _, parent_proof = self.finish("T000")
        _, child_proof = self.finish("T001")
        self.rt.revoke_evidence(parent_proof["evidence"], "independent_test")
        self.assertFalse(self.rt.proof_is_accepted_for_gate(child_proof["evidence"], ENV))

    def test_bound_source_version_cannot_drift_during_consumer_run(self):
        self.chain(2)
        self.finish("T000")
        claim = self.rt.claim("second", environment=ENV)
        self.rt.put_resource("r1", "changed", 2)
        with self.assertRaises(GuardError):
            self.rt.execute(Intent(claim["run_id"], "artifact.write", "r2", 1,
                                   claim["run_id"] + ".write", claim["fence"],
                                   {"content": "ALPHA"}), claim["token"])
        self.assertEqual(self.rt.resource("r2")["version"], 1)

    def test_wrong_expected_source_sha_rejected(self):
        self.resources(2)
        self.rt.add_task("T000", "r0", "r1", "uppercase", digest("ALPHA"))
        with self.assertRaises(GuardError):
            self.rt.add_task("T001", "r1", "r2", "copy", digest("ALPHA"),
                             dependencies=["T000"], input_mode=MODE,
                             producer="T000", source_expected_sha=digest("OTHER"))
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM tasks").fetchone()[0], 1)

    def test_producer_must_be_declared_dependency(self):
        self.resources(2)
        self.rt.add_task("T000", "r0", "r1", "uppercase", digest("ALPHA"))
        with self.assertRaises(GuardError):
            self.rt.add_task("T001", "r1", "r2", "copy", digest("ALPHA"),
                             input_mode=MODE, producer="T000",
                             source_expected_sha=digest("ALPHA"))

    def test_producer_output_must_be_consumer_source(self):
        self.resources(3)
        self.rt.add_task("T000", "r0", "r1", "uppercase", digest("ALPHA"))
        with self.assertRaises(GuardError):
            self.rt.add_task("T001", "r2", "r3", "copy", digest("ALPHA"),
                             dependencies=["T000"], input_mode=MODE,
                             producer="T000", source_expected_sha=digest("ALPHA"))

    def test_missing_or_malformed_binding_is_rejected_atomically(self):
        self.resources(2)
        self.rt.add_task("T000", "r0", "r1", "uppercase", digest("ALPHA"))
        cases = [
            {"input_mode": MODE},
            {"input_mode": MODE, "producer": "T000"},
            {"input_mode": MODE, "producer": "T000", "source_expected_sha": "X"},
            {"input_mode": "UNKNOWN", "producer": "T000", "source_expected_sha": digest("ALPHA")},
            {"producer": "T000", "source_expected_sha": digest("ALPHA")},
        ]
        for index, extra in enumerate(cases):
            with self.subTest(extra=extra), self.assertRaises(GuardError):
                self.rt.add_task("BAD" + str(index), "r1", "r2", "copy",
                                 digest("ALPHA"), dependencies=["T000"], **extra)
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM tasks").fetchone()[0], 1)

    def test_fork_and_join_declared_lineage_remains_executable(self):
        self.chain(2)
        self.rt.put_resource("fork-out", "")
        self.rt.put_resource("join-out", "")
        self.rt.add_task("T002", "r1", "fork-out", "copy", digest("ALPHA"),
                         dependencies=["T000"], input_mode=MODE, producer="T000",
                         source_expected_sha=digest("ALPHA"))
        self.rt.add_task("T003", "r2", "join-out", "copy", digest("ALPHA"),
                         dependencies=["T001", "T002"], input_mode=MODE,
                         producer="T001", source_expected_sha=digest("ALPHA"))
        proofs = []
        for index in range(4):
            _, proof = self.finish("T%03d" % index)
            proofs.append(proof)
            self.assertEqual(proof["outcome"], "PASS")
        self.assertEqual(self.rt.resource("join-out")["content"], "ALPHA")
        self.rt.revoke_evidence(proofs[2]["evidence"], "nonproducer_parent")
        self.assertFalse(self.rt.proof_is_accepted_for_gate(proofs[3]["evidence"], ENV))

    def test_multiple_direct_producers_of_source_are_rejected(self):
        self.resources(2)
        for task in ["P1", "P2"]:
            self.rt.add_task(task, "r0", "r1", "uppercase", digest("ALPHA"))
        with self.assertRaises(GuardError):
            self.rt.add_task("B", "r1", "r2", "copy", digest("ALPHA"),
                             dependencies=["P1", "P2"], input_mode=MODE,
                             producer="P1", source_expected_sha=digest("ALPHA"))

    def test_backup_restores_bound_lineage_without_reissuing_producer(self):
        self.chain(2)
        self.finish("T000")
        backup = Path(self.tmp.name) / "backup.sqlite"
        self.rt.backup(backup)
        self.rt.close()
        self.rt = Runtime(backup, clock=lambda: self.now[0])
        _, proof = self.finish("T001")
        self.assertTrue(self.rt.proof_is_accepted_for_gate(proof["evidence"], ENV))
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 2)

    def test_expired_consumer_reclaims_with_same_verified_input(self):
        self.chain(2)
        self.finish("T000")
        old = self.rt.claim("old", ttl=1, environment=ENV)
        self.now[0] += 2
        self.assertEqual(self.rt.recover(), 1)
        self.rt.resume("T001", environment=ENV)
        new = self.rt.claim("new", environment=ENV)
        self.assertEqual(new["task"]["input_version"], 2)
        self.assertNotEqual(old["run_id"], new["run_id"])
        self.assertGreater(new["fence"], old["fence"])
        old_intent = Intent(old["run_id"], "artifact.write", "r2", 1,
                            old["run_id"] + ".write", old["fence"],
                            {"content": "ALPHA"})
        with self.assertRaises(GuardError):
            self.rt.execute(old_intent, old["token"])


if __name__ == "__main__":
    unittest.main()
