"""Owner consent storage/signing races; the other five fixture gates stay synthetic."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from universal.broker import WorkerGate, environment_identity
from universal.consent import ConsentAuthority, MAX_TTL_SECONDS, VERIFIER_ID
from universal.core import GuardError, Intent, Runtime, canonical, digest
from universal.gates import CRITERIA, GateEngine
from universal.protocol import ProtocolError, VERSION


class ConsentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.sqlite"
        self.now = [1000.0]
        self.rt = Runtime(self.path, clock=lambda: self.now[0])
        self.rt.put_resource("input", "alpha")
        self.rt.put_resource("output", "")
        self.rt.add_task("T", "input", "output", "uppercase", digest("ALPHA"))
        self.claim = self.rt.claim("owner")
        self.rt.execute(Intent(self.claim["run_id"], "artifact.write", "output", 1,
                               "artifact-effect", self.claim["fence"], {"content": "ALPHA"}), self.claim["token"])
        self.environment = environment_identity()
        self.proof = self.rt.verify("T", self.environment)
        self.gate = GateEngine(self.rt)
        self.verifiers = self.gate.register_synthetic_verifiers()
        self.authority = ConsentAuthority(self.gate)
        self.verifiers["consent"] = VERIFIER_ID
        self.contract = self.new_contract()

    def tearDown(self):
        self.rt.close()
        self.temp.cleanup()

    def new_contract(self, environment=None):
        return self.gate.define_contract("T", self.claim["run_id"], self.proof["evidence"],
                                         environment or self.environment, self.verifiers)

    def observation(self, consent_id):
        return {"executed": True, "artifact_sha": digest("ALPHA"), "consent_id": consent_id}

    def check(self, consent_id, contract=None):
        return self.gate.run_check(contract or self.contract, "consent", self.observation(consent_id))

    def grant(self, contract=None, expiry=1100.0):
        return self.authority.grant(contract or self.contract, expires_at=expiry)

    def other_fixture_checks(self):
        values = {"tests": {"cases": [True]}, "licenses": {"licenses": ["MIT"], "allowed": ["MIT"]},
                  "secrets": {"artifact_content": "ALPHA", "forbidden_markers": ["FIXTURE_CANARY"]},
                  "provenance": {"source": {"id": "input", "version": 1, "sha": digest("alpha"), "origin": "owner_fixture"}},
                  "environment": {"environment": self.environment}}
        for criterion in CRITERIA - {"consent"}:
            self.gate.run_check(self.contract, criterion,
                                {"executed": True, "artifact_sha": digest("ALPHA"), **values[criterion]})

    def accepted(self):
        return self.gate.evaluate(self.contract, self.environment)["accepted"]

    def test_explicit_owner_receipt_accepts_only_consent_with_other_fixture_checks(self):
        receipt = self.grant()
        self.assertEqual(self.check(receipt)["outcome"], "PASS")
        self.assertFalse(self.accepted())  # Five checks cannot be omitted.
        self.other_fixture_checks()
        self.assertTrue(self.accepted())
        self.assertTrue(self.rt.check_journal())

    def test_worker_approval_boolean_cannot_replace_an_owner_record(self):
        result = self.gate.run_check(self.contract, "consent",
                                     {"executed": True, "artifact_sha": digest("ALPHA"),
                                      "approved": True, "scope": "local_validation_only", "expires_at": 1100.0})
        self.assertEqual(result["outcome"], "UNKNOWN")
        self.assertFalse(self.accepted())

    def test_extra_claimed_pass_or_publish_scope_is_not_a_receipt(self):
        receipt = self.grant()
        for extra in ({"approved": True}, {"outcome": "PASS"}, {"scope": "publish"}):
            with self.subTest(extra=extra):
                result = self.gate.run_check(self.contract, "consent", {**self.observation(receipt), **extra})
                self.assertEqual(result["outcome"], "UNKNOWN")

    def test_missing_invalid_and_unknown_receipts_never_pass(self):
        for receipt in ("missing-receipt", "../receipt", None, [], True):
            with self.subTest(receipt=receipt):
                self.assertNotEqual(self.check(receipt)["outcome"], "PASS")

    def test_wrong_artifact_and_unexecuted_check_never_pass(self):
        receipt = self.grant()
        for change, outcome in (({"artifact_sha": "0" * 64}, "FAIL"), ({"executed": False}, "UNKNOWN")):
            result = self.gate.run_check(self.contract, "consent", {**self.observation(receipt), **change})
            self.assertEqual(result["outcome"], outcome)

    def test_receipt_for_identical_bytes_cannot_cross_contracts(self):
        receipt = self.grant()
        self.assertEqual(self.check(receipt, self.new_contract())["outcome"], "FAIL")

    def test_expiry_boundary_invalidates_existing_attestation(self):
        receipt = self.grant()
        self.check(receipt)
        self.other_fixture_checks()
        self.assertTrue(self.accepted())
        self.now[0] = 1100.0
        self.assertFalse(self.accepted())
        self.assertEqual(self.check(receipt)["outcome"], "STALE")

    def test_clock_rollback_invalidates_existing_check_and_new_consent_check(self):
        receipt = self.grant()
        self.check(receipt)
        self.other_fixture_checks()
        self.now[0] = 999.0
        self.assertFalse(self.accepted())
        self.assertEqual(self.check(receipt)["outcome"], "STALE")

    def test_invalid_expiry_never_creates_a_record(self):
        for expiry in (True, None, "1100", float("nan"), float("inf"), 999.0, 1000.0,
                       1000.0 + MAX_TTL_SECONDS + 1):
            with self.subTest(expiry=expiry), self.assertRaises(GuardError):
                self.grant(expiry=expiry)
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM owner_consents").fetchone()[0], 0)

    def test_maximum_bounded_expiry_is_accepted(self):
        self.assertEqual(self.check(self.grant(expiry=1000.0 + MAX_TTL_SECONDS))["outcome"], "PASS")

    def test_revocation_invalidates_signed_pass_and_prevents_new_pass(self):
        receipt = self.grant()
        self.check(receipt)
        self.other_fixture_checks()
        self.assertTrue(self.accepted())
        self.assertTrue(self.authority.revoke(receipt))
        self.assertFalse(self.accepted())
        self.assertFalse(self.authority.revoke(receipt))
        self.assertEqual(self.check(receipt)["outcome"], "FAIL")
        self.assertTrue(self.rt.check_journal())

    def test_unknown_receipt_cannot_be_revoked(self):
        with self.assertRaises(GuardError):
            self.authority.revoke("unknown")

    def test_revoking_one_receipt_conservatively_requires_a_new_check_for_another(self):
        first, second = self.grant(), self.grant()
        self.check(second)
        self.other_fixture_checks()
        self.authority.revoke(first)
        self.assertFalse(self.accepted())
        self.assertEqual(self.check(second)["outcome"], "PASS")
        self.assertTrue(self.accepted())

    def test_consent_records_and_revocations_are_immutable(self):
        receipt = self.grant()
        self.authority.revoke(receipt)
        for operation in ("DELETE FROM owner_consents", "UPDATE owner_consents SET id=id",
                          "DELETE FROM owner_consent_revocations", "UPDATE owner_consent_revocations SET id=id"):
            with self.subTest(operation=operation), self.assertRaises(sqlite3.IntegrityError):
                self.rt.db.execute(operation)

    def test_fake_signature_cannot_certify_an_owner_decision(self):
        receipt = self.grant()
        row = self.rt.db.execute("SELECT * FROM owner_consents WHERE id=?", (receipt,)).fetchone()
        body = json.loads(row["body"])
        body["consent_id"] = "forged"
        self.rt.db.execute("INSERT INTO owner_consents VALUES(?,?,?,?,?)",
                           ("forged", self.contract, row["epoch"], canonical(body), "0" * 64))
        self.assertEqual(self.check("forged")["outcome"], "FAIL")

    def test_wrong_scope_even_in_signed_owner_record_does_not_authorize_publication(self):
        receipt = self.grant()
        row = self.rt.db.execute("SELECT * FROM owner_consents WHERE id=?", (receipt,)).fetchone()
        key = self.gate._key()
        body = json.loads(row["body"])
        body.update(consent_id="wrong-scope", scope="publish")
        self.rt.db.execute("INSERT INTO owner_consents VALUES(?,?,?,?,?)",
                           ("wrong-scope", self.contract, key["epoch"], canonical(body), self.gate._signature(key["secret"], body)))
        self.assertEqual(self.check("wrong-scope")["outcome"], "FAIL")

    def test_environment_drift_between_contract_and_grant_is_rejected(self):
        with patch("universal.broker.environment_identity", return_value="changed-environment"):
            with self.assertRaises(GuardError):
                self.grant()

    def test_synthetic_consent_contract_cannot_receive_real_owner_receipt(self):
        verifiers = {**self.verifiers, "consent": "synthetic-consent"}
        contract = self.gate.define_contract("T", self.claim["run_id"], self.proof["evidence"], self.environment, verifiers)
        with self.assertRaises(GuardError):
            self.grant(contract)

    def test_output_version_drift_refuses_new_receipt_even_with_same_bytes(self):
        receipt = self.grant()
        self.rt.put_resource("output", "ALPHA", 2)
        with self.assertRaises(GuardError):
            self.check(receipt)
        with self.assertRaises(GuardError):
            self.grant()

    def test_source_version_drift_refuses_receipt_and_existing_attestation(self):
        receipt = self.grant()
        self.check(receipt)
        self.other_fixture_checks()
        self.rt.put_resource("input", "alpha", 1)
        self.assertFalse(self.accepted())
        with self.assertRaises(GuardError):
            self.grant()

    def test_revocation_before_first_attestation_never_allows_a_pass(self):
        receipt = self.grant()
        self.authority.revoke(receipt)
        self.assertEqual(self.check(receipt)["outcome"], "FAIL")

    def test_owner_transaction_and_module_drift_are_rechecked_before_signing(self):
        receipt = self.grant()
        original = self.gate._runner_current
        calls = [0]
        def drift(verifier_id, runner, registration):
            calls[0] += 1
            return False if calls[0] == 2 else original(verifier_id, runner, registration)
        with patch.object(self.gate, "_runner_current", side_effect=drift), self.assertRaises(GuardError):
            self.check(receipt)
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM gate_attestations WHERE criterion='consent'").fetchone()[0], 0)

    def test_signer_rotation_invalidates_the_consent_contract(self):
        receipt = self.grant()
        self.check(receipt)
        self.other_fixture_checks()
        self.gate.rotate_signing_key()
        self.assertFalse(self.accepted())
        with self.assertRaises(GuardError):
            self.check(receipt)

    def test_receipt_survives_restart_and_revocation_survives_backup_restore(self):
        receipt = self.grant()
        self.check(receipt)
        self.other_fixture_checks()
        with Runtime(self.path, clock=lambda: self.now[0]) as reopened:
            gate = GateEngine(reopened)
            authority = ConsentAuthority(gate)
            self.assertTrue(gate.evaluate(self.contract, self.environment)["accepted"])
            self.assertEqual(gate.run_check(self.contract, "consent", self.observation(receipt))["outcome"], "PASS")
            authority.revoke(receipt)
            backup = Path(self.temp.name) / "backup.sqlite"
            reopened.backup(backup)
        with Runtime(backup, clock=lambda: self.now[0]) as restored:
            gate = GateEngine(restored)
            ConsentAuthority(gate)
            self.assertFalse(gate.evaluate(self.contract, self.environment)["accepted"])
            self.assertEqual(gate.run_check(self.contract, "consent", self.observation(receipt))["outcome"], "FAIL")

    def test_restarted_gate_without_loaded_verifier_cannot_create_new_positive_attestation(self):
        receipt = self.grant()
        with Runtime(self.path, clock=lambda: self.now[0]) as reopened:
            gate = GateEngine(reopened)
            result = gate.run_check(self.contract, "consent", self.observation(receipt))
            self.assertEqual(result["outcome"], "UNKNOWN")

    def test_revocation_between_capture_and_signing_is_seen_by_transactional_lookup(self):
        receipt = self.grant()
        with Runtime(self.path, clock=lambda: self.now[0]) as other:
            other_authority = ConsentAuthority(GateEngine(other))
            original = self.gate._runner_current
            count = [0]
            def interleave(verifier_id, runner, registration):
                count[0] += 1
                if count[0] == 1:
                    other_authority.revoke(receipt)
                return original(verifier_id, runner, registration)
            with patch.object(self.gate, "_runner_current", side_effect=interleave):
                self.assertEqual(self.check(receipt)["outcome"], "FAIL")
            self.assertEqual(count[0], 2)

    def test_lookup_and_attestation_signing_hold_the_same_sqlite_writer_lock(self):
        receipt = self.grant()
        contender = sqlite3.connect(self.path, timeout=0, isolation_level=None)
        blocked = []
        def observe(statement):
            if statement.startswith("SELECT * FROM owner_consents WHERE"):
                try:
                    contender.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as error:
                    blocked.append("locked" in str(error))
                else:
                    contender.execute("ROLLBACK")
                    blocked.append(False)
        self.rt.db.set_trace_callback(observe)
        try:
            self.assertEqual(self.check(receipt)["outcome"], "PASS")
            self.assertEqual(blocked, [True])
        finally:
            self.rt.db.set_trace_callback(None)
            contender.close()

    def test_transactional_execution_mode_cannot_be_changed_without_new_registration(self):
        row = self.rt.db.execute("SELECT method FROM gate_verifiers WHERE id=?", (VERIFIER_ID,)).fetchone()
        with self.assertRaises(GuardError):
            self.gate.register_verifier(VERIFIER_ID, row["method"], {"consent"}, self.authority.check, transactional=False)

    def test_implementation_helper_drift_refuses_grant_and_positive_check(self):
        receipt = self.grant()
        with patch("universal.consent.implementation_identity", return_value="0" * 64):
            with self.assertRaises(GuardError):
                self.grant()
            self.assertNotEqual(self.check(receipt)["outcome"], "PASS")

    def test_direct_runner_call_outside_owner_transaction_does_not_pass(self):
        receipt = self.grant()
        context = self.gate.contract_context(self.contract)
        result = self.authority.check(self.observation(receipt), context, self.now[0])
        self.assertEqual(result.outcome, "UNKNOWN")

    def test_no_worker_opcode_can_grant_revoke_or_choose_consent(self):
        worker = WorkerGate(self.rt, self.claim)
        for index, operation in enumerate(("consent.grant", "consent.revoke", "consent", "approve"), start=1):
            with self.subTest(operation=operation), self.assertRaises((GuardError, ProtocolError)):
                worker.handle({"version": VERSION, "request_id": index,
                               "job_id": self.claim["run_id"], "op": operation})
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM owner_consents").fetchone()[0], 0)

    def test_consent_journal_metadata_contains_no_artifact_body_or_signing_secret(self):
        self.grant()
        journal = " ".join(row[0] for row in self.rt.db.execute("SELECT metadata FROM events WHERE action='consent.grant'"))
        key = self.gate._key()["secret"]
        self.assertNotIn("ALPHA", journal)
        self.assertNotIn(key.hex(), journal)


if __name__ == "__main__":
    unittest.main()
