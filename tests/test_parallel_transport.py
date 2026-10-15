"""Routing/provenance tests; MissionClient mocks are not sandbox evidence."""
import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import run_public_mission as adapter
from universal.core import GuardError
from universal.mission_contracts import canonical
from tests.test_mission_cli import request
from tests.test_public_mission_transport import FakeProvider


class ParallelTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="coguni-parallel-transport-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pin, self.first, self.second = "a" * 40, "b" * 40, "c" * 40
        self.branch = "work/mvp-mission-transport-parallel-A"
        self.context = {"request_commit": self.second, "ref": "refs/heads/" + self.branch}
        self.req = request(owner="265171248")
        self.expected = b"SYNTHETIC:ALPHA"
        self.path = self.root / adapter.REQUEST
        self.path.parent.mkdir(parents=True)
        target = self.root / adapter.TARGETS / "synthetic-A/result.txt"
        target.parent.mkdir(parents=True)
        target.write_bytes(self.expected)
        self.predecessor = {"request_commit": self.first, "provider_run_id": 44,
                            "artifact_sha256": hashlib.sha256(self.expected).hexdigest()}
        self.run = {"head_sha": self.first, "conclusion": "success", "status": "completed",
                    "head_branch": self.branch, "event": "push", "repository": {"id": 1418009675},
                    "actor": {"id": 265171248}, "path": ".github/workflows/ci.yml"}
        self.jobs = {"total_count": 1, "jobs": [{"name": "sandbox-runtime", "head_sha": self.first,
                     "conclusion": "success", "steps": [{
                     "name": "Process an owner public synthetic mission on the qualified host",
                     "status": "completed", "conclusion": "success"}]}]}

    def packet(self, project="synthetic-A", mode="INDEPENDENT", predecessor=None):
        req = request(project=project, owner="265171248")
        return {"schema_version": 2, "request": req, "predecessor": predecessor, "mode": mode}

    def run_mock_client(self, packet, *, reject=False):
        self.path.write_bytes(canonical(packet))
        out = self.root / "receipt.json"
        with patch.object(adapter, "ROOT", self.root), \
             patch.object(adapter, "provider_context", return_value=self.context), \
             patch.object(adapter, "verify_code_pin"), \
             patch.object(adapter, "git", return_value=b""), \
             patch.object(adapter, "MissionClient") as constructor:
            client = constructor.return_value.__enter__.return_value
            client.execute.return_value = {"state": "COMPLETED", "artifact": {"accepted_for_gate": True}}
            if reject:
                with self.assertRaises(GuardError):
                    adapter.run(adapter.REQUEST, out)
                constructor.assert_not_called()
                self.assertFalse(out.exists())
                return
            # Mock receipts must never resemble live provider evidence in CI.
            with redirect_stdout(io.StringIO()):
                result = adapter.run(adapter.REQUEST, out)
            client.submit.assert_called_once_with(packet["request"])
            env = packet["request"]["envelope"]
            client.execute.assert_called_once_with(env["project"]["id"], env["mission_id"])
            self.assertEqual(json.loads(out.read_text()), result)
            return result

    def check_predecessor(self, *, run=None, jobs=None, old=None, prior_target=b""):
        provider = FakeProvider(self.run if run is None else run,
                                self.jobs if jobs is None else jobs)
        first = self.packet() if old is None else old
        def observed_git(*args):
            return canonical(first) if args[1].endswith(":" + adapter.REQUEST) else prior_target
        with patch.object(adapter, "ROOT", self.root), patch.object(adapter, "_fetch_commit"), \
             patch.object(adapter, "git", side_effect=observed_git), \
             patch.object(adapter, "verify_code_pin"), \
             patch.object(adapter.urllib.request, "build_opener", return_value=provider):
            return adapter.verify_predecessor(self.predecessor, self.context, self.pin)

    def test_v2_independent_a_and_b_keep_existing_client_and_inert_receipt(self):
        for project in ("synthetic-A", "synthetic-B"):
            with self.subTest(project=project):
                receipt = self.run_mock_client(self.packet(project))
                self.assertEqual(receipt["schema_version"], 2)
                self.assertEqual(receipt["mode"], "INDEPENDENT")
                self.assertIsNone(receipt["predecessor"])
                self.assertFalse(receipt["target_applied_by_coguni"])
                self.assertFalse(receipt["chat_connected"])
                self.assertFalse(receipt["persistent_service"])

    def test_v1_b_without_predecessor_still_refuses_and_a_receipt_is_unchanged(self):
        b = self.packet("synthetic-B")
        b["schema_version"] = 1; del b["mode"]
        self.run_mock_client(b, reject=True)
        a = self.packet()
        a["schema_version"] = 1; del a["mode"]
        receipt = self.run_mock_client(a)
        self.assertNotIn("schema_version", receipt)
        self.assertNotIn("mode", receipt)

    def test_v2_rejects_unknown_versions_modes_and_additional_fields(self):
        cases = []
        for version in (True, 3, "2", 2.0):
            packet = self.packet(); packet["schema_version"] = version
            cases.append(packet)
        for mode in (None, True, "independent", "", ["INDEPENDENT"]):
            packet = self.packet(); packet["mode"] = mode
            cases.append(packet)
        extra = self.packet(); extra["owner_command"] = "ignored"
        cases.append(extra)
        missing = self.packet(); del missing["mode"]
        cases.append(missing)
        for packet in cases:
            with self.subTest(packet=packet):
                self.run_mock_client(packet, reject=True)

    def test_v2_dependency_shapes_refuse_before_dispatch(self):
        for packet in (self.packet("synthetic-A", predecessor=self.predecessor),
                       self.packet("synthetic-B", predecessor=self.predecessor),
                       self.packet("synthetic-B", mode="DEPENDENT"),
                       self.packet("synthetic-A", mode="DEPENDENT", predecessor=self.predecessor),
                       self.packet("another-project")):
            with self.subTest(packet=packet):
                self.run_mock_client(packet, reject=True)

    def test_v2_predecessor_requires_a_applied_readback_and_changed_base(self):
        accepted = self.check_predecessor()
        self.assertEqual(accepted["state"], "ACCEPTED_SCOPED_PUBLIC_FIXTURE")
        target = self.root / adapter.TARGETS / "synthetic-A/result.txt"
        target.write_bytes(b"")
        with self.assertRaises(GuardError):
            self.check_predecessor()
        target.write_bytes(self.expected)
        first = self.packet()
        first["request"]["envelope"]["project"]["base_version"] = hashlib.sha256(self.expected).hexdigest()
        with self.assertRaises(GuardError):
            self.check_predecessor(old=first, prior_target=self.expected)

    def test_v2_predecessor_cross_branch_commit_run_and_code_spoofs_refuse(self):
        for field, value in (("head_branch", "work/mvp-mission-transport-parallel-B"),
                             ("head_sha", self.second), ("actor", {"id": 1}),
                             ("repository", {"id": 1}), ("event", "pull_request"),
                             ("status", "in_progress"), ("conclusion", "cancelled")):
            with self.subTest(field=field), self.assertRaises(GuardError):
                self.check_predecessor(run={**self.run, field: value})
        changed = self.packet(); changed["request"]["code_ref"] = self.second
        with self.assertRaises(GuardError):
            self.check_predecessor(old=changed)
        missing_step = copy.deepcopy(self.jobs); missing_step["jobs"][0]["steps"] = []
        with self.assertRaises(GuardError):
            self.check_predecessor(jobs=missing_step)

    def test_v2_predecessor_cannot_be_b_or_dependent_or_malformed_packet(self):
        first = self.packet("synthetic-B")
        dependent = self.packet(mode="DEPENDENT", predecessor=self.predecessor)
        extra = self.packet(); extra["extra"] = "data"
        for old in (first, dependent, extra):
            with self.subTest(old=old), self.assertRaises(GuardError):
                self.check_predecessor(old=old)

    def test_v2_d_cannot_execute_before_a_readback_or_cross_branch_qualification(self):
        packet = self.packet("synthetic-B", mode="DEPENDENT", predecessor=self.predecessor)
        self.path.write_bytes(canonical(packet))
        target = self.root / adapter.TARGETS / "synthetic-A/result.txt"
        for applied, branch in ((False, self.branch), (True, "work/mvp-mission-transport-parallel-B")):
            target.write_bytes(self.expected if applied else b"")
            provider = FakeProvider({**self.run, "head_branch": branch}, self.jobs)
            def observed_git(*args):
                return canonical(self.packet()) if args[1].endswith(":" + adapter.REQUEST) else b""
            with self.subTest(applied=applied, branch=branch), patch.object(adapter, "ROOT", self.root), \
                 patch.object(adapter, "provider_context", return_value=self.context), \
                 patch.object(adapter, "verify_code_pin"), patch.object(adapter, "_fetch_commit"), \
                 patch.object(adapter, "git", side_effect=observed_git), \
                 patch.object(adapter.urllib.request, "build_opener", return_value=provider), \
                 patch.object(adapter, "MissionClient") as client, self.assertRaises(GuardError):
                adapter.run(adapter.REQUEST, self.root / "receipt.json")
            client.assert_not_called()

    def test_v2_dependent_routes_to_existing_verifier_and_records_mode(self):
        packet = self.packet("synthetic-B", mode="DEPENDENT", predecessor=self.predecessor)
        accepted = self.check_predecessor()
        with patch.object(adapter, "verify_predecessor", return_value=accepted) as gate:
            receipt = self.run_mock_client(packet)
        gate.assert_called_once_with(self.predecessor, self.context, self.pin)
        self.assertEqual(receipt["mode"], "DEPENDENT")
        self.assertEqual(receipt["predecessor"], accepted)


if __name__ == "__main__":
    unittest.main()
