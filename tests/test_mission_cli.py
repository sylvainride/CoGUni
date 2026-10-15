"""Durable owner CLI contracts plus separate actual confined two-turn runs."""
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from universal.broker import environment_identity
from universal.core import GuardError, Intent, Runtime
from universal.mission_cli import MissionClient
from universal.mission_contracts import MissionContractError, canonical


def request(project="synthetic-A", mission="m-1", payload="synthetic:alpha", *, now=100,
            expires=1000, base=None, owner="fixture-owner", action="uppercase"):
    return {"envelope": {
        "schema_version": 1, "mission_id": mission, "idempotency_key": "key-" + project + "-" + mission,
        "project": {"kind": "local", "id": project, "owner": owner,
                    "base_version": base or hashlib.sha256(b"").hexdigest(),
                    "source_of_truth": "owner-synthetic-fixture"},
        "contract": {"task_id": "task-" + mission, "objective": "bounded synthetic string computation",
                     "allowed_actions": ["simulate"], "forbidden_actions": ["publish"],
                     "criteria": ["exact owner output and independent target readback"],
                     "dependencies": [], "max_attempts": 2, "max_duration_seconds": 60,
                     "max_external_cost": 0, "artifact_policy": "public_synthetic"},
        "created_unix": now, "expires_unix": expires,
        "source_sha256": hashlib.sha256(payload.encode()).hexdigest(), "privacy": "PUBLIC_SYNTHETIC",
    }, "payload": payload, "action": action, "code_ref": "a" * 40}


class CLIFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="coguni-mvp-cli-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "owner"
        self.targets = self.root / "targets"
        self.targets.mkdir(mode=0o700)
        for project in ("synthetic-A", "synthetic-B"):
            directory = self.targets / project
            directory.mkdir(mode=0o700)
            (directory / "result.txt").write_bytes(b"")
        self.now = 150
        self.client = MissionClient(self.state, self.targets, "fixture-owner", clock=lambda: self.now)
        self.addCleanup(self.client.close)

    def complete_owner_fixture(self, project="synthetic-A", mission="m-1"):
        """Owner-only exact oracle fixture: not a confinement validation."""
        row, req = self.client._loaded(project, mission)
        ex = self.client._executor()
        task_id = ex.task_id(row["id"], req["payload"], req["action"])
        with Runtime(ex.runtime_path) as runtime:
            claim = runtime.claim("test-owner-fixture", task_id=task_id, ttl=60)
            content = req["payload"].upper() if req["action"] == "uppercase" else hashlib.sha256(req["payload"].encode()).hexdigest()
            runtime.execute(Intent(claim["run_id"], "artifact.write", claim["task"]["output"],
                                   claim["output_version"], claim["run_id"] + ".write",
                                   claim["fence"], {"content": content}), claim["token"])
            runtime.verify(task_id, environment_identity(), expected_run_id=claim["run_id"])
        return ex.result(task_id)


class MissionCLIOwnerTests(CLIFixture, unittest.TestCase):
    def test_replay_and_conflict_preserve_one_admission_and_original_contract(self):
        req = request()
        first = self.client.submit(req)
        events = len(self.client.journal.events())
        replay = self.client.submit(copy.deepcopy(req))
        self.assertTrue(replay["replayed"])
        self.assertFalse(first["replayed"])
        self.assertEqual(replay["task_id"], first["task_id"])
        self.assertEqual(len(self.client.journal.events()), events)
        changed = request(payload="synthetic:changed")
        with self.assertRaises(GuardError):
            self.client.submit(changed)
        self.assertEqual(self.client.status("synthetic-A", "m-1")["source_sha256"], req["envelope"]["source_sha256"])
        self.assertTrue(self.client.journal.verify_chain())

    def test_owner_project_privacy_base_and_ttl_are_enforced(self):
        for req in (request(owner="other-owner"), request(project="real-project"),
                    request(base="f" * 64), request(expires=150)):
            with self.subTest(req=req), self.assertRaises((GuardError, MissionContractError)):
                self.client.submit(req)
        private = request(); private["envelope"]["privacy"] = "PRIVATE_OWNER"
        with self.assertRaises((GuardError, MissionContractError)):
            self.client.submit(private)
        self.client.submit(request())
        with MissionClient(self.state, self.targets, "other-owner", clock=lambda: self.now) as other:
            with self.assertRaises(GuardError):
                other.status("synthetic-A", "m-1")
        with self.assertRaises((GuardError, KeyError)):
            self.client.status("synthetic-B", "m-1")
        self.now = 1000
        self.assertEqual(self.client.status("synthetic-A", "m-1")["state"], "BLOCKED")
        with self.assertRaises((GuardError, MissionContractError)):
            self.client.execute("synthetic-A", "m-1")
        with self.assertRaises((GuardError, MissionContractError)):
            self.client.reconcile("synthetic-A", "m-1")

    def test_silent_active_status_poll_and_handoff_do_not_dispatch_or_fail_work(self):
        self.client.submit(request())
        with patch("universal.mission_executor.DeterministicExecutor.run") as execute:
            self.assertEqual(self.client.reconcile("synthetic-A", "m-1")["state"], "READY")
            execute.assert_not_called()
            first = self.client.execute("synthetic-A", "m-1")
            self.assertEqual(first["state"], "RUNNING")
            self.assertIsNone(first["artifact"])
            for _ in range(3):
                self.assertEqual(self.client.status("synthetic-A", "m-1")["state"], "RUNNING")
            attached = self.client.execute("synthetic-A", "m-1")
            self.assertIsNone(attached["artifact"])
            self.assertEqual(self.client.reconcile("synthetic-A", "m-1")["state"], "RUNNING")
            self.assertEqual(execute.call_count, 1)
            handoff = self.client.handoff("synthetic-A", "m-1")
            self.assertFalse(handoff["chat_wakeup_available"])
            self.assertFalse(handoff["persistent_service"])
            self.assertIn("reprise", handoff["message"])
            self.now += 61
            self.assertEqual(self.client.status("synthetic-A", "m-1")["state"], "SUSPECT")
            self.assertFalse(self.client.status("synthetic-A", "m-1")["effect_retry_authorized"])

    def test_ack_requires_computation_and_independent_target_readback(self):
        self.client.submit(request())
        expected = hashlib.sha256(b"SYNTHETIC:ALPHA").hexdigest()
        with self.assertRaises(GuardError):
            self.client.ack("synthetic-A", "m-1", artifact_sha256=expected)
        result = self.complete_owner_fixture()
        self.assertTrue(result["accepted_for_gate"])
        with self.assertRaises(GuardError):
            self.client.ack("synthetic-A", "m-1", artifact_sha256=result["output_sha256"])
        self.assertEqual((self.targets / "synthetic-A/result.txt").read_bytes(), b"")
        self.assertNotEqual(self.client.status("synthetic-A", "m-1")["state"], "ACCEPTED")
        (self.targets / "synthetic-A/result.txt").write_text(result["content"])
        with self.assertRaises(GuardError):
            self.client.ack("synthetic-A", "m-1", artifact_sha256="0" * 64)
        accepted = self.client.ack("synthetic-A", "m-1", artifact_sha256=result["output_sha256"])
        self.assertEqual(accepted["state"], "ACCEPTED")
        count = len(self.client.journal.events())
        replay = self.client.ack("synthetic-A", "m-1", artifact_sha256=result["output_sha256"])
        self.assertEqual(replay["state"], "ACCEPTED")
        self.assertEqual(len(self.client.journal.events()), count)
        (self.targets / "synthetic-A/result.txt").write_text("concurrent divergence after ACK")
        self.assertNotEqual(self.client.status("synthetic-A", "m-1")["state"], "ACCEPTED")
        with self.assertRaises(GuardError):
            self.client.ack("synthetic-A", "m-1", artifact_sha256=result["output_sha256"])
        self.client.revoke("synthetic-A", "m-1")
        self.assertEqual(self.client.status("synthetic-A", "m-1")["state"], "CANCELLED")
        self.assertIsNone(self.client.result("synthetic-A", "m-1")["artifact"])
        # A verified computation over a target already equal to its output
        # cannot prove that a target modification was performed this turn.
        (self.targets / "synthetic-B/result.txt").write_bytes(b"SYNTHETIC:ALPHA")
        self.client.submit(request(project="synthetic-B", mission="no-change", base=result["output_sha256"]))
        unchanged = self.complete_owner_fixture("synthetic-B", "no-change")
        with self.assertRaises(GuardError):
            self.client.ack("synthetic-B", "no-change", artifact_sha256=unchanged["output_sha256"])

    def test_expired_or_revoked_result_cannot_be_newly_accepted(self):
        self.client.submit(request())
        result = self.complete_owner_fixture()
        (self.targets / "synthetic-A/result.txt").write_text(result["content"])
        self.client.submit(request(project="synthetic-B", mission="m-2", expires=2000))
        revoked = self.complete_owner_fixture("synthetic-B", "m-2")
        (self.targets / "synthetic-B/result.txt").write_text(revoked["content"])
        self.now = 1000
        with self.assertRaises((GuardError, MissionContractError)):
            self.client.ack("synthetic-A", "m-1", artifact_sha256=result["output_sha256"])
        self.client.revoke("synthetic-B", "m-2")
        with self.assertRaises(GuardError):
            self.client.ack("synthetic-B", "m-2", artifact_sha256=revoked["output_sha256"])
        self.assertNotEqual(self.client.result("synthetic-B", "m-2")["state"], "ACCEPTED")
        self.assertIsNone(self.client.result("synthetic-B", "m-2")["artifact"])

    def test_cancel_and_source_tampering_prevent_dispatch(self):
        self.client.submit(request())
        self.client.cancel("synthetic-A", "m-1")
        with self.assertRaises(GuardError):
            self.client.execute("synthetic-A", "m-1")
        with self.assertRaises(GuardError):
            self.client.reconcile("synthetic-A", "m-1")
        self.client.submit(request(project="synthetic-B", mission="m-2"))
        row, _ = self.client._loaded("synthetic-B", "m-2")
        source = next(iter(row["contract"]["sources"]))
        Path(source).write_text("synthetic:forged")
        with self.assertRaises(GuardError):
            self.client.status("synthetic-B", "m-2")

    def test_two_processes_replay_one_authenticated_owner_admission(self):
        now = int(time.time())
        req = request(now=now, expires=now + 300)
        wire = canonical({"schema_version": 1, "method": "mission.submit", "params": req}).decode()
        cold_state = self.root / 'cold-owner'
        self.assertFalse(cold_state.exists())
        args = [sys.executable, "-B", "-m", "universal.mission_cli", "--state", str(cold_state),
                "--targets", str(self.targets), "--owner", "fixture-owner"]
        def invoke(_):
            return subprocess.run(args, input=wire, capture_output=True, text=True,
                                  cwd=Path(__file__).resolve().parents[1], timeout=20)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(invoke, range(2)))
        self.assertEqual([result.returncode for result in results], [0, 0],
                         [(result.stdout, result.stderr) for result in results])
        responses = [json.loads(result.stdout)["result"] for result in results]
        self.assertEqual(sum(not response["replayed"] for response in responses), 1)
        self.assertEqual(len({response["task_id"] for response in responses}), 1)
        with MissionClient(cold_state, self.targets, "fixture-owner") as observed:
            self.assertEqual(observed.journal.db.execute("SELECT count(*) FROM continuity_tasks").fetchone()[0], 1)


class MissionCLIIsolationTests(CLIFixture, unittest.TestCase):
    def test_crash_after_local_commit_reconciles_verifier_without_second_effect(self):
        import universal.broker as broker
        self.client.submit(request())
        real_launch = broker.launch
        def crash_before_verifier(role):
            if role == "verifier":
                raise OSError("injected owner failure after committed local output")
            return real_launch(role)
        with patch.object(broker, "launch", side_effect=crash_before_verifier):
            with self.assertRaises(OSError):
                self.client.execute("synthetic-A", "m-1")
        with Runtime(self.state / "runtime.sqlite") as runtime:
            self.assertEqual(runtime.db.execute("SELECT status FROM tasks").fetchone()[0], "RESULT_READY")
            self.assertEqual(runtime.db.execute("SELECT count(*) FROM effects").fetchone()[0], 1)
            self.assertEqual(runtime.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)
        with MissionClient(self.state, self.targets, "fixture-owner", clock=lambda: self.now) as resumed:
            recovered = resumed.reconcile("synthetic-A", "m-1")
            self.assertEqual(recovered["state"], "COMPLETED")
            self.assertTrue(recovered["artifact"]["accepted_for_gate"])
            self.assertEqual(resumed.reconcile("synthetic-A", "m-1")["run_id"], recovered["run_id"])
        with Runtime(self.state / "runtime.sqlite") as runtime:
            self.assertEqual(runtime.db.execute("SELECT count(*) FROM effects").fetchone()[0], 1)
            self.assertEqual(runtime.db.execute("SELECT count(*) FROM runs").fetchone()[0], 1)
            self.assertEqual(runtime.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 1)

    def test_actual_two_turn_loop_independent_application_and_ack_lost_replay(self):
        for project, mission, payload, action in (("synthetic-A", "m-1", "synthetic:alpha", "uppercase"),
                                                  ("synthetic-B", "m-2", "synthetic:beta", "sha256")):
            with self.subTest(project=project):
                self.client.submit(request(project, mission, payload, action=action))
                result = self.client.execute(project, mission)
                self.assertEqual(result["state"], "COMPLETED")
                artifact = result["artifact"]
                expected = payload.upper() if action == "uppercase" else hashlib.sha256(payload.encode()).hexdigest()
                self.assertTrue(artifact["accepted_for_gate"])
                self.assertEqual(artifact["content"], expected)
                target = self.targets / project / "result.txt"
                self.assertEqual(target.read_bytes(), b"")
                # The trusted Chat/client owner, separately from CoGUni, applies
                # and reads back the exact benign result to its synthetic target.
                target.write_text(expected)
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), artifact["output_sha256"])
                replay = self.client.execute(project, mission)
                self.assertEqual(replay["run_id"], result["run_id"])
                accepted = self.client.ack(project, mission, artifact_sha256=artifact["output_sha256"])
                self.assertEqual(accepted["state"], "ACCEPTED")
                replay = self.client.result(project, mission)
                self.assertEqual(replay["run_id"], accepted["run_id"])
                self.assertEqual(self.client.ack(project, mission, artifact_sha256=artifact["output_sha256"])["state"], "ACCEPTED")
        with Runtime(self.state / "runtime.sqlite") as runtime:
            self.assertEqual(runtime.db.execute("SELECT count(*) FROM effects").fetchone()[0], 2)
            self.assertEqual(runtime.db.execute("SELECT count(*) FROM runs").fetchone()[0], 2)

    def test_actual_completion_survives_client_restart_without_redispatch(self):
        self.client.submit(request())
        result = self.client.execute("synthetic-A", "m-1")
        with MissionClient(self.state, self.targets, "fixture-owner", clock=lambda: self.now) as resumed:
            readback = resumed.result("synthetic-A", "m-1")
            replay = resumed.execute("synthetic-A", "m-1")
            self.assertEqual(readback["run_id"], result["run_id"])
            self.assertEqual(replay["artifact"]["evidence_id"], result["artifact"]["evidence_id"])
        with Runtime(self.state / "runtime.sqlite") as runtime:
            self.assertEqual(runtime.db.execute("SELECT count(*) FROM effects").fetchone()[0], 1)

    def test_actual_completed_result_with_divergent_target_is_not_accepted(self):
        self.client.submit(request())
        result = self.client.execute("synthetic-A", "m-1")
        (self.targets / "synthetic-A/result.txt").write_text("unexpected concurrent target version")
        with self.assertRaises(GuardError):
            self.client.ack("synthetic-A", "m-1", artifact_sha256=result["artifact"]["output_sha256"])
        self.assertNotEqual(self.client.status("synthetic-A", "m-1")["state"], "ACCEPTED")
        self.assertEqual(self.client.execute("synthetic-A", "m-1")["run_id"], result["run_id"])


if __name__ == "__main__":
    unittest.main()
