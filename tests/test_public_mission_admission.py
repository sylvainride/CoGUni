"""Provider transitions on real Git trees; no worker or external effect."""
from contextlib import ExitStack, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from tools import run_public_mission as adapter
from tests.test_mission_cli import request
from universal.core import GuardError
from universal.mission_contracts import canonical


class PublicMissionAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="coguni-push-admission-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        for project in ("synthetic-A", "synthetic-B"):
            self.write(adapter.TARGETS + "/" + project + "/result.txt", b"")
        self.write("source.py", b"# immutable fixture code\n")
        self.pin = self.commit()
        self.path = self.root / adapter.REQUEST
        self.out = self.root / "receipt.json"
        self.env = {"GITHUB_REPOSITORY": "sylvainride/CoGUni", "GITHUB_REPOSITORY_ID": "1418009675",
                    "GITHUB_REPOSITORY_OWNER_ID": "265171248", "GITHUB_ACTOR_ID": "265171248",
                    "GITHUB_SERVER_URL": "https://github.com", "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REF": "refs/heads/work/mvp-mission-transport-passe3-fixture",
                    "GITHUB_RUN_ID": "55", "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_EVENT_PATH": str(self.root / "event.json")}

    def git(self, *args):
        # Only network fetch is replaced. All ancestry, modes, blobs and diffs
        # are observed with actual Git, including counterexamples.
        if args[0] == "-c" and "fetch" in args:
            return b""
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.DEVNULL)

    def write(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def commit(self):
        self.git("add", "--", "source.py", "tests")
        self.git("commit", "-qm", "isolated fixture transition", "--allow-empty")
        return self.git("rev-parse", "HEAD").decode().strip()

    def packet(self, **kwargs):
        now = int(time.time())
        req = request(owner="265171248", now=now, expires=now + 600, **kwargs)
        req["code_ref"] = self.pin
        return {"schema_version": 2, "mode": "INDEPENDENT", "request": req, "predecessor": None}

    def submit_commit(self, packet=None):
        self.write(adapter.REQUEST, canonical(self.packet() if packet is None else packet))
        return self.commit()

    def event(self, before, after):
        return {"before": before, "after": after, "ref": self.env["GITHUB_REF"],
                "created": before == "0" * 40, "deleted": False, "forced": False,
                "repository": {"id": 1418009675, "full_name": "sylvainride/CoGUni",
                               "owner": {"id": 265171248, "login": "sylvainride"}},
                "sender": {"id": 265171248}, "head_commit": {"id": after}}

    def invoke(self, before, after, *, event=None, observe=False):
        data = self.event(before, after) if event is None else event
        (self.root / "event.json").write_text(json.dumps(data))
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {**self.env, "GITHUB_SHA": after}, clear=True))
            stack.enter_context(patch.object(adapter, "ROOT", self.root))
            stack.enter_context(patch.object(adapter, "git", side_effect=self.git))
            stack.enter_context(redirect_stdout(io.StringIO()))
            if observe:
                return adapter.observe_push_transition(adapter.provider_context())
            return adapter.run(adapter.REQUEST, self.out)

    def test_new_request_enters_existing_client_once_and_cas_never_dispatches(self):
        first = self.submit_commit()
        with patch.object(adapter.MissionClient, "execute", return_value={
                "state": "COMPLETED", "artifact": {"accepted_for_gate": True}}) as execute:
            result = self.invoke(self.pin, first)
        execute.assert_called_once_with("synthetic-A", "m-1")
        self.assertEqual(result["state"], "RESULT_READY")
        self.write(adapter.TARGETS + "/synthetic-A/result.txt", b"SYNTHETIC:ALPHA")
        cas = self.commit()
        with patch.object(adapter, "MissionClient") as client, patch.object(adapter, "verify_predecessor") as predecessor:
            result = self.invoke(first, cas)
        client.assert_not_called()
        predecessor.assert_not_called()
        self.assertEqual(result["state"], "SKIPPED_UNCHANGED_REQUEST")
        self.assertFalse(result["business_executed"])
        self.assertFalse(result["target_applied_by_coguni"])
        self.assertNotIn("result", result)

    def test_new_stale_malformed_or_expired_request_is_never_a_skip(self):
        self.write(adapter.TARGETS + "/synthetic-A/result.txt", b"applied")
        base = self.commit()
        expired = self.packet()
        expired["request"]["envelope"]["created_unix"] = 1
        expired["request"]["envelope"]["expires_unix"] = 2
        wrong_source = self.packet()
        wrong_source["request"]["envelope"]["source_sha256"] = "f" * 64
        for packet in (self.packet(), expired, wrong_source, {"schema_version": 99}):
            after = self.submit_commit(packet)
            self.out.unlink(missing_ok=True)
            with self.subTest(packet=packet), patch.object(adapter.MissionClient, "execute") as execute:
                with self.assertRaises((GuardError, ValueError)):
                    self.invoke(base, after)
                execute.assert_not_called()
                self.assertFalse(self.out.exists())
            base = after

    def test_target_and_new_packet_together_are_a_new_admission(self):
        first = self.submit_commit()
        self.write(adapter.TARGETS + "/synthetic-A/result.txt", b"applied")
        packet = self.packet(project="synthetic-B", mission="new-b")
        second = self.submit_commit(packet)
        self.assertEqual(self.invoke(first, second, observe=True)["state"], "NEW_REQUEST")
        with patch.object(adapter.MissionClient, "execute", return_value={
                "state": "COMPLETED", "artifact": {"accepted_for_gate": True}}) as execute:
            result = self.invoke(first, second)
        execute.assert_called_once_with("synthetic-B", "new-b")
        self.assertEqual(result["state"], "RESULT_READY")

    def test_every_commit_is_inspected_including_restore_revert_and_same_blob(self):
        first = self.submit_commit()
        self.path.unlink(); self.commit()
        restored = self.submit_commit()
        self.assertEqual(self.invoke(first, restored, observe=True)["state"], "NEW_REQUEST")
        original = self.path.read_bytes()
        self.submit_commit(self.packet(mission="changed"))
        self.path.write_bytes(original); reverted = self.commit()
        self.assertEqual(self.invoke(restored, reverted, observe=True)["state"], "NEW_REQUEST")
        same = self.commit()
        self.assertEqual(self.invoke(reverted, same, observe=True)["state"], "SKIPPED_UNCHANGED_REQUEST")

    def test_deletion_absence_and_branch_creation_without_packet_are_neutral(self):
        first = self.submit_commit()
        self.path.unlink(); deleted = self.commit()
        with patch.object(adapter, "MissionClient") as client:
            self.assertEqual(self.invoke(first, deleted)["state"], "NOT_SUBMITTED")
            self.assertEqual(self.invoke("0" * 40, deleted)["state"], "NOT_SUBMITTED")
        client.assert_not_called()
        empty = self.commit()
        self.assertEqual(self.invoke(deleted, empty)["state"], "NOT_SUBMITTED")

    def test_branch_copy_with_packet_and_empty_range_refuse(self):
        first = self.submit_commit()
        for before in ("0" * 40, first):
            with self.subTest(before=before), self.assertRaises(GuardError):
                self.invoke(before, first)

    def test_provider_mismatch_missing_event_and_rewrite_refuse_before_client(self):
        first = self.submit_commit()
        good = self.event(self.pin, first)
        for key, value in (("before", "x" * 40), ("after", self.pin), ("ref", "refs/heads/main"),
                           ("forced", True), ("deleted", True), ("created", True),
                           ("sender", {"id": 1}), ("repository", {"id": 1}),
                           ("head_commit", {"id": self.pin})):
            with self.subTest(key=key), patch.object(adapter, "MissionClient") as client, self.assertRaises(GuardError):
                self.invoke(self.pin, first, event={**good, key: value})
            client.assert_not_called()
        for key in good:
            event = copy.deepcopy(good); del event[key]
            with self.subTest(missing=key), self.assertRaises(GuardError):
                self.invoke(self.pin, first, event=event)
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(GuardError):
            adapter.observe_push_transition({})

    def test_source_changes_cannot_hide_behind_skip_new_or_deleted_packet(self):
        first = self.submit_commit()
        self.write("source.py", b"# substituted\n")
        changed = self.commit()
        with self.assertRaises(GuardError):
            self.invoke(first, changed)
        new = self.submit_commit(self.packet(mission="other"))
        with self.assertRaises(GuardError):
            self.invoke(first, new)
        # Even if only this push changed inert data, the cumulative code pin
        # still rejects a source substitution introduced by an earlier push.
        same = self.commit()
        with self.assertRaises(GuardError):
            self.invoke(new, same)
        self.path.unlink(); deleted = self.commit()
        with self.assertRaises(GuardError):
            self.invoke(first, deleted)

    def test_checkout_blob_symlink_and_executable_mode_refuse(self):
        first = self.submit_commit()
        self.path.write_bytes(b"substituted checkout")
        with self.assertRaises(GuardError):
            self.invoke(self.pin, first)
        self.path.unlink(); self.path.symlink_to("/etc/passwd")
        linked = self.commit()
        with self.assertRaises(GuardError):
            self.invoke(first, linked)
        self.path.unlink(); executable = self.submit_commit()
        self.path.chmod(0o755); executable = self.commit()
        with self.assertRaises(GuardError):
            self.invoke(first, executable)

    def test_nonancestor_merge_and_unavailable_history_refuse(self):
        first = self.submit_commit()
        self.git("checkout", "-qb", "side", self.pin)
        side = self.submit_commit(self.packet(mission="side"))
        with self.assertRaises(GuardError):
            self.invoke(first, side)
        with self.assertRaises(GuardError):
            self.invoke("f" * 40, side)
        # Two-parent merges are deliberately outside this transport policy.
        self.git("checkout", "-qb", "merge-side", first)
        self.git("merge", "--no-commit", "-s", "ours", side)
        merge = self.commit()
        with self.assertRaises(GuardError):
            self.invoke(first, merge)

    def test_overlong_transition_fails_closed(self):
        first = self.submit_commit()
        for _ in range(65):
            last = self.commit()
        with self.assertRaises(GuardError):
            self.invoke(first, last)


if __name__ == "__main__":
    unittest.main()
