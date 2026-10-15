"""Public adapter gates: synthetic provider fixtures, no network authority."""
import copy
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


class FakeProvider:
    def __init__(self, run, jobs):
        self.values = [json.dumps(run).encode(), json.dumps(jobs).encode()]
        self.requests = []

    def open(self, url, *, timeout):
        self.requests.append((url, timeout))
        return io.BytesIO(self.values.pop(0))


class PublicMissionTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="coguni-public-adapter-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pin = "a" * 40
        self.first = "b" * 40
        self.second = "c" * 40
        self.branch = "work/mvp-mission-transport-fixture"
        self.context = {"request_commit": self.second, "ref": "refs/heads/" + self.branch}
        self.req = request(owner="265171248")
        self.req["code_ref"] = self.pin
        self.expected = b"SYNTHETIC:ALPHA"
        target = self.root / adapter.TARGETS / "synthetic-A/result.txt"
        target.parent.mkdir(parents=True)
        target.write_bytes(self.expected)
        self.predecessor = {"request_commit": self.first, "provider_run_id": 44,
                            "artifact_sha256": hashlib.sha256(self.expected).hexdigest()}
        self.run = {"head_sha": self.first, "conclusion": "success", "status": "completed",
                    "head_branch": self.branch, "event": "push", "repository": {"id": 1418009675},
                    "actor": {"id": 265171248}, "path": ".github/workflows/ci.yml"}
        self.jobs = {"total_count": 1, "jobs": [{"name": "sandbox-runtime", "head_sha": self.first,
                    "conclusion": "success", "steps": [{"name": "Process an owner public synthetic mission on the qualified host",
                    "status": "completed", "conclusion": "success"}]}]}

    def call_predecessor(self, *, run=None, jobs=None, req=None, predecessor=None, prior_target=b""):
        provider = FakeProvider(run or self.run, jobs or self.jobs)
        old = {"schema_version": 1, "request": req or self.req, "predecessor": None}
        def observed_git(*args):
            return canonical(old) if args[1].endswith(":" + adapter.REQUEST) else prior_target
        with patch.object(adapter, "ROOT", self.root), patch.object(adapter, "_fetch_commit"), \
             patch.object(adapter, "git", side_effect=observed_git), \
             patch.object(adapter, "verify_code_pin") as code_pin, \
             patch.object(adapter.urllib.request, "build_opener", return_value=provider):
            result = adapter.verify_predecessor(predecessor or self.predecessor, self.context, self.pin)
        return result, provider, code_pin

    def test_provider_requires_exact_repository_actor_branch_event_and_checkout(self):
        env = {"GITHUB_REPOSITORY": "sylvainride/CoGUni", "GITHUB_REPOSITORY_ID": "1418009675",
               "GITHUB_REPOSITORY_OWNER_ID": "265171248", "GITHUB_ACTOR_ID": "265171248",
               "GITHUB_SERVER_URL": "https://github.com", "GITHUB_EVENT_NAME": "push",
               "GITHUB_REF": "refs/heads/" + self.branch, "GITHUB_SHA": self.second,
               "GITHUB_RUN_ID": "55", "GITHUB_RUN_ATTEMPT": "1"}
        with patch.dict(adapter.os.environ, env, clear=True), patch.object(adapter, "git", return_value=(self.second + "\n").encode()):
            context = adapter.provider_context()
        self.assertEqual(context["repository_id"], 1418009675)
        self.assertEqual(context["actor_id"], 265171248)
        for key, bad in (("GITHUB_REPOSITORY", "another/CoGUni"),
                         ("GITHUB_REPOSITORY_ID", "12"), ("GITHUB_REPOSITORY_OWNER_ID", "13"),
                         ("GITHUB_ACTOR_ID", "14"), ("GITHUB_SERVER_URL", "https://elsewhere.invalid"),
                         ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REF", "refs/heads/main")):
            with self.subTest(key=key), patch.dict(adapter.os.environ, {**env, key: bad}, clear=True), \
                 patch.object(adapter, "git", return_value=(self.second + "\n").encode()), self.assertRaises(GuardError):
                adapter.provider_context()
        with patch.dict(adapter.os.environ, env, clear=True), patch.object(adapter, "git", return_value=(self.first + "\n").encode()), self.assertRaises(GuardError):
            adapter.provider_context()

    def test_code_pin_allows_only_three_inert_files_and_ordinary_target_modes(self):
        def git_valid(*args):
            if args[0] == "diff":
                return (adapter.REQUEST + "\n" + adapter.TARGETS + "/synthetic-A/result.txt\n").encode()
            return b"100644 blob deadbeef\tresult.txt\n"
        with patch.object(adapter, "_fetch_commit"), patch.object(adapter, "git", side_effect=git_valid):
            adapter.verify_code_pin(self.req, self.context)
        for changed in ("universal/mission_cli.py\n", ".github/workflows/ci.yml\n", "AGENTS.md\n"):
            with self.subTest(changed=changed), patch.object(adapter, "_fetch_commit"), \
                 patch.object(adapter, "git", return_value=changed.encode()), self.assertRaises(GuardError):
                adapter.verify_code_pin(self.req, self.context)
        def git_symlink(*args):
            return b"" if args[0] == "diff" else b"120000 blob deadbeef\tresult.txt\n"
        with patch.object(adapter, "_fetch_commit"), patch.object(adapter, "git", side_effect=git_symlink), self.assertRaises(GuardError):
            adapter.verify_code_pin(self.req, self.context)

    def test_b_requires_same_branch_exact_successful_sandbox_step_and_code_pin(self):
        good, provider, code_pin = self.call_predecessor()
        self.assertEqual(good["state"], "ACCEPTED_SCOPED_PUBLIC_FIXTURE")
        self.assertEqual(good["owner_readback_sha256"], self.predecessor["artifact_sha256"])
        self.assertEqual(provider.requests, [
            ("https://api.github.com/repos/sylvainride/CoGUni/actions/runs/44", 20),
            ("https://api.github.com/repos/sylvainride/CoGUni/actions/runs/44/jobs?per_page=100", 20)])
        code_pin.assert_called_once_with(self.req, {**self.context, "request_commit": self.first})
        for field, value in (("head_sha", self.second), ("status", "in_progress"),
                             ("conclusion", "failure"), ("head_branch", "work/another"),
                             ("event", "workflow_dispatch"), ("path", ".github/workflows/other.yml"),
                             ("repository", {"id": 12}), ("actor", {"id": 13})):
            with self.subTest(field=field), self.assertRaises(GuardError):
                self.call_predecessor(run={**self.run, field: value})
        malformed_jobs = []
        absent = copy.deepcopy(self.jobs); absent["jobs"][0]["steps"] = []
        malformed_jobs.append(absent)
        skipped = copy.deepcopy(self.jobs); skipped["jobs"][0]["steps"][0]["conclusion"] = "skipped"
        malformed_jobs.append(skipped)
        wrong_head = copy.deepcopy(self.jobs); wrong_head["jobs"][0]["head_sha"] = self.second
        malformed_jobs.append(wrong_head)
        incomplete = copy.deepcopy(self.jobs); incomplete["total_count"] = 2
        malformed_jobs.append(incomplete)
        duplicate = copy.deepcopy(self.jobs); duplicate["jobs"] *= 2; duplicate["total_count"] = 2
        malformed_jobs.append(duplicate)
        for jobs in malformed_jobs:
            with self.subTest(jobs=jobs), self.assertRaises(GuardError):
                self.call_predecessor(jobs=jobs)
        wrong_pin = copy.deepcopy(self.req); wrong_pin["code_ref"] = self.second
        with self.assertRaises(GuardError):
            self.call_predecessor(req=wrong_pin)
        wrong_project = request(project="synthetic-B"); wrong_project["code_ref"] = self.pin
        with self.assertRaises(GuardError):
            self.call_predecessor(req=wrong_project)
        with self.assertRaises(GuardError):
            self.call_predecessor(prior_target=b"another admitted target version")
        no_change = copy.deepcopy(self.req)
        no_change["envelope"]["project"]["base_version"] = hashlib.sha256(self.expected).hexdigest()
        with self.assertRaises(GuardError):
            self.call_predecessor(req=no_change, prior_target=self.expected)
        (self.root / adapter.TARGETS / "synthetic-A/result.txt").write_bytes(b"unverified")
        with self.assertRaises(GuardError):
            self.call_predecessor()

    def test_b_missing_predecessor_and_a_with_predecessor_block_before_execution(self):
        path = self.root / adapter.REQUEST
        path.parent.mkdir(parents=True, exist_ok=True)
        for project, predecessor in (("synthetic-B", None), ("synthetic-A", self.predecessor)):
            packet = {"schema_version": 1, "request": request(project=project), "predecessor": predecessor}
            path.write_bytes(canonical(packet))
            with self.subTest(project=project), patch.object(adapter, "ROOT", self.root), \
                 patch.object(adapter, "provider_context", return_value=self.context), \
                 patch.object(adapter, "verify_code_pin"), patch.object(adapter, "MissionClient") as client, \
                 self.assertRaises(GuardError):
                adapter.run(adapter.REQUEST, self.root / "receipt.json")
            client.assert_not_called()
            self.assertFalse((self.root / "receipt.json").exists())


if __name__ == "__main__":
    unittest.main()
