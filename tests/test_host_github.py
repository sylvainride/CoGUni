"""P5 fixed GitHub reader tests: fully mocked HTTPS, no live network or writes."""
import base64
import copy
from email.message import Message
import hashlib
import http.client
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
import urllib.error
from unittest.mock import patch

from tests.test_mission_cli import request
from universal import host_github as reader
from universal.core import GuardError
from universal.mission_contracts import canonical, fingerprint
from universal.persistent_provider_observation import ProviderObservation

ROOT = Path(__file__).resolve().parents[1]


class Response(io.BytesIO):
    def __init__(self, data, url, *, status=200, content_type="application/json", headers=None):
        if type(data) is dict:
            data = canonical(data)
        super().__init__(data)
        self.url, self.status = url, status
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        for key, value in (headers or {}).items():
            self.headers[key] = str(value)
        self.read_sizes = []

    def geturl(self):
        return self.url

    def read(self, size=-1):
        self.read_sizes.append(size)
        return super().read(size)


class Opener:
    def __init__(self, values):
        self.values = list(values)
        self.calls = []
        self.responses = []

    def open(self, request, *, timeout):
        self.calls.append((request, timeout))
        value = self.values.pop(0)
        if isinstance(value, BaseException):
            raise value
        if not isinstance(value, Response):
            value = Response(value, request.full_url)
        self.responses.append(value)
        return value


class HostGithubTests(unittest.TestCase):
    def setUp(self):
        self.binding = dict(repository_id=1418009675, actor_id=265171248,
                            run_id=1234567, attempt=1, commit="b" * 40,
                            branch="work/mvp-mission-transport-p5-readproof", code_ref="a" * 40,
                            request_sha256="0" * 64)
        self.packet = {"schema_version": 2, "mode": "INDEPENDENT",
                       "request": request(owner="265171248"), "predecessor": None}
        self.repo = {"id": 1418009675, "full_name": "sylvainride/CoGUni",
                     "owner": {"id": 265171248, "login": "sylvainride"}}
        self.run = {"id": self.binding["run_id"], "run_attempt": 1,
                    "repository": copy.deepcopy(self.repo), "head_repository": copy.deepcopy(self.repo),
                    "actor": {"id": 265171248, "login": "sylvainride"},
                    "triggering_actor": {"id": 265171248, "login": "sylvainride"},
                    "event": "push", "path": ".github/workflows/ci.yml",
                    "head_branch": self.binding["branch"], "head_sha": self.binding["commit"],
                    "status": "in_progress", "conclusion": None}
        self.refresh_content()

    def refresh_content(self):
        raw = canonical(self.packet)
        self.binding["request_sha256"] = fingerprint(self.packet)
        sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        self.content = {"type": "file", "name": "request.json", "path": reader.REQUEST_PATH,
                        "size": len(raw), "sha": sha, "encoding": "base64",
                        "content": base64.encodebytes(raw).decode()}
        self.tree = {"truncated": False, "tree": [{"path": reader.REQUEST_PATH,
                     "mode": "100644", "type": "blob", "sha": sha}]}

    def call(self, *, values=None, binding=None, now=123):
        opener = Opener(values if values is not None else [self.repo, self.run, self.content, self.tree])
        with patch.object(reader.urllib.request, "build_opener", return_value=opener), \
             patch.object(reader.time, "time", return_value=now):
            result = reader.read_github(self.binding if binding is None else binding)
        return result, opener

    def assert_unavailable(self, result, reason="PROVENANCE_MISMATCH"):
        self.assertEqual(result, {"state": "UNAVAILABLE", "reason": reason, "observed_unix": 123})
        self.assertNotIn("observation", result)

    def test_positive_observation_exact_pins_four_fixed_gets_and_no_authority(self):
        result, opener = self.call()
        self.assertEqual(result["state"], "OBSERVED")
        observation = ProviderObservation(**result["observation"])
        self.assertEqual(observation.scheduler_record(), {**self.binding, "status": "in_progress", "conclusion": None})
        self.assertEqual(observation.observed_unix, 123)
        provenance = result["provenance"]
        self.assertEqual(provenance["scope"], "PUBLIC_GITHUB_HTTPS_METADATA_ONLY")
        self.assertFalse(provenance["caller_authenticated"])
        self.assertFalse(provenance["sender_verified"])
        self.assertTrue(provenance["triggering_actor_verified"])
        self.assertTrue(provenance["ordinary_file_verified"])
        self.assertEqual(provenance["get_count"], 4)
        self.assertEqual([item[0].full_url for item in opener.calls], [
            reader.API, reader.API + "/actions/runs/1234567/attempts/1",
            reader.API + "/contents/" + reader.REQUEST_PATH + "?ref=" + "b" * 40,
            reader.API + "/git/trees/" + "b" * 40 + "?recursive=1"])
        for request_obj, timeout in opener.calls:
            self.assertEqual(request_obj.get_method(), "GET")
            self.assertIsNone(request_obj.data)
            self.assertNotIn("authorization", {key.lower() for key in request_obj.headers})
            self.assertEqual(timeout, reader.SOCKET_TIMEOUT_SECONDS)
        self.assertTrue(all(response.read_sizes == [reader.MAX_RESPONSE_BYTES + 1]
                            for response in opener.responses))
        self.assertLess(len(canonical(result)), 16384)
        self.assertNotIn("health", result)
        self.assertNotIn("execution_authorized", result)

    def test_observation_id_stable_across_ack_loss_but_changes_for_new_status(self):
        first, _ = self.call(now=123)
        replay, _ = self.call(now=124)
        self.assertEqual(first["observation"]["observation_id"], replay["observation"]["observation_id"])
        self.assertNotEqual(first["observation"]["observed_unix"], replay["observation"]["observed_unix"])
        self.run.update(status="completed", conclusion="success")
        completed, _ = self.call()
        self.assertEqual(completed["state"], "OBSERVED")
        self.assertNotEqual(first["observation"]["observation_id"], completed["observation"]["observation_id"])
        self.assertNotIn("application_status", completed)

    def test_valid_binding_copies_and_refuses_types_extra_fields_and_wrong_scope(self):
        validated = reader.validate_binding(self.binding)
        self.assertEqual(validated, self.binding)
        self.assertIsNot(validated, self.binding)
        for update in ({"repository_id": 1}, {"repository_id": True}, {"actor_id": "265171248"},
                       {"run_id": True}, {"run_id": 0}, {"run_id": 10**15}, {"attempt": 101},
                       {"attempt": False}, {"commit": "A" * 40}, {"code_ref": "a" * 39},
                       {"request_sha256": "b" * 65}, {"branch": "main"},
                       {"branch": self.binding["branch"] + "../bad"},
                       {"branch": self.binding["branch"] + "/.hidden"},
                       {"branch": self.binding["branch"] + "/bad.lock"},
                       {"branch": self.binding["branch"] + "//bad"},
                       {"url": "https://elsewhere.invalid"}, {"execution_authorized": True}):
            with self.subTest(update=update), self.assertRaises(GuardError):
                reader.validate_binding({**self.binding, **update})
        for key in self.binding:
            bad = {name: value for name, value in self.binding.items() if name != key}
            with self.subTest(missing=key), self.assertRaises(GuardError):
                reader.validate_binding(bad)
        result, opener = self.call(binding={**self.binding, "repository_id": 2})
        self.assert_unavailable(result)
        self.assertEqual(len(opener.calls), 0)

    def test_repository_owner_identity_at_every_boundary_is_pinned(self):
        for position in (0, 1, 2):
            for path, replacement in ((["id"], 9), (["id"], True),
                                      (["full_name"], "someone/CoGUni"),
                                      (["owner", "id"], 9), (["owner", "login"], "someone")):
                repo, run = copy.deepcopy(self.repo), copy.deepcopy(self.run)
                target = (repo, run["repository"], run["head_repository"])[position]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                with self.subTest(position=position, path=path, value=replacement):
                    result, _ = self.call(values=[repo, run, self.content, self.tree])
                    self.assert_unavailable(result)

    def test_every_run_identity_and_optional_sender_are_pinned(self):
        for field, replacement in (("id", 8), ("id", True), ("run_attempt", 2),
                                   ("run_attempt", True), ("head_sha", "c" * 40),
                                   ("head_branch", "main"), ("event", "pull_request"),
                                   ("path", ".github/workflows/other.yml"),
                                   ("actor", {"id": 265171248, "login": "someone"}),
                                   ("triggering_actor", {"id": 7, "login": "someone"}),
                                   ("sender", {"id": 7, "login": "someone"}),
                                   ("head_repository", None)):
            with self.subTest(field=field, value=replacement):
                result, _ = self.call(values=[self.repo, {**self.run, field: replacement}, self.content, self.tree])
                self.assert_unavailable(result)
        for missing in ("id", "run_attempt", "head_sha", "head_branch", "event", "path", "actor", "repository"):
            run = {key: value for key, value in self.run.items() if key != missing}
            with self.subTest(missing=missing):
                result, _ = self.call(values=[self.repo, run, self.content, self.tree])
                self.assert_unavailable(result)
        no_trigger = {key: value for key, value in self.run.items() if key != "triggering_actor"}
        result, _ = self.call(values=[self.repo, no_trigger, self.content, self.tree])
        self.assertEqual(result["state"], "OBSERVED")
        self.assertFalse(result["provenance"]["triggering_actor_verified"])

    def test_provider_status_is_inert_and_contradictory_statuses_refused(self):
        for status, conclusion in (("queued", None), ("in_progress", None),
                                   ("completed", "success"), ("completed", "failure"),
                                   ("completed", "cancelled"), ("completed", "timed_out")):
            with self.subTest(status=status, conclusion=conclusion):
                run = {**self.run, "status": status, "conclusion": conclusion}
                result, _ = self.call(values=[self.repo, run, self.content, self.tree])
                self.assertEqual(result["state"], "OBSERVED")
                self.assertEqual(result["observation"]["status"], status)
        for status, conclusion in (("completed", None), ("in_progress", "success"),
                                   ("PASS", "success"), ("completed", "action_required")):
            with self.subTest(status=status, conclusion=conclusion):
                run = {**self.run, "status": status, "conclusion": conclusion}
                result, _ = self.call(values=[self.repo, run, self.content, self.tree])
                self.assert_unavailable(result)

    def test_http_errors_are_unavailable_at_each_stage_without_fallback(self):
        cases = [(401, {}, "ACCESS_DENIED"), (403, {}, "ACCESS_DENIED"),
                 (403, {"X-RateLimit-Remaining": "0"}, "RATE_LIMIT"),
                 (404, {}, "NOT_FOUND"), (429, {}, "RATE_LIMIT"), (500, {}, "UNAVAILABLE"),
                 (302, {"Location": "https://elsewhere.invalid"}, "PROVENANCE_MISMATCH")]
        for stage in range(4):
            for status, headers, reason in cases:
                values = [self.repo, self.run, self.content, self.tree]
                values[stage] = urllib.error.HTTPError(reader.API, status, "mock", headers, None)
                with self.subTest(stage=stage, status=status, headers=headers):
                    result, opener = self.call(values=values)
                    self.assert_unavailable(result, reason)
                    self.assertEqual(len(opener.calls), stage + 1)

    def test_timeout_connection_and_incomplete_response_are_never_success(self):
        for exception in (socket.timeout(), urllib.error.URLError("offline"),
                          ConnectionResetError(), http.client.IncompleteRead(b"{")):
            with self.subTest(exception=type(exception).__name__):
                result, opener = self.call(values=[exception])
                self.assert_unavailable(result, "UNAVAILABLE")
                self.assertEqual(len(opener.calls), 1)

    def test_redirect_is_physically_disabled_and_redirected_response_refused(self):
        handler = reader._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "mock", {}, "https://elsewhere.invalid"))
        result, opener = self.call(values=[Response(self.repo, "https://elsewhere.invalid")])
        self.assert_unavailable(result)
        self.assertEqual(len(opener.calls), 1)

    def test_strict_json_duplicate_keys_truncation_unicode_and_nonfinite_refused(self):
        invalid = [b'{"id":1418009675,"id":1418009675}', b'{"owner":{"id":1,"id":2}}',
                   b'{', b'[]', b'null', b'{"value":NaN}', b'{"value":Infinity}', b'\xff']
        for stage in range(4):
            for raw in invalid:
                values = [self.repo, self.run, self.content, self.tree]
                values[stage] = raw
                with self.subTest(stage=stage, raw=raw):
                    result, opener = self.call(values=values)
                    self.assert_unavailable(result)
                    self.assertEqual(len(opener.calls), stage + 1)

    def test_response_size_declared_length_and_representation_are_bounded(self):
        bad = [Response(b" " * (reader.MAX_RESPONSE_BYTES + 1), reader.API),
               Response(self.repo, reader.API, headers={"Content-Length": reader.MAX_RESPONSE_BYTES + 1}),
               Response(self.repo, reader.API, headers={"Content-Length": 1}),
               Response(self.repo, reader.API, headers={"Content-Length": "-1"}),
               Response(self.repo, reader.API, headers={"Content-Encoding": "gzip"}),
               Response(self.repo, reader.API, content_type="text/html")]
        for response in bad:
            with self.subTest(headers=str(response.headers)):
                result, opener = self.call(values=[response])
                self.assert_unavailable(result)
                self.assertTrue(all(size <= reader.MAX_RESPONSE_BYTES + 1 for size in response.read_sizes))
                self.assertEqual(len(opener.calls), 1)

    def test_content_type_size_encoding_path_hash_and_base64_are_bound(self):
        for update in ({"type": "symlink"}, {"path": "somewhere/request.json"},
                       {"name": "other.json"}, {"size": True}, {"size": 16385},
                       {"encoding": "none"}, {"sha": "0" * 40},
                       {"content": self.content["content"] + "!"},
                       {"content": base64.b64encode(b"{}").decode()},
                       {"content": "a" * 23001}, {"target": "other.json"},
                       {"submodule_git_url": "https://elsewhere.invalid"}):
            with self.subTest(update=update):
                result, _ = self.call(values=[self.repo, self.run, {**self.content, **update}, self.tree])
                self.assert_unavailable(result)

    def test_exact_git_tree_mode_prevents_contents_symlink_dereference_confusion(self):
        entry = self.tree["tree"][0]
        for update in ({"mode": "120000"}, {"mode": "160000", "type": "commit"},
                       {"mode": "100755"}, {"type": "tree"}, {"sha": "e" * 40},
                       {"path": "other.json"}):
            with self.subTest(update=update):
                tree = {"truncated": False, "tree": [{**entry, **update}]}
                result, _ = self.call(values=[self.repo, self.run, self.content, tree])
                self.assert_unavailable(result)
        for tree in ({"truncated": True, "tree": [entry]}, {"truncated": 0, "tree": [entry]},
                     {"tree": [entry]}, {"truncated": False, "tree": [entry, entry]},
                     {"truncated": False, "tree": []}, {"truncated": False, "tree": [None]}):
            with self.subTest(tree=tree):
                result, _ = self.call(values=[self.repo, self.run, self.content, tree])
                self.assert_unavailable(result)

    def test_packet_fingerprint_and_immutable_code_ref_are_checked(self):
        for update in ({"code_ref": "c" * 40}, {"request_sha256": "d" * 64}):
            with self.subTest(update=update):
                result, _ = self.call(binding={**self.binding, **update})
                self.assert_unavailable(result)

    def test_existing_packet_versions_and_dependencies_are_observed_without_reexecution(self):
        self.packet = {"schema_version": 1, "request": self.packet["request"], "predecessor": None}
        self.refresh_content()
        result, _ = self.call()
        self.assertEqual(result["state"], "OBSERVED")
        predecessor = {"request_commit": "d" * 40, "provider_run_id": 88,
                       "artifact_sha256": "e" * 64}
        self.packet["predecessor"] = predecessor
        self.packet["request"]["envelope"]["project"]["id"] = "synthetic-B"
        self.refresh_content()
        result, _ = self.call()
        self.assertEqual(result["state"], "OBSERVED")
        self.packet.update(schema_version=2, mode="DEPENDENT")
        self.refresh_content()
        result, _ = self.call()
        self.assertEqual(result["state"], "OBSERVED")
        for bad in ({**predecessor, "execution_authorized": True}, True,
                    {**predecessor, "provider_run_id": True},
                    {**predecessor, "request_commit": "bad"}):
            self.packet["predecessor"] = bad
            self.refresh_content()
            with self.subTest(predecessor=bad):
                result, _ = self.call()
                self.assert_unavailable(result)
        self.packet["predecessor"] = predecessor
        self.packet["mode"] = "INDEPENDENT"
        self.refresh_content()
        result, _ = self.call()
        self.assert_unavailable(result)

    def test_rehashed_worker_authorization_unknown_fields_and_private_scope_rejected(self):
        original = copy.deepcopy(self.packet)
        for target in ("packet", "request", "envelope"):
            self.packet = copy.deepcopy(original)
            item = self.packet if target == "packet" else self.packet["request"]
            if target == "envelope":
                item = item["envelope"]
            item["execution_authorized"] = True
            self.refresh_content()
            with self.subTest(target=target):
                result, _ = self.call()
                self.assert_unavailable(result)
        for key, replacement in (("privacy", "PRIVATE_OWNER"), ("project", {
                **original["request"]["envelope"]["project"], "id": "real-project"})):
            self.packet = copy.deepcopy(original)
            self.packet["request"]["envelope"][key] = replacement
            self.refresh_content()
            with self.subTest(key=key):
                result, _ = self.call()
                self.assert_unavailable(result)

    def test_rehashed_packet_must_preserve_static_mission_client_synthetic_scope(self):
        original = copy.deepcopy(self.packet)
        cases = [("request", "payload", "real:private"),
                 ("request", "payload", "synthetic:" + "x" * 129),
                 ("request", "payload", True), ("request", "action", "shell"),
                 ("request", "action", ["uppercase"]),
                 ("envelope", "source_sha256", "f" * 64),
                 ("envelope", "expires_unix", 100 + 86401),
                 ("envelope", "parent_mission_id", "another-mission"),
                 ("envelope", "capability_snapshot_ref", "worker-grant"),
                 ("contract", "max_duration_seconds", 301),
                 ("contract", "allowed_actions", ["remote-write"]),
                 ("contract", "max_external_cost", 1),
                 ("contract", "artifact_policy", "private_owner"),
                 ("contract", "dependencies", ["other-task"])]
        for target, key, value in cases:
            self.packet = copy.deepcopy(original)
            destination = self.packet["request"]
            if target != "request":
                destination = destination["envelope"]
            if target == "contract":
                destination = destination["contract"]
            destination[key] = value
            self.refresh_content()
            with self.subTest(target=target, key=key, value=value):
                result, _ = self.call()
                self.assert_unavailable(result)

    def test_packet_json_duplicate_keys_and_oversize_do_not_bypass_blob_hash(self):
        for raw in (b'{"schema_version":2,"schema_version":2}', b'{"test":NaN}',
                    b'{"test":"' + b"a" * 16385 + b'"}'):
            content = {**self.content, "size": len(raw), "content": base64.b64encode(raw).decode(),
                       "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}
            with self.subTest(size=len(raw)):
                result, _ = self.call(values=[self.repo, self.run, content, self.tree])
                self.assert_unavailable(result)

    def test_reader_module_rejects_arguments_and_oversize_stdin_without_network(self):
        for args, raw in ((["--url", "https://elsewhere.invalid"], b"{}"), ([], b"a" * 16385),
                          ([], b'{"repository_id":1,"repository_id":2}')):
            with self.subTest(args=args, size=len(raw)):
                completed = subprocess.run([sys.executable, "-m", "universal.host_github", *args],
                                           input=raw, capture_output=True, cwd=ROOT, timeout=5)
                self.assertEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, b"")
                result = json.loads(completed.stdout)
                self.assertEqual(result["state"], "UNAVAILABLE")
                self.assertEqual(result["reason"], "PROVENANCE_MISMATCH")
                self.assertEqual(len(completed.stdout.splitlines()), 1)
                self.assertLess(len(completed.stdout), 16384)


if __name__ == "__main__":
    unittest.main()
