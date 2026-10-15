"""Fixed public GitHub read boundary for the private owner host.

No credentials, provider writes, configurable URLs, execution grants or health
readbacks. HTTPS metadata identifies the public source in this limited scope;
it does not authenticate this caller or attest execution/application of a task.
The host must run this module in its hard-deadline process boundary.
"""
from dataclasses import asdict
import base64
import hashlib
import http.client
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.request

from .core import GuardError
from .mission_contracts import (_read, canonical, decode_mission, fingerprint,
                                MissionContractError)
from .mission_cli import _PAYLOAD
from .persistent_provider_observation import ProviderObservation

API = "https://api.github.com/repos/sylvainride/CoGUni"
REQUEST_PATH = "tests/fixtures_mvp_transport/request.json"
WORKFLOW_PATH = ".github/workflows/ci.yml"
MAX_RESPONSE_BYTES = 262144
SOCKET_TIMEOUT_SECONDS = 5
_BINDING_FIELDS = {"repository_id", "actor_id", "run_id", "attempt", "commit",
                   "branch", "code_ref", "request_sha256"}
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_BRANCH = re.compile(r"work/mvp-mission-transport-[A-Za-z0-9._/-]{1,96}\Z")


def validate_binding(binding):
    """Validate a private owner pin, never a binding supplied by a worker."""
    if type(binding) is not dict or set(binding) != _BINDING_FIELDS:
        raise GuardError("exact owner provider binding required")
    for name, maximum in (("repository_id", 2**63 - 1), ("actor_id", 2**63 - 1),
                          ("run_id", 10**15 - 1), ("attempt", 100)):
        if type(binding[name]) is not int or not 0 < binding[name] <= maximum:
            raise GuardError("invalid owner provider numeric pin")
    if binding["repository_id"] != 1418009675 or binding["actor_id"] != 265171248:
        raise GuardError("owner provider identity is outside fixed scope")
    for name, pattern in (("commit", _SHA40), ("code_ref", _SHA40),
                          ("request_sha256", _SHA64), ("branch", _BRANCH)):
        if type(binding[name]) is not str or not pattern.fullmatch(binding[name]):
            raise GuardError("invalid owner provider source pin")
    # These are Git refs, not URL components. Reject Git's ambiguous forms as
    # well as a path-like value which happens to fit the bounded alphabet.
    branch = binding["branch"]
    if (".." in branch or "//" in branch or branch.endswith(("/", ".", ".lock"))
            or any(part.startswith(".") or part.endswith(".lock") for part in branch.split("/"))):
        raise GuardError("invalid owner provider branch pin")
    return dict(binding)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate provider field")
        result[key] = value
    return result


def _no_constant(_):
    raise ValueError("nonfinite provider number")


def _json_response(opener, url):
    request = urllib.request.Request(url, method="GET", headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "CoGUni-readonly-owner-host/1"})
    with opener.open(request, timeout=SOCKET_TIMEOUT_SECONDS) as response:
        if response.geturl() != url or response.status != 200:
            raise GuardError("provider redirected or substituted response")
        if (response.headers.get_content_type() != "application/json"
                or response.headers.get("Content-Encoding", "identity") != "identity"):
            raise GuardError("provider returned unsupported representation")
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isascii() or not length.isdigit()
                                   or not 0 < int(length) <= MAX_RESPONSE_BYTES):
            raise GuardError("provider declared unbounded response")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if (not 0 < len(raw) <= MAX_RESPONSE_BYTES
                or length is not None and len(raw) != int(length)):
            raise GuardError("provider returned oversized or truncated response")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                      parse_constant=_no_constant)
    if type(data) is not dict:
        raise GuardError("provider root must be an object")
    return data


def _repository(value):
    return (type(value) is dict and type(value.get("id")) is int
            and value["id"] == 1418009675 and value.get("full_name") == "sylvainride/CoGUni"
            and type(value.get("owner")) is dict
            and type(value["owner"].get("id")) is int
            and value["owner"]["id"] == 265171248
            and value["owner"].get("login") == "sylvainride")


def _actor(value):
    return (type(value) is dict and type(value.get("id")) is int
            and value["id"] == 265171248 and value.get("login") == "sylvainride")


def _packet(raw, binding):
    packet = _read(raw)
    version = packet.get("schema_version")
    if type(version) is not int or version not in (1, 2):
        raise GuardError("invalid synthetic packet version")
    fields = {"schema_version", "request", "predecessor"}
    if version == 2:
        fields.add("mode")
        if type(packet.get("mode")) is not str or packet["mode"] not in {"INDEPENDENT", "DEPENDENT"}:
            raise GuardError("invalid synthetic packet mode")
    if set(packet) != fields or type(packet.get("request")) is not dict:
        raise GuardError("invalid synthetic packet shape")
    predecessor = packet["predecessor"]
    if predecessor is not None:
        if (type(predecessor) is not dict
                or set(predecessor) != {"request_commit", "provider_run_id", "artifact_sha256"}
                or type(predecessor["request_commit"]) is not str
                or not _SHA40.fullmatch(predecessor["request_commit"])
                or type(predecessor["provider_run_id"]) is not int
                or not 0 < predecessor["provider_run_id"] < 10**15
                or type(predecessor["artifact_sha256"]) is not str
                or not _SHA64.fullmatch(predecessor["artifact_sha256"])):
            raise GuardError("invalid synthetic predecessor shape")
    request = packet["request"]
    if set(request) != {"envelope", "payload", "action", "code_ref"}:
        raise GuardError("invalid synthetic request shape")
    # Parse the original bounded envelope at its original creation time. This
    # observes a past run; it does not renew admission or current expiry.
    envelope = request["envelope"]
    if type(envelope) is not dict:
        raise GuardError("invalid synthetic envelope")
    decode_mission(canonical(envelope), now_unix=envelope["created_unix"])
    project = envelope["project"]
    contract = envelope["contract"]
    if (envelope["privacy"] != "PUBLIC_SYNTHETIC"
            or project["kind"] != "local" or project["id"] not in {"synthetic-A", "synthetic-B"}
            or project["owner"] != "265171248"
            or project["source_of_truth"] != "owner-synthetic-fixture"
            or envelope.get("parent_mission_id") is not None
            or envelope.get("capability_snapshot_ref") is not None
            or envelope["expires_unix"] - envelope["created_unix"] > 86400
            or contract["max_duration_seconds"] > 300
            or contract["allowed_actions"] != ["simulate"]
            or contract["max_external_cost"] != 0
            or contract["artifact_policy"] != "public_synthetic"
            or contract["dependencies"]
            or type(request["payload"]) is not str or not _PAYLOAD.fullmatch(request["payload"])
            or type(request["action"]) is not str or request["action"] not in {"uppercase", "sha256"}
            or envelope["source_sha256"] != hashlib.sha256(request["payload"].encode()).hexdigest()
            or request["code_ref"] != binding["code_ref"]
            or fingerprint(packet) != binding["request_sha256"]):
        raise GuardError("synthetic packet does not match owner pins")
    if (version == 1 and ((project["id"] == "synthetic-A" and predecessor is not None)
                          or (project["id"] == "synthetic-B" and predecessor is None))
            or version == 2 and packet["mode"] == "INDEPENDENT" and predecessor is not None
            or version == 2 and packet["mode"] == "DEPENDENT"
               and (project["id"] != "synthetic-B" or predecessor is None)):
        raise GuardError("invalid synthetic packet dependency")
    return packet


def _content(value, binding):
    if (value.get("type") != "file" or value.get("path") != REQUEST_PATH
            or value.get("name") != "request.json" or value.get("encoding") != "base64"
            or type(value.get("size")) is not int or not 0 < value["size"] <= 16384
            or type(value.get("sha")) is not str or not _SHA40.fullmatch(value["sha"])
            or type(value.get("content")) is not str
            or "target" in value or "submodule_git_url" in value):
        raise GuardError("provider request is not a bounded file blob")
    encoded = value["content"]
    if len(encoded) > 23000:
        raise GuardError("provider request encoding exceeds bound")
    # GitHub wraps base64 with LF; accept only that documented whitespace.
    raw = base64.b64decode(encoded.replace("\n", ""), validate=True)
    if (len(raw) != value["size"]
            or hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest() != value["sha"]):
        raise GuardError("provider request blob integrity mismatch")
    _packet(raw, binding)
    return value["sha"]


def _ordinary_tree(tree, blob_sha):
    # Contents may transparently dereference an in-repository symlink. Only
    # the immutable Git tree proves the original request's ordinary-file mode.
    if tree.get("truncated") is not False or type(tree.get("tree")) is not list:
        raise GuardError("provider tree is incomplete")
    entries = tree["tree"]
    if any(type(entry) is not dict for entry in entries):
        raise GuardError("provider tree entry is malformed")
    matching = [entry for entry in entries if entry.get("path") == REQUEST_PATH]
    if (len(matching) != 1 or matching[0].get("mode") != "100644"
            or matching[0].get("type") != "blob" or matching[0].get("sha") != blob_sha):
        raise GuardError("provider request tree mode or blob mismatch")


def _unavailable(reason):
    return {"state": "UNAVAILABLE", "reason": reason, "observed_unix": int(time.time())}


def read_github(binding):
    """GET fixed immutable source metadata; errors never become observations."""
    try:
        binding = validate_binding(binding)
        opener = urllib.request.build_opener(_NoRedirect)
        if not _repository(_json_response(opener, API)):
            raise GuardError("provider repository identity mismatch")
        run = _json_response(opener, API + "/actions/runs/" + str(binding["run_id"])
                             + "/attempts/" + str(binding["attempt"]))
        if (not _repository(run.get("repository")) or not _repository(run.get("head_repository"))
                or not _actor(run.get("actor")) or run.get("event") != "push"
                or run.get("path") != WORKFLOW_PATH
                or type(run.get("id")) is not int or run["id"] != binding["run_id"]
                or type(run.get("run_attempt")) is not int or run["run_attempt"] != binding["attempt"]
                or run.get("head_branch") != binding["branch"] or run.get("head_sha") != binding["commit"]):
            raise GuardError("provider run identity mismatch")
        for optional_actor in ("sender", "triggering_actor"):
            if optional_actor in run and not _actor(run[optional_actor]):
                raise GuardError("provider triggering identity mismatch")
        content = _json_response(opener, API + "/contents/" + REQUEST_PATH + "?ref=" + binding["commit"])
        blob_sha = _content(content, binding)
        tree = _json_response(opener, API + "/git/trees/" + binding["commit"] + "?recursive=1")
        _ordinary_tree(tree, blob_sha)
        substantive = {**binding, "status": run["status"], "conclusion": run["conclusion"]}
        observation = ProviderObservation(observation_id=fingerprint(substantive),
                                          **substantive, observed_unix=int(time.time()))
        return {"state": "OBSERVED", "observation": asdict(observation), "provenance": {
            "scope": "PUBLIC_GITHUB_HTTPS_METADATA_ONLY", "caller_authenticated": False,
            "repository_id": binding["repository_id"], "actor_id": binding["actor_id"],
            "run_id": binding["run_id"], "attempt": binding["attempt"],
            "commit": binding["commit"], "branch": binding["branch"],
            "code_ref": binding["code_ref"], "request_sha256": binding["request_sha256"],
            "workflow_path": WORKFLOW_PATH, "request_path": REQUEST_PATH,
            "request_blob_sha": blob_sha, "get_count": 4, "ordinary_file_verified": True,
            "sender_verified": "sender" in run, "triggering_actor_verified": "triggering_actor" in run}}
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            reason = "RATE_LIMIT" if (error.headers or {}).get("X-RateLimit-Remaining") == "0" else "ACCESS_DENIED"
        else:
            reason = ({404: "NOT_FOUND", 429: "RATE_LIMIT"}.get(error.code)
                      or ("PROVENANCE_MISMATCH" if 300 <= error.code < 400 else "UNAVAILABLE"))
        return _unavailable(reason)
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError, http.client.HTTPException):
        return _unavailable("UNAVAILABLE")
    except (GuardError, MissionContractError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        return _unavailable("PROVENANCE_MISMATCH")


def main():
    """One binding on stdin, one bounded JSON response; no URL/command flags."""
    try:
        if len(sys.argv) != 1:
            raise GuardError("reader accepts no arguments")
        result = read_github(_read(sys.stdin.buffer.read(16385)))
    except (GuardError, MissionContractError, ValueError, OSError):
        result = _unavailable("PROVENANCE_MISMATCH")
    sys.stdout.buffer.write(canonical(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
