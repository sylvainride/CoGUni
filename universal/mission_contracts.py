"""Inert, bounded wire contracts for synthetic universal missions.

Parsing or hashing a mission, receipt, or event NEVER authenticates a Chat sender,
authorizes an effect, certifies a worker PASS, or creates a runtime grant. The
existing owner journal, consent authority, and verifier remain authoritative.
"""
import hashlib
import json
import math
import re

MAX_WIRE_BYTES = 16_384
MAX_MISSION_LIFETIME = 30 * 24 * 3600
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z")
_KEY = re.compile(r"[A-Za-z0-9._:-]{8,160}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class MissionContractError(ValueError):
    """Untrusted wire input is malformed; never retry it as an authorized effect."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise MissionContractError("duplicate field")
        result[key] = value
    return result


def _no_constant(_):
    raise MissionContractError("nonfinite number")


def _read(raw):
    if type(raw) not in (str, bytes):
        raise MissionContractError("wire input must be JSON text")
    try:
        data = raw.encode("utf-8") if type(raw) is str else raw
        if not 0 < len(data) <= MAX_WIRE_BYTES:
            raise MissionContractError("wire size exceeded")
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                         parse_constant=_no_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise MissionContractError("invalid UTF-8 JSON") from exc
    if type(obj) is not dict:
        raise MissionContractError("root must be object")
    return obj


def _shape(value, required, optional=()):
    if type(value) is not dict or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        raise MissionContractError("missing or unexpected field")


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise MissionContractError("invalid integer")


def _string(value, minimum=1, maximum=160, pattern=None):
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise MissionContractError("invalid string")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise MissionContractError("invalid Unicode scalar") from exc
    if pattern is not None and not pattern.fullmatch(value):
        raise MissionContractError("invalid identifier")


def _items(value, minimum, maximum, item_max, *, unique=False):
    if type(value) is not list or not minimum <= len(value) <= maximum:
        raise MissionContractError("invalid list")
    for item in value:
        _string(item, 1, item_max)
    if unique and len(set(value)) != len(value):
        raise MissionContractError("duplicate list member")


def _one(value, choices):
    if type(value) is not str or value not in choices:
        raise MissionContractError("invalid enum")


def _sha(value):
    _string(value, 64, 64, _SHA)


def _common(value):
    _integer(value["schema_version"], 1, 1)
    _string(value["mission_id"], 1, 96, _ID)
    _sha(value["source_sha256"])


def _mission(value, now_unix):
    _shape(value, {"schema_version", "mission_id", "idempotency_key", "project", "contract",
                   "created_unix", "expires_unix", "source_sha256", "privacy"},
           {"parent_mission_id", "capability_snapshot_ref"})
    _common(value)
    _string(value["idempotency_key"], 8, 160, _KEY)
    _integer(now_unix, 0, 2**63 - 1)
    _integer(value["created_unix"], 0, 2**63 - 1)
    _integer(value["expires_unix"], 0, 2**63 - 1)
    if not value["created_unix"] <= now_unix < value["expires_unix"] or not 0 < value["expires_unix"] - value["created_unix"] <= MAX_MISSION_LIFETIME:
        raise MissionContractError("expired or unbounded mission")
    _one(value["privacy"], {"PUBLIC_SYNTHETIC", "PRIVATE_OWNER"})
    for key, maxlen in (("parent_mission_id", 96), ("capability_snapshot_ref", 160)):
        if key in value and value[key] is not None:
            _string(value[key], 1, maxlen, _ID if key == "parent_mission_id" else None)
    project = value["project"]
    _shape(project, {"kind", "id", "owner", "base_version", "source_of_truth"})
    _one(project["kind"], {"floot", "github", "local", "other"})
    for key, maxlen in (("id", 160), ("owner", 160), ("base_version", 160), ("source_of_truth", 220)):
        _string(project[key], 1, maxlen)
    contract = value["contract"]
    _shape(contract, {"task_id", "objective", "allowed_actions", "forbidden_actions", "criteria",
                      "dependencies", "max_attempts", "max_duration_seconds", "max_external_cost", "artifact_policy"})
    _string(contract["task_id"], 1, 96)
    _string(contract["objective"], 1, 1024)
    for key, mn, mx, item_max in (("allowed_actions", 0, 24, 120), ("forbidden_actions", 0, 48, 120),
                                  ("criteria", 1, 32, 300), ("dependencies", 0, 32, 96)):
        _items(contract[key], mn, mx, item_max, unique=True)
    if set(contract["allowed_actions"]) & set(contract["forbidden_actions"]):
        raise MissionContractError("conflicting actions")
    if contract["task_id"] in contract["dependencies"]:
        raise MissionContractError("self dependency")
    _integer(contract["max_attempts"], 1, 20)
    _integer(contract["max_duration_seconds"], 1, MAX_MISSION_LIFETIME)
    cost = contract["max_external_cost"]
    if type(cost) not in (int, float) or not math.isfinite(cost) or not 0 <= cost <= 1_000_000:
        raise MissionContractError("invalid nominal cost limit")
    _one(contract["artifact_policy"], {"public_synthetic", "private_owner", "none"})
    if value["privacy"] == "PRIVATE_OWNER" and contract["artifact_policy"] == "public_synthetic":
        raise MissionContractError("private input cannot request public artifact")


def _receipt(value):
    _shape(value, {"schema_version", "mission_id", "run_id", "project_id", "source_sha256",
                   "result_state", "artifact_sha256", "integrity_verified", "application_status",
                   "acceptance_status"}, {"target_version_after", "proof_refs", "error_code"})
    _common(value)
    _string(value["run_id"], 1, 96, _ID)
    _string(value["project_id"])
    _one(value["result_state"], {"RESULT_READY", "FAILED_CONFIRMED", "UNKNOWN_EFFECT", "BLOCKED_TOOL", "BLOCKED_PERMISSION"})
    if value["artifact_sha256"] is not None:
        _sha(value["artifact_sha256"])
    if type(value["integrity_verified"]) is not bool:
        raise MissionContractError("invalid integrity flag")
    _one(value["application_status"], {"NOT_APPLIED", "APPLY_REQUESTED", "APPLIED", "FAILED", "UNKNOWN_EFFECT"})
    _one(value["acceptance_status"], {"NOT_TESTED", "PASS_SCOPED", "FAIL", "BLOCKED"})
    if value["integrity_verified"] and value["artifact_sha256"] is None:
        raise MissionContractError("integrity flag has no artifact")
    if value["result_state"] == "UNKNOWN_EFFECT" and value["acceptance_status"] == "PASS_SCOPED":
        raise MissionContractError("unknown effect is not accepted")
    if "target_version_after" in value and value["target_version_after"] is not None:
        _string(value["target_version_after"])
    if "error_code" in value and value["error_code"] is not None:
        _string(value["error_code"], 1, 120)
    if "proof_refs" in value:
        _items(value["proof_refs"], 0, 32, 240, unique=True)


def _event(value):
    _shape(value, {"schema_version", "mission_id", "run_id", "event_seq", "state", "observed_unix",
                   "source_sha256", "proof_kind", "fence", "revision"},
           {"project_id", "lease_until_unix", "heartbeat_seq", "progress_seq", "event_digest", "reason_code"})
    _common(value)
    _string(value["run_id"], 1, 96, _ID)
    if "project_id" in value:
        _string(value["project_id"])
    for key in ("event_seq", "observed_unix", "fence", "revision"):
        _integer(value[key], 0, 2**63 - 1)
    for key in ("lease_until_unix", "heartbeat_seq", "progress_seq"):
        if key in value and value[key] is not None:
            _integer(value[key], 0, 2**63 - 1)
    _one(value["state"], {"QUEUED", "CLAIMED", "RUNNING", "SILENT_RUNNING", "SUSPECT_RECOVERY",
                           "RESULT_READY", "RESULT_INSPECTED", "APPLY_REQUESTED", "APPLIED",
                           "VERIFYING", "ACCEPTED", "NEEDS_REWORK", "BLOCKED_PERMISSION", "BLOCKED_TOOL",
                           "BLOCKED_QUOTA", "FAILED_CONFIRMED", "UNKNOWN_EFFECT", "CANCELLED",
                           "CHAT_HANDOFF", "PAUSED_NO_EXECUTOR"})
    _one(value["proof_kind"], {"OWNER_JOURNAL", "AUTH_PROVIDER", "TRUSTED_SUPERVISOR", "EXTERNAL_RECEIPT", "UNTRUSTED_WORKER"})
    if value["proof_kind"] == "UNTRUSTED_WORKER" and value["state"] in {"ACCEPTED", "APPLIED"}:
        raise MissionContractError("worker cannot attest acceptance or effect")
    if "event_digest" in value:
        _sha(value["event_digest"])
        body = {key: val for key, val in value.items() if key != "event_digest"}
        if value["event_digest"] != fingerprint(body):
            raise MissionContractError("event digest mismatch")
    if "reason_code" in value:
        _string(value["reason_code"], 1, 120)


def canonical(value):
    """Deterministic bytes for integrity only, never an authenticated signature."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def decode_mission(raw, *, now_unix):
    value = _read(raw)
    _mission(value, now_unix)
    return value


def decode_receipt(raw):
    value = _read(raw)
    _receipt(value)
    return value


def decode_event(raw):
    value = _read(raw)
    _event(value)
    return value
