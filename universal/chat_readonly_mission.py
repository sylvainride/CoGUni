"""Pure offline mission fixture; no GitHub runner, authentication or remote effects.

Feature is disconnected by design. The trusted caller supplies identity and time;
no value from an untrusted mission can elevate permissions. No replay store exists.
"""
import hashlib
import re

_KEYS = frozenset({"mission_version", "repository_full_name", "repository_id",
                   "owner_id", "actor_id", "source_sha", "nonce", "expires_unix",
                   "kind", "payload"})
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_PAYLOAD = re.compile(r"synthetic:[a-zA-Z0-9._-]{1,64}\Z")


def run_offline_hash(mission, *, trusted_repo_id, trusted_owner_id,
                     trusted_actor_id, trusted_source_sha, now_unix):
    """Validate one bounded envelope and hash inert UTF-8 data, never execute it.

    This is NOT a signed owner grant, Chat integration, replay prevention, or
    evidence that GitHub Actions can dispatch a mission. Keep feature OFF.
    """
    if not isinstance(mission, dict) or set(mission) != _KEYS:
        raise ValueError("invalid mission fields")
    if type(mission["mission_version"]) is not int or mission["mission_version"] != 1:
        raise ValueError("unsupported mission version")
    if mission["repository_full_name"] != "sylvainride/CoGUni" or mission["repository_id"] != "1418009675":
        raise ValueError("repository mismatch")
    if mission["repository_id"] != trusted_repo_id or mission["owner_id"] != trusted_owner_id or mission["actor_id"] != trusted_actor_id:
        raise ValueError("trusted identity mismatch")
    if not isinstance(trusted_source_sha, str) or not _SHA.fullmatch(trusted_source_sha):
        raise ValueError("invalid trusted SHA")
    if not isinstance(mission["source_sha"], str) or mission["source_sha"] != trusted_source_sha:
        raise ValueError("source SHA mismatch")
    if not isinstance(mission["nonce"], str) or not _NONCE.fullmatch(mission["nonce"]):
        raise ValueError("invalid nonce")
    if type(now_unix) is not int or type(mission["expires_unix"]) is not int:
        raise ValueError("invalid clock")
    if not now_unix < mission["expires_unix"] <= now_unix + 900:
        raise ValueError("expired or excessive lifetime")
    if mission["kind"] != "READ_ONLY_HASH":
        raise ValueError("operation denied")
    if not isinstance(mission["payload"], str) or not _PAYLOAD.fullmatch(mission["payload"]):
        raise ValueError("synthetic payload required")
    return {"kind": "READ_ONLY_HASH_RESULT", "source_sha": trusted_source_sha,
            "nonce": mission["nonce"],
            "payload_sha256": hashlib.sha256(mission["payload"].encode("utf-8")).hexdigest(),
            "scope": "PURE_LOCAL_TEST_ONLY_NOT_AUTHORIZED_DISPATCH"}
