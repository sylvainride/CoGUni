"""Trusted controller credential rotation; never a worker IPC operation.

SQLite serializes rotation, revocation and local effects with BEGIN IMMEDIATE.
Only token_hash changes: existing grants, deadlines and fencing remain intact.
This owner API provides no remote authentication or user session protocol.
"""
from dataclasses import dataclass, field
import hmac
import secrets

from .core import GuardError, digest


@dataclass(frozen=True)
class CredentialRotation:
    run_id: str
    token: str = field(repr=False)
    fence: int
    expires: float


def _validate_arguments(runtime, run_id, current_token, expected_fence):
    runtime._id(run_id)
    if (not isinstance(current_token, str) or not current_token
            or len(current_token) > 256
            or any(ord(character) > 127 for character in current_token)):
        raise GuardError("invalid credential")
    if type(expected_fence) is not int or expected_fence < 1:
        raise GuardError("invalid credential fence", "BLOCK")


def _validated_current(runtime, run_id, current_token, expected_fence):
    """Caller owns the transaction; all observations share its snapshot."""
    run = runtime.db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    current_hash = digest(current_token)
    if not run or not hmac.compare_digest(run["token_hash"], current_hash):
        raise GuardError("invalid credential")
    if run["state"] not in {"RUNNING", "SUCCEEDED"}:
        raise GuardError("credential run not active", "BLOCK")
    task = runtime.task(run["task"])
    grants = runtime.db.execute("SELECT * FROM grants WHERE run=?", (run_id,)).fetchall()
    required_scopes = {(task["input"], "artifact.read"), (task["output"], "artifact.write")}
    now = runtime.clock()
    if (len(grants) != len(required_scopes)
            or {(row["resource"], row["tool"]) for row in grants} != required_scopes
            or any(row["revoked"] or row["expires"] <= now for row in grants)):
        raise GuardError("scope absent, expired or revoked")
    lease = runtime.db.execute("SELECT * FROM leases WHERE run=?", (run_id,)).fetchone()
    if (not lease or lease["resource"] != task["output"]
            or lease["fence"] != expected_fence or lease["expires"] <= now):
        raise GuardError("stale fencing token", "BLOCK")
    return current_hash, lease


def assert_run_credentials_active(runtime, run_id, current_token, *, expected_fence):
    """Owner checks a retained broker credential, including before ``done``.

    Failure means the controller must refuse/close that worker channel. This
    check does not reserve future rights: actual writes retain their own atomic
    Runtime.execute authorization against concurrent rotation or revocation.
    """
    _validate_arguments(runtime, run_id, current_token, expected_fence)
    with runtime.transaction():
        _validated_current(runtime, run_id, current_token, expected_fence)


def rotate_run_token(runtime, run_id, current_token, *, expected_fence):
    """Rotate an authenticated current run token with CAS, preserving grants.

    The caller is the trusted owner/controller, not a worker. The current token
    and fence identify the credential to replace. Revoke/expiry/terminal state
    always win once committed. No secret or token hash enters the audit log.
    A committed local receipt can be replayed with the replacement token only
    while its original grants and lease remain valid.
    """
    _validate_arguments(runtime, run_id, current_token, expected_fence)
    with runtime.transaction():
        current_hash, lease = _validated_current(runtime, run_id, current_token, expected_fence)
        replacement = secrets.token_urlsafe(32)
        if (not isinstance(replacement, str) or not replacement
                or len(replacement) > 256
                or any(ord(character) > 127 for character in replacement)):
            raise GuardError("credential generator failure", "BLOCK")
        replacement_hash = digest(replacement)
        if (hmac.compare_digest(current_hash, replacement_hash)
                or runtime.db.execute("SELECT 1 FROM runs WHERE token_hash=? LIMIT 1", (replacement_hash,)).fetchone()):
            raise GuardError("credential rotation collision", "BLOCK")
        changed = runtime.db.execute(
            "UPDATE runs SET token_hash=? WHERE id=? AND token_hash=? AND state IN ('RUNNING','SUCCEEDED')",
            (replacement_hash, run_id, current_hash),
        ).rowcount
        if changed != 1:
            raise GuardError("credential rotation CAS failed", "BLOCK")
        runtime._event("owner", "credential.rotate", run_id, "ROTATED")
        return CredentialRotation(run_id, replacement, lease["fence"], lease["expires"])
