"""P33: invoke the existing owner deterministic oracle after a local effect.

This is NOT a new signer, validator database, or Chat receiver. It delegates
exclusively to Runtime.verify and Runtime.proof_is_accepted_for_gate. Its
result is a point-in-time local observation: for future use, a trusted owner
must query the proof again in its original store and verification environment.
Neither worker fields nor an Outbox adapter ACK can establish PASS.
"""
from dataclasses import dataclass
import re

from .core import GuardError, Runtime

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class OwnerOracleObservation:
    task_id: str
    run_id: str
    evidence_id: str
    outcome: str
    environment: str
    output_version: int
    output_sha256: str
    accepted_at_observation: bool
    signed_generative_proof: bool = False
    remote_effect_authorized: bool = False


def verify_local_exact_sha(runtime, task_id, expected_run_id, environment, *,
                           owner_output_resource, owner_expected_sha256):
    """Read immutable owner pins then call the existing independent verifier.

    The caller is the trusted *owner controller*, not a worker IPC function.
    A mismatch blocks BEFORE Runtime.verify can mutate task/evidence state.
    """
    if type(runtime) is not Runtime:
        raise GuardError("trusted owner Runtime required", "BLOCK")
    for field in (task_id, expected_run_id, owner_output_resource, environment):
        if type(field) is not str or not 1 <= len(field) <= 200:
            raise GuardError("bounded owner identity required", "BLOCK")
    if type(owner_expected_sha256) is not str or not _SHA256.fullmatch(owner_expected_sha256):
        raise GuardError("valid pinned owner SHA-256 required", "BLOCK")
    with runtime.transaction():
        task = runtime.task(task_id)
        run = runtime.db.execute("SELECT task,state FROM runs WHERE id=?", (expected_run_id,)).fetchone()
        if (task["validation_mode"] != "DETERMINISTIC_EXACT_SHA"
                or task["output"] != owner_output_resource
                or task["expected_sha"] != owner_expected_sha256
                or not run or run["task"] != task_id or run["state"] != "SUCCEEDED"):
            raise GuardError("owner run, target or oracle contract mismatch", "BLOCK")
    result = runtime.verify(task_id, environment, expected_run_id=expected_run_id)
    # Re-query the owner database; a returned dict alone is not an oracle.
    evidence_id = result["evidence"]
    with runtime.transaction():
        evidence = runtime._evidence(evidence_id)
        task = runtime.task(task_id)
        output = runtime.resource(task["output"])
        accepted = runtime._proof_is_accepted_for_gate(evidence, environment)
        if evidence["run"] != expected_run_id or evidence["task"] != task_id:
            raise GuardError("foreign independent evidence", "BLOCK")
        if result["outcome"] == "PASS" and not accepted:
            raise GuardError("owner evidence stale before observation", "BLOCK")
        return OwnerOracleObservation(task_id, expected_run_id, evidence_id,
                                      evidence["outcome"], environment,
                                      output["version"], output["sha"], accepted)
