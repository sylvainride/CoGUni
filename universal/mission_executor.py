"""Bounded offline mission execution through the existing confined broker.

This trusted owner facade adds no database, signer, grants or worker opcode.
Inputs are synthetic strings, never executable code or external instructions.
The broker's isolated worker produces a candidate; its independent verifier and
Runtime's pinned SHA/current-proof predicate decide acceptance.
"""
import hashlib
import math
from pathlib import Path
import re

from .broker import environment_identity, run_pool
from .core import GuardError, Runtime, canonical, digest


_TASK = re.compile(r"mvp-[0-9a-f]{64}\Z")
_PAYLOAD = re.compile(r"(?:synthetic:[A-Za-z0-9._:-]+|[A-Za-z]+)\Z")


def _expected(payload, action):
    return payload.upper() if action == "uppercase" else hashlib.sha256(payload.encode("ascii")).hexdigest()


class DeterministicExecutor:
    """Trusted owner; runtime_path must refer to the owner's private store.

    A caller owns its mission authorization/revocation/expiry protocol. This
    executor never treats a transport ACK, a returned dict or worker PASS as an
    authorization to apply an effect to another project.
    """

    def __init__(self, runtime_path):
        self.runtime_path = Path(runtime_path)

    @staticmethod
    def task_id(key, payload, action="uppercase"):
        """Pure identity derivation; reading status never provisions a task."""
        Runtime._id(key)
        if (type(payload) is not str or not 1 <= len(payload) <= 256
                or not _PAYLOAD.fullmatch(payload)
                or type(action) is not str or action not in {"uppercase", "sha256"}):
            raise GuardError("bounded synthetic deterministic input required", "BLOCK")
        return "mvp-" + digest(canonical([key, payload, action]))

    def prepare(self, key, payload, action="uppercase"):
        """Atomically provision or replay one immutable synthetic contract."""
        task_id = self.task_id(key, payload, action)
        source_id, output_id = task_id + "-input", task_id + "-output"
        expected_sha = digest(_expected(payload, action))
        with Runtime(self.runtime_path) as runtime:
            with runtime.transaction():
                existing = runtime.db.execute("SELECT id FROM tasks WHERE id=?", (task_id,)).fetchone()
                if existing:
                    task = runtime.task(task_id)
                    source = runtime.resource(source_id)
                    if (task["input"] != source_id or task["output"] != output_id
                            or task["action"] != action or task["expected_sha"] != expected_sha
                            or task["input_mode"] != "PINNED_VERSION"
                            or task["validation_mode"] != "DETERMINISTIC_EXACT_SHA"
                            or source["content"] != payload or source["sha"] != digest(payload)
                            or source["version"] != task["input_version"]):
                        raise GuardError("synthetic task contract changed", "BLOCK")
                    return task_id
                # These insertions and _insert_task share the Runtime owner
                # transaction, avoiding partial provisioning after a crash.
                for resource_id, content in ((source_id, payload), (output_id, "")):
                    if runtime.db.execute("SELECT 1 FROM resources WHERE id=?", (resource_id,)).fetchone():
                        raise GuardError("synthetic resource identity collision", "BLOCK")
                    runtime.db.execute("INSERT INTO resources VALUES(?,?,?,?)",
                                       (resource_id, content, 1, digest(content)))
                    runtime._event("owner", "resource.put", resource_id, "COMMITTED",
                                   {"version": 1, "sha": digest(content)})
                runtime._validate_task_contract(task_id, source_id, output_id, action, expected_sha, ())
                runtime._insert_task(task_id, source_id, output_id, action, expected_sha)
                runtime._event("owner", "task.add", task_id, "READY",
                               {"input_mode": "PINNED_VERSION", "profile": "synthetic-mvp-v1"})
        return task_id

    @staticmethod
    def _contract(runtime, task_id):
        if type(task_id) is not str or not _TASK.fullmatch(task_id):
            raise GuardError("synthetic executor task required", "BLOCK")
        task = runtime.task(task_id)
        source = runtime.resource(task["input"])
        if (task["input"] != task_id + "-input" or task["output"] != task_id + "-output"
                or task["action"] not in {"uppercase", "sha256"}
                or not 1 <= len(source["content"]) <= 256
                or not _PAYLOAD.fullmatch(source["content"])
                or task["input_mode"] != "PINNED_VERSION"
                or task["validation_mode"] != "DETERMINISTIC_EXACT_SHA"
                or task["expected_sha"] != digest(_expected(source["content"], task["action"]))
                or task["input_version"] != source["version"]):
            raise GuardError("synthetic executor contract stale", "BLOCK")
        return task

    def run(self, task_id, timeout=30):
        """Run only READY, or recover RESULT_READY without replaying its write.

        Existing RUNNING, failed, revoked or stale work is never reset/retried.
        Concurrent owners can launch redundant confined readers but claim's
        transaction permits one run/effect, and no other READY task is claimed.
        A timeout propagates and the broker abandons uncommitted local work;
        callers must reconcile this store before deciding any future action.
        """
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            raise GuardError("bounded executor timeout required", "BLOCK")
        self._require_store()
        with Runtime(self.runtime_path) as runtime:
            with runtime.transaction():
                task = self._contract(runtime, task_id)
                should_run = task["status"] in {"READY", "RESULT_READY"}
        if should_run:
            run_pool(self.runtime_path, workers=1, max_jobs=1, timeout=timeout,
                     worker_names=["mvp-worker"], task_id=task_id)
        return self.result(task_id)

    def result(self, task_id):
        """Re-read accepted proof in the current environment; omit credentials."""
        self._require_store()
        environment = environment_identity()
        with Runtime(self.runtime_path) as runtime:
            with runtime.transaction():
                task = self._contract(runtime, task_id)
                output = runtime.resource(task["output"])
                run = runtime.db.execute("SELECT id,state FROM runs WHERE task=? ORDER BY started DESC,id LIMIT 1",
                                         (task_id,)).fetchone()
                evidence = runtime.db.execute("SELECT * FROM evidence WHERE task=? ORDER BY created DESC,id LIMIT 1",
                                              (task_id,)).fetchone()
                accepted = bool(evidence and run and evidence["run"] == run["id"]
                                and runtime._proof_is_accepted_for_gate(evidence, environment))
                raw_status = task["status"]
                status = ("COMPLETED" if accepted else raw_status
                          if raw_status in {"READY", "RUNNING", "RESULT_READY"} else "BLOCKED")
                return {"task_id": task_id, "task_status": raw_status, "status": status,
                        "run_id": run["id"] if run else None,
                        "evidence_id": evidence["id"] if evidence else None,
                        "content": output["content"], "output_sha256": output["sha"],
                        "output_version": output["version"], "environment": environment,
                        "accepted_for_gate": accepted}

    def _require_store(self):
        if not self.runtime_path.is_file() or self.runtime_path.is_symlink():
            raise GuardError("original owner runtime store required", "BLOCK")
