"""Transactional local artifact runtime.

The owner control API is trusted. Worker intents use per-run credentials and exact
grants. This library does NOT isolate a hostile process from the host or SQLite.
The deterministic pool remains restricted to its three jobs. Optional generated
candidates require a separate owner policy verifier, never a worker's PASS.
Schema 4 preserves v7 pinning and adds explicit validation/policy contracts.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import time
import tempfile
import uuid

from .dag import topological_order


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class GuardError(Exception):
    def __init__(self, reason, decision="DENY"):
        self.reason, self.decision = reason, decision
        super().__init__(reason)


@dataclass(frozen=True)
class Intent:
    run_id: str
    tool: str
    resource: str
    expected_version: int
    key: str
    fence: int
    args: dict = field(default_factory=dict)


SCHEMA = """
CREATE TABLE resources(id TEXT PRIMARY KEY, content TEXT NOT NULL, version INTEGER NOT NULL, sha TEXT NOT NULL);
CREATE TABLE tasks(id TEXT PRIMARY KEY, input TEXT NOT NULL REFERENCES resources(id), output TEXT NOT NULL REFERENCES resources(id), action TEXT NOT NULL, expected_sha TEXT NOT NULL, input_version INTEGER NOT NULL, status TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1);
CREATE TABLE deps(task TEXT REFERENCES tasks(id), parent TEXT REFERENCES tasks(id), PRIMARY KEY(task,parent));
CREATE TABLE runs(id TEXT PRIMARY KEY, task TEXT NOT NULL REFERENCES tasks(id), worker TEXT NOT NULL, token_hash TEXT NOT NULL, state TEXT NOT NULL, started REAL NOT NULL, ended REAL, output_version INTEGER, input_version INTEGER NOT NULL);
CREATE TABLE run_dependencies(run TEXT NOT NULL REFERENCES runs(id), parent TEXT NOT NULL REFERENCES tasks(id), revision INTEGER NOT NULL, PRIMARY KEY(run,parent));
CREATE TABLE grants(run TEXT REFERENCES runs(id), resource TEXT REFERENCES resources(id), tool TEXT NOT NULL, expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(run,resource,tool));
CREATE TABLE leases(resource TEXT PRIMARY KEY REFERENCES resources(id), run TEXT REFERENCES runs(id), expires REAL NOT NULL, fence INTEGER NOT NULL);
CREATE TABLE effects(key TEXT PRIMARY KEY, run TEXT NOT NULL REFERENCES runs(id), fingerprint TEXT NOT NULL, resource TEXT NOT NULL, state TEXT NOT NULL, receipt TEXT);
CREATE TABLE evidence(id TEXT PRIMARY KEY, task TEXT NOT NULL REFERENCES tasks(id), run TEXT NOT NULL REFERENCES runs(id), method TEXT NOT NULL, outcome TEXT NOT NULL, input_version INTEGER NOT NULL, output_version INTEGER NOT NULL, output_sha TEXT NOT NULL, environment TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE sources(id TEXT PRIMARY KEY, resource TEXT NOT NULL REFERENCES resources(id), version INTEGER NOT NULL, sha TEXT NOT NULL, classification TEXT NOT NULL);
CREATE TABLE approvals(id TEXT PRIMARY KEY, action_digest TEXT NOT NULL, expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL, metadata TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'immutable event'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'immutable event'); END;
CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence BEGIN SELECT RAISE(ABORT,'immutable evidence'); END;
CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence BEGIN SELECT RAISE(ABORT,'immutable evidence'); END;
PRAGMA application_id=1129664565;
PRAGMA user_version=2;
"""


class Runtime:
    MAX_CONTENT = 1_000_000
    ACTIONS = {"copy", "uppercase", "sha256"}

    def __init__(self, path, clock=time.time):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        # sqlite3's context manager commits/rolls back, but does not close. Any
        # exception after connect (including migration and WAL setup) must close
        # the owned connection rather than leave it for garbage collection.
        try:
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA busy_timeout=10000")
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                if self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
                    raise GuardError("foreign database")
                self.db.executescript("BEGIN IMMEDIATE;" + SCHEMA + "COMMIT;")
                version = 2
            elif version == 1:
                required = {"resources", "tasks", "deps", "runs", "grants", "leases", "effects", "evidence", "sources", "approvals", "events"}
                present = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not required <= present:
                    raise GuardError("foreign schema cannot be migrated")
                # Conservatively stop old active runs: their dependency snapshot is missing.
                with self.transaction():
                    self.db.execute("CREATE TABLE run_dependencies(run TEXT NOT NULL REFERENCES runs(id), parent TEXT NOT NULL REFERENCES tasks(id), revision INTEGER NOT NULL, PRIMARY KEY(run,parent))")
                    self.db.execute("UPDATE tasks SET status='BLOCKED',revision=revision+1 WHERE id IN (SELECT task FROM runs WHERE state IN ('RUNNING','SUCCEEDED'))")
                    self.db.execute("UPDATE runs SET state='SUSPECT' WHERE state IN ('RUNNING','SUCCEEDED')")
                    self.db.execute("UPDATE tasks SET status='PARTIAL',revision=revision+1 WHERE status='VERIFIED' AND EXISTS(SELECT 1 FROM deps WHERE deps.task=tasks.id)")
                    self.db.execute("PRAGMA application_id=1129664565")
                    self.db.execute("PRAGMA user_version=2")
                    self._event("controller", "migrate", "schema", "V2")
                version = 2
            elif version not in (2, 3, 4) or self.db.execute("PRAGMA application_id").fetchone()[0] != 1129664565:
                raise GuardError("unsupported schema version")
            if version == 2:
                with self.transaction():
                    self.db.execute("ALTER TABLE tasks ADD COLUMN input_mode TEXT NOT NULL DEFAULT 'PINNED_VERSION'")
                    self.db.execute("ALTER TABLE tasks ADD COLUMN producer TEXT REFERENCES tasks(id) DEFERRABLE INITIALLY DEFERRED")
                    self.db.execute("ALTER TABLE tasks ADD COLUMN source_expected_sha TEXT")
                    self.db.execute("CREATE TABLE run_input_bindings(run TEXT PRIMARY KEY REFERENCES runs(id), producer TEXT NOT NULL REFERENCES tasks(id), producer_run TEXT NOT NULL REFERENCES runs(id), evidence TEXT NOT NULL REFERENCES evidence(id), resource TEXT NOT NULL REFERENCES resources(id), version INTEGER NOT NULL, sha TEXT NOT NULL, environment TEXT NOT NULL)")
                    self.db.execute("CREATE TRIGGER binding_no_update BEFORE UPDATE ON run_input_bindings BEGIN SELECT RAISE(ABORT,'immutable binding'); END")
                    self.db.execute("CREATE TRIGGER binding_no_delete BEFORE DELETE ON run_input_bindings BEGIN SELECT RAISE(ABORT,'immutable binding'); END")
                    self.db.execute("PRAGMA user_version=3")
                    self._event("controller", "migrate", "schema", "V3_PINNED_DEFAULT")
                version = 3
            if version == 3:
                with self.transaction():
                    self.db.execute("CREATE TABLE validation_policies(id TEXT PRIMARY KEY,body TEXT NOT NULL,sha TEXT NOT NULL,created REAL NOT NULL)")
                    self.db.execute("CREATE TABLE validation_policy_revocations(id TEXT PRIMARY KEY REFERENCES validation_policies(id),created REAL NOT NULL,reason TEXT NOT NULL)")
                    self.db.execute("CREATE TABLE generative_keys(epoch INTEGER PRIMARY KEY,secret BLOB NOT NULL,created REAL NOT NULL)")
                    self.db.execute("CREATE TABLE generative_evaluations(evidence TEXT PRIMARY KEY REFERENCES evidence(id),policy TEXT NOT NULL REFERENCES validation_policies(id),epoch INTEGER NOT NULL REFERENCES generative_keys(epoch),body TEXT NOT NULL,signature TEXT NOT NULL)")
                    for table in ("validation_policies", "validation_policy_revocations", "generative_keys", "generative_evaluations"):
                        for operation in ("UPDATE", "DELETE"):
                            self.db.execute(f"CREATE TRIGGER {table}_no_{operation.lower()} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'immutable validation record'); END")
                    self.db.execute("ALTER TABLE tasks ADD COLUMN validation_mode TEXT NOT NULL DEFAULT 'DETERMINISTIC_EXACT_SHA'")
                    self.db.execute("ALTER TABLE tasks ADD COLUMN policy_id TEXT REFERENCES validation_policies(id)")
                    self.db.execute("ALTER TABLE tasks ADD COLUMN source_policy_id TEXT REFERENCES validation_policies(id)")
                    self.db.execute("ALTER TABLE run_input_bindings ADD COLUMN producer_policy_sha TEXT")
                    self.db.execute("ALTER TABLE run_input_bindings ADD COLUMN producer_epoch INTEGER")
                    self.db.execute("PRAGMA user_version=4")
                    self._event("controller", "migrate", "schema", "V4_STRICT_DEFAULT")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException as original:
            # SQLITE_FULL/IOERR can already roll back the transaction. Preserve
            # that original error instead of masking it with a second rollback.
            try:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
            except BaseException as cleanup:
                # A failed rollback leaves a poisoned connection: never allow a
                # later operation to accidentally commit the unfinished write.
                if hasattr(original, "add_note"):
                    original.add_note("Rollback failed: " + type(cleanup).__name__)
                try:
                    self.db.close()
                except BaseException as closing:
                    if hasattr(original, "add_note"):
                        original.add_note("Connection close failed: " + type(closing).__name__)
            raise

    def _event(self, actor, action, target, outcome, metadata=None):
        # Payloads, credentials and source content are deliberately excluded.
        previous_row = self.db.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        previous = previous_row[0] if previous_row else "0" * 64
        # SQLite persists this column as REAL; hash the same representation even
        # when a trusted test/controller clock returns an integer.
        data = [float(self.clock()), actor, action, target, outcome, canonical(metadata or {}), previous]
        self.db.execute("INSERT INTO events(at,actor,action,target,outcome,metadata,previous,hash) VALUES(?,?,?,?,?,?,?,?)", (*data, digest(canonical(data))))

    def check_journal(self):
        previous = "0" * 64
        for row in self.db.execute("SELECT * FROM events ORDER BY id"):
            values = [row[k] for k in ("at", "actor", "action", "target", "outcome", "metadata", "previous")]
            if row["previous"] != previous or row["hash"] != digest(canonical(values)):
                return False
            previous = row["hash"]
        return True

    @staticmethod
    def _id(value):
        if not isinstance(value, str) or not value or len(value) > 200 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:" for c in value):
            raise GuardError("invalid identifier")

    def resource(self, resource):
        row = self.db.execute("SELECT * FROM resources WHERE id=?", (resource,)).fetchone()
        if not row:
            raise GuardError("unknown resource")
        return dict(row)

    def _invalidate(self, resource):
        affected = {row[0] for row in self.db.execute("SELECT id FROM tasks WHERE status='VERIFIED' AND (input=? OR output=?)", (resource, resource))}
        self._invalidate_tasks(affected, {"resource": resource})

    def _invalidate_tasks(self, affected, metadata):
        """Transaction-owned conservative invalidation, including descendants."""
        affected = set(affected)
        children = {}
        for child, parent in self.db.execute("SELECT task,parent FROM deps"):
            children.setdefault(parent, []).append(child)
        pending = list(affected)
        while pending:
            for child in children.get(pending.pop(), []):
                if child not in affected:
                    affected.add(child)
                    pending.append(child)
        for task in affected:
            self.db.execute("UPDATE tasks SET status='PARTIAL', revision=revision+1 WHERE id=? AND status='VERIFIED'", (task,))
            self._event("controller", "invalidate", task, "STALE", metadata)

    def _dependencies_current_shallow(self, run):
        expected = self.db.execute("SELECT count(*) FROM deps JOIN runs ON runs.task=deps.task WHERE runs.id=?", (run,)).fetchone()[0]
        captured = self.db.execute("SELECT count(*) FROM run_dependencies WHERE run=?", (run,)).fetchone()[0]
        if expected != captured:
            return False
        # Equal cardinality alone does not prove the prerequisite identities
        # stayed the same (one parent may have been replaced by another).
        if self.db.execute("SELECT 1 FROM run_dependencies JOIN runs ON runs.id=run_dependencies.run LEFT JOIN deps ON deps.task=runs.task AND deps.parent=run_dependencies.parent WHERE run_dependencies.run=? AND deps.parent IS NULL", (run,)).fetchone():
            return False
        return not self.db.execute("SELECT 1 FROM run_dependencies JOIN tasks ON tasks.id=run_dependencies.parent WHERE run_dependencies.run=? AND (tasks.status!='VERIFIED' OR tasks.revision!=run_dependencies.revision)", (run,)).fetchone()

    def _proof_base_is_accepted(self, row, environment):
        """Transaction-owned predicate; lineage is checked separately iteratively."""
        task = self.task(row["task"])
        run = self.db.execute("SELECT * FROM runs WHERE id=?", (row["run"],)).fetchone()
        revoked = self.db.execute("SELECT 1 FROM events WHERE action='evidence.revoke' AND target=? AND outcome='REVOKED' LIMIT 1", (row["id"],)).fetchone()
        source, output = self.resource(task["input"]), self.resource(task["output"])
        if task["input_mode"] in {"VERIFIED_UPSTREAM_OUTPUT", "VERIFIED_UPSTREAM_POLICY_OUTPUT"}:
            binding = self.db.execute("SELECT environment FROM run_input_bindings WHERE run=?", (row["run"],)).fetchone()
            if not binding or binding["environment"] != environment:
                return False
        if task["validation_mode"] == "DETERMINISTIC_EXACT_SHA":
            validation = row["method"] == "sha256_equals_owner_contract" and row["output_sha"] == task["expected_sha"]
        elif task["validation_mode"] == "GENERATIVE_POLICY_VALIDATED":
            from .generative import generative_proof_accepted
            validation = row["method"] == "independent_generative_policy_v1" and generative_proof_accepted(self, row, environment)
        else:
            validation = False
        return bool(row["outcome"] == "PASS" and row["environment"] == environment
                    and validation
                    and task["status"] == "VERIFIED" and run and run["state"] == "VERIFIED"
                    and task["input_version"] == row["input_version"]
                    and run["task"] == row["task"] and run["input_version"] == row["input_version"]
                    and run["output_version"] == row["output_version"] and not revoked
                    and source["version"] == row["input_version"]
                    and output["version"] == row["output_version"] and output["sha"] == row["output_sha"])

    def _dependencies_current(self, run):
        """Direct control deps plus exact upstream proof lineage, without recursion."""
        pending, seen = [run], set()
        while pending:
            current = pending.pop()
            if current in seen:
                return False  # single-input lineage cannot have a legitimate cycle
            seen.add(current)
            if not self._dependencies_current_shallow(current):
                return False
            current_run = self.db.execute("SELECT * FROM runs WHERE id=?", (current,)).fetchone()
            if not current_run:
                return False
            task = self.task(current_run["task"])
            if task["validation_mode"] == "GENERATIVE_POLICY_VALIDATED" and (not self.db.execute("SELECT 1 FROM validation_policies WHERE id=?", (task["policy_id"],)).fetchone() or self.db.execute("SELECT 1 FROM validation_policy_revocations WHERE id=?", (task["policy_id"],)).fetchone()):
                return False
            binding = self.db.execute("SELECT * FROM run_input_bindings WHERE run=?", (current,)).fetchone()
            if task["input_mode"] == "PINNED_VERSION":
                if binding is not None:
                    return False
                continue
            if task["input_mode"] not in {"VERIFIED_UPSTREAM_OUTPUT", "VERIFIED_UPSTREAM_POLICY_OUTPUT"} or not binding:
                return False
            producer = self.task(binding["producer"])
            row = self.db.execute("SELECT * FROM evidence WHERE id=?", (binding["evidence"],)).fetchone()
            if (binding["producer"] != task["producer"] or binding["resource"] != task["input"]
                    or producer["output"] != task["input"] or binding["version"] != current_run["input_version"]
                    or not row
                    or row["task"] != binding["producer"] or row["run"] != binding["producer_run"]
                    or row["output_version"] != binding["version"] or row["output_sha"] != binding["sha"]
                    or not self._proof_base_is_accepted(row, binding["environment"])):
                return False
            if task["input_mode"] == "VERIFIED_UPSTREAM_OUTPUT":
                if binding["sha"] != task["source_expected_sha"] or binding["producer_policy_sha"] is not None or binding["producer_epoch"] is not None:
                    return False
            else:
                policy = self.db.execute("SELECT sha FROM validation_policies WHERE id=?", (task["source_policy_id"],)).fetchone()
                evaluation = self.db.execute("SELECT epoch,policy FROM generative_evaluations WHERE evidence=?", (row["id"],)).fetchone()
                if (producer["validation_mode"] != "GENERATIVE_POLICY_VALIDATED" or producer["policy_id"] != task["source_policy_id"]
                        or not policy or binding["producer_policy_sha"] != policy["sha"] or not evaluation
                        or evaluation["policy"] != task["source_policy_id"] or binding["producer_epoch"] != evaluation["epoch"]):
                    return False
            pending.append(binding["producer_run"])
        return True

    def _validate_input_mode(self, mode, producer, source_expected_sha, parents, source_policy_id=None):
        if mode == "PINNED_VERSION":
            if producer is not None or source_expected_sha is not None or source_policy_id is not None:
                raise GuardError("pinned input cannot select a producer")
        elif mode == "VERIFIED_UPSTREAM_OUTPUT":
            self._id(producer)
            if source_policy_id is not None or producer not in parents or not isinstance(source_expected_sha, str) or len(source_expected_sha) != 64 or any(c not in "0123456789abcdef" for c in source_expected_sha):
                raise GuardError("explicit producer, dependency and source SHA required")
        elif mode == "VERIFIED_UPSTREAM_POLICY_OUTPUT":
            self._id(producer)
            self._id(source_policy_id)
            if producer not in parents or source_expected_sha is not None:
                raise GuardError("explicit producer dependency and policy required")
        else:
            raise GuardError("unknown input mode")

    def _validate_producer_contract(self, task_id):
        task = self.task(task_id)
        if task["input_mode"] == "PINNED_VERSION":
            return
        producer = self.task(task["producer"])
        producers = [row[0] for row in self.db.execute("SELECT tasks.id FROM deps JOIN tasks ON tasks.id=deps.parent WHERE deps.task=? AND tasks.output=?", (task_id, task["input"]))]
        if producers != [task["producer"]]:
            raise GuardError("ambiguous or incompatible producer contract")
        if task["input_mode"] == "VERIFIED_UPSTREAM_OUTPUT":
            if producer["validation_mode"] != "DETERMINISTIC_EXACT_SHA" or producer["expected_sha"] != task["source_expected_sha"]:
                raise GuardError("incompatible exact SHA producer contract")
        elif producer["validation_mode"] != "GENERATIVE_POLICY_VALIDATED" or producer["policy_id"] != task["source_policy_id"]:
            raise GuardError("incompatible producer policy contract")

    def _resolve_upstream(self, task, environment):
        if not isinstance(environment, str) or not environment or len(environment) > 200:
            raise GuardError("trusted environment required for upstream input", "BLOCK")
        self._validate_producer_contract(task["id"])
        candidates = self.db.execute("SELECT * FROM evidence WHERE task=? AND outcome='PASS' ORDER BY created DESC,id", (task["producer"],)).fetchall()
        accepted = [row for row in candidates if self._proof_is_accepted_for_gate(row, environment)]
        if len(accepted) != 1:
            raise GuardError("unique accepted producer proof required", "BLOCK")
        row = accepted[0]
        source = self.resource(task["input"])
        if row["output_version"] != source["version"] or source["sha"] != row["output_sha"] or (task["input_mode"] == "VERIFIED_UPSTREAM_OUTPUT" and row["output_sha"] != task["source_expected_sha"]):
            raise GuardError("upstream artifact contract stale", "BLOCK")
        result = {"producer": task["producer"], "producer_run": row["run"], "evidence": row["id"],
                "resource": task["input"], "version": source["version"], "sha": source["sha"], "environment": environment}
        if task["input_mode"] == "VERIFIED_UPSTREAM_POLICY_OUTPUT":
            result["producer_policy_sha"] = self.db.execute("SELECT sha FROM validation_policies WHERE id=?", (task["source_policy_id"],)).fetchone()[0]
            result["producer_epoch"] = self.db.execute("SELECT epoch FROM generative_evaluations WHERE evidence=?", (row["id"],)).fetchone()[0]
        return result

    def put_resource(self, resource, content, expected_version=None):
        """Trusted OWNER provisioning / CAS; never exposed as a worker tool."""
        self._id(resource)
        if not isinstance(content, str) or len(content.encode("utf-8")) > self.MAX_CONTENT:
            raise GuardError("invalid resource content")
        with self.transaction():
            row = self.db.execute("SELECT version FROM resources WHERE id=?", (resource,)).fetchone()
            if row:
                if expected_version != row[0]:
                    raise GuardError("stale resource version", "BLOCK")
                lease = self.db.execute("SELECT expires FROM leases WHERE resource=?", (resource,)).fetchone()
                if lease and lease[0] > self.clock():
                    raise GuardError("resource leased", "BLOCK")
                version = row[0] + 1
                self.db.execute("UPDATE resources SET content=?,version=?,sha=? WHERE id=?", (content, version, digest(content), resource))
                self._invalidate(resource)
            else:
                if expected_version not in (None, 0):
                    raise GuardError("stale resource version", "BLOCK")
                version = 1
                self.db.execute("INSERT INTO resources VALUES(?,?,?,?)", (resource, content, version, digest(content)))
            self._event("owner", "resource.put", resource, "COMMITTED", {"version": version, "sha": digest(content)})
        return version

    def _validate_task_contract(self, task, source, output, action, expected_sha, dependencies, validation_mode="DETERMINISTIC_EXACT_SHA", policy_id=None):
        self._id(task)
        self._id(source)
        self._id(output)
        if source == output or not isinstance(action, str):
            raise GuardError("invalid task contract")
        if validation_mode == "DETERMINISTIC_EXACT_SHA":
            if policy_id is not None or action not in self.ACTIONS or not isinstance(expected_sha, str) or len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
                raise GuardError("invalid task contract")
        elif validation_mode == "GENERATIVE_POLICY_VALIDATED":
            self._id(policy_id)
            if action != "candidate" or expected_sha is not None:
                raise GuardError("invalid generative task contract")
        else:
            raise GuardError("unknown validation mode")
        if isinstance(dependencies, (str, bytes, dict)):
            raise GuardError("invalid dependencies")
        try:
            parents = set(dependencies)
        except TypeError:
            raise GuardError("invalid dependencies") from None
        for parent in parents:
            self._id(parent)
        return parents

    def _insert_task(self, task, source, output, action, expected_sha, input_mode="PINNED_VERSION", producer=None, source_expected_sha=None, validation_mode="DETERMINISTIC_EXACT_SHA", policy_id=None, source_policy_id=None):
        """Transaction-owned insert; source version is captured under the lock."""
        input_version = self.resource(source)["version"]
        self.resource(output)
        if validation_mode == "GENERATIVE_POLICY_VALIDATED":
            policy = self.db.execute("SELECT 1 FROM validation_policies WHERE id=? AND NOT EXISTS(SELECT 1 FROM validation_policy_revocations WHERE id=?)", (policy_id,policy_id)).fetchone()
            if not policy:
                raise GuardError("active owner policy required", "BLOCK")
        self.db.execute("INSERT INTO tasks(id,input,output,action,expected_sha,input_version,status,input_mode,producer,source_expected_sha,validation_mode,policy_id,source_policy_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (task, source, output, action, expected_sha if expected_sha is not None else "", input_version, "READY", input_mode, producer, source_expected_sha, validation_mode, policy_id, source_policy_id))

    def add_task(self, task, source, output, action, expected_sha, dependencies=(), *, input_mode="PINNED_VERSION", producer=None, source_expected_sha=None, validation_mode="DETERMINISTIC_EXACT_SHA", policy_id=None, source_policy_id=None):
        parents = self._validate_task_contract(task, source, output, action, expected_sha, dependencies, validation_mode, policy_id)
        self._validate_input_mode(input_mode, producer, source_expected_sha, parents, source_policy_id)
        with self.transaction():
            self._insert_task(task, source, output, action, expected_sha, input_mode, producer, source_expected_sha, validation_mode, policy_id, source_policy_id)
            if task in parents:
                raise ValueError("dependency cycle")
            # This task is new. Every other prerequisite must already exist
            # (foreign key), and cannot already depend on a previously absent
            # node. Adding its outgoing prerequisites cannot introduce a cycle.
            for parent in sorted(parents):
                self.db.execute("INSERT INTO deps VALUES(?,?)", (task, parent))
            if input_mode != "PINNED_VERSION":
                self._validate_producer_contract(task)
            self._event("owner", "task.add", task, "READY", {"input_mode": input_mode})

    def add_tasks_batch(self, contracts):
        """Owner atomic import, including forward references within the batch.

        Validate the complete graph once after all nodes/edges are provisioned;
        any invalid resource, missing dependency, duplicate ID or cycle rolls
        back tasks, edges and audit events together. Returns IDs in input order.
        """
        if not isinstance(contracts, list):
            raise GuardError("invalid batch contracts")
        required = {"id", "source", "output", "action", "expected_sha"}
        normalized = []
        for contract in contracts:
            if not isinstance(contract, dict) or not required <= set(contract) or set(contract) - required - {"dependencies", "input_mode", "producer", "source_expected_sha", "validation_mode", "policy_id", "source_policy_id"}:
                raise GuardError("invalid batch contract schema")
            validation_mode, policy_id = contract.get("validation_mode", "DETERMINISTIC_EXACT_SHA"), contract.get("policy_id")
            parents = self._validate_task_contract(contract["id"], contract["source"], contract["output"], contract["action"], contract["expected_sha"], contract.get("dependencies", ()), validation_mode, policy_id)
            # Keep the validated immutable scalar fields, rather than retaining
            # a caller-owned mapping that could change before the transaction.
            mode = contract.get("input_mode", "PINNED_VERSION")
            producer, source_sha = contract.get("producer"), contract.get("source_expected_sha")
            source_policy_id = contract.get("source_policy_id")
            self._validate_input_mode(mode, producer, source_sha, parents, source_policy_id)
            normalized.append(({**{key: contract[key] for key in required}, "input_mode": mode, "producer": producer, "source_expected_sha": source_sha, "validation_mode": validation_mode, "policy_id": policy_id, "source_policy_id": source_policy_id}, parents))
        with self.transaction():
            for contract, _ in normalized:
                self._insert_task(contract["id"], contract["source"], contract["output"], contract["action"], contract["expected_sha"], contract["input_mode"], contract["producer"], contract["source_expected_sha"], contract["validation_mode"], contract["policy_id"], contract["source_policy_id"])
            for contract, parents in normalized:
                for parent in sorted(parents):
                    self.db.execute("INSERT INTO deps VALUES(?,?)", (contract["id"], parent))
            graph = {r[0]: [] for r in self.db.execute("SELECT id FROM tasks")}
            for child, parent in self.db.execute("SELECT task,parent FROM deps"):
                graph[child].append(parent)
            topological_order(graph)
            for contract, _ in normalized:
                if contract["input_mode"] != "PINNED_VERSION":
                    self._validate_producer_contract(contract["id"])
            for contract, _ in normalized:
                self._event("owner", "task.add", contract["id"], "READY", {"provisioning": "batch"})
        return [contract["id"] for contract, _ in normalized]

    def task(self, task):
        row = self.db.execute("SELECT * FROM tasks WHERE id=?", (task,)).fetchone()
        if not row:
            raise GuardError("unknown task")
        result = dict(row)
        if result["validation_mode"] == "GENERATIVE_POLICY_VALIDATED":
            result["expected_sha"] = None
        return result

    def add_dependency(self, task_id, parent, expected_revision):
        """Owner changes a not-yet-started contract with revision CAS and cycle rejection."""
        with self.transaction():
            task = self.task(task_id)
            self.task(parent)
            if task["status"] != "READY" or task["revision"] != expected_revision:
                raise GuardError("stale or active task contract", "BLOCK")
            # An edge task→parent creates a cycle precisely when parent already
            # reaches task by following prerequisites. Walk only those ancestors
            # iteratively, preserving deep-DAG safety and transaction/CAS checks.
            pending, visited = [parent], set()
            while pending:
                ancestor = pending.pop()
                if ancestor == task_id:
                    raise ValueError("dependency cycle")
                if ancestor not in visited:
                    visited.add(ancestor)
                    pending.extend(row[0] for row in self.db.execute("SELECT parent FROM deps WHERE task=?", (ancestor,)))
            self.db.execute("INSERT INTO deps VALUES(?,?)", (task_id, parent))
            if task["input_mode"] != "PINNED_VERSION":
                self._validate_producer_contract(task_id)
            self.db.execute("UPDATE tasks SET revision=revision+1 WHERE id=?", (task_id,))
            self._event("owner", "dependency.add", task_id, "COMMITTED", {"parent": parent})

    def abandon_run(self, run_id, reason="ipc_disconnected"):
        """Trusted controller disconnect handling; never discards a committed result.

        Reason is a controller-selected label, not an exception/payload dump.
        Expire only this run's lease, leaving any replacement holder untouched.
        """
        self._id(run_id)
        self._id(reason)
        with self.transaction():
            run = self.db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            if not run:
                raise GuardError("unknown run")
            if run["state"] != "RUNNING":
                return False
            self.db.execute("UPDATE runs SET state='SUSPECT',ended=? WHERE id=?", (self.clock(), run_id))
            self.db.execute("UPDATE tasks SET status='BLOCKED',revision=revision+1 WHERE id=?", (run["task"],))
            self.db.execute("UPDATE grants SET revoked=1 WHERE run=?", (run_id,))
            self.db.execute("UPDATE leases SET expires=? WHERE run=?", (self.clock(), run_id))
            self._event("controller", "run.abandon", run_id, "SUSPECT", {"reason": reason})
            return True

    def claim(self, worker, ttl=30, *, environment=None, supported_actions=None, task_id=None):
        self._id(worker)
        if not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or ttl <= 0 or ttl > 3600:
            raise GuardError("invalid lease duration")
        if supported_actions is not None and (not isinstance(supported_actions, (set,frozenset,list,tuple)) or not supported_actions or not set(supported_actions) <= self.ACTIONS | {"candidate"}):
            raise GuardError("invalid supported actions")
        if task_id is not None:
            self._id(task_id)
        with self.transaction():
            candidates = self.db.execute("SELECT * FROM tasks WHERE status='READY' AND NOT EXISTS(SELECT 1 FROM deps JOIN tasks p ON p.id=deps.parent WHERE deps.task=tasks.id AND p.status!='VERIFIED') ORDER BY id").fetchall()
            for task in candidates:
                task = dict(task)
                if task_id is not None and task["id"] != task_id:
                    continue
                if supported_actions is not None and task["action"] not in supported_actions:
                    continue
                if task["validation_mode"] == "GENERATIVE_POLICY_VALIDATED" and self.db.execute("SELECT 1 FROM validation_policy_revocations WHERE id=?", (task["policy_id"],)).fetchone():
                    self.db.execute("UPDATE tasks SET status='BLOCKED',revision=revision+1 WHERE id=?", (task["id"],))
                    self._event("controller","claim",task["id"],"POLICY_REVOKED")
                    continue
                binding = None
                if task["input_mode"] != "PINNED_VERSION":
                    try:
                        binding = self._resolve_upstream(task, environment)
                    except GuardError:
                        self.db.execute("UPDATE tasks SET status='BLOCKED',revision=revision+1 WHERE id=?", (task["id"],))
                        self._event("controller", "claim", task["id"], "UPSTREAM_UNACCEPTED")
                        continue
                    task["input_version"] = binding["version"]
                if self.resource(task["input"])["version"] != task["input_version"]:
                    self.db.execute("UPDATE tasks SET status='BLOCKED',revision=revision+1 WHERE id=?", (task["id"],))
                    self._event("controller", "claim", task["id"], "STALE_INPUT")
                    continue
                lease = self.db.execute("SELECT * FROM leases WHERE resource=?", (task["output"],)).fetchone()
                if lease and lease["expires"] > self.clock():
                    continue
                run = str(uuid.uuid4())
                token = secrets.token_urlsafe(32)
                fence = lease["fence"] + 1 if lease else 1
                expires = self.clock() + ttl
                self.db.execute("INSERT INTO runs(id,task,worker,token_hash,state,started,input_version) VALUES(?,?,?,?,?,?,?)", (run, task["id"], worker, digest(token), "RUNNING", self.clock(), task["input_version"]))
                if binding:
                    self.db.execute("INSERT INTO run_input_bindings VALUES(?,?,?,?,?,?,?,?,?,?)", (run, binding["producer"], binding["producer_run"], binding["evidence"], binding["resource"], binding["version"], binding["sha"], binding["environment"], binding.get("producer_policy_sha"), binding.get("producer_epoch")))
                self.db.execute("INSERT INTO run_dependencies SELECT ?,tasks.id,tasks.revision FROM deps JOIN tasks ON tasks.id=deps.parent WHERE deps.task=?", (run, task["id"]))
                self.db.execute("INSERT INTO leases VALUES(?,?,?,?) ON CONFLICT(resource) DO UPDATE SET run=excluded.run,expires=excluded.expires,fence=excluded.fence", (task["output"], run, expires, fence))
                for resource, tool in [(task["input"], "artifact.read"), (task["output"], "artifact.write")]:
                    self.db.execute("INSERT INTO grants(run,resource,tool,expires) VALUES(?,?,?,?)", (run, resource, tool, expires))
                self.db.execute("UPDATE tasks SET status='RUNNING',input_version=?,revision=revision+1 WHERE id=?", (task["input_version"], task["id"]))
                self._event(worker, "claim", task["id"], "RUNNING", {"run": run, "fence": fence})
                if task["validation_mode"] == "GENERATIVE_POLICY_VALIDATED":
                    task["expected_sha"] = None
                return {"run_id": run, "token": token, "fence": fence, "task": dict(task), "output_version": self.resource(task["output"])["version"]}
        return None

    def revoke(self, run):
        with self.transaction():
            self.db.execute("UPDATE grants SET revoked=1 WHERE run=?", (run,))
            self._event("owner", "revoke", run, "REVOKED")

    def _authorize(self, intent, token):
        if not isinstance(intent, Intent) or intent.tool not in {"artifact.read", "artifact.write"}:
            raise GuardError("unknown or disabled tool", "BLOCK")
        if not isinstance(intent.expected_version, int) or isinstance(intent.expected_version, bool) or not isinstance(intent.fence, int) or isinstance(intent.fence, bool):
            raise GuardError("invalid intent schema")
        self._id(intent.key)
        self._id(intent.resource)
        if not isinstance(intent.args, dict) or set(intent.args) != ({"content"} if intent.tool == "artifact.write" else set()):
            raise GuardError("invalid intent arguments")
        if intent.tool == "artifact.write":
            try:
                valid_content = isinstance(intent.args["content"], str) and len(intent.args["content"].encode("utf-8")) <= self.MAX_CONTENT
            except UnicodeEncodeError:
                valid_content = False
            if not valid_content:
                raise GuardError("invalid intent content")
        run = self.db.execute("SELECT * FROM runs WHERE id=?", (intent.run_id,)).fetchone()
        if not run or not isinstance(token, str) or not hmac.compare_digest(run["token_hash"], digest(token)):
            raise GuardError("invalid credential")
        grant = self.db.execute("SELECT * FROM grants WHERE run=? AND resource=? AND tool=?", (intent.run_id, intent.resource, intent.tool)).fetchone()
        if not grant or grant["revoked"] or grant["expires"] <= self.clock():
            raise GuardError("scope absent, expired or revoked")
        lease = self.db.execute("SELECT * FROM leases WHERE run=?", (intent.run_id,)).fetchone()
        if not lease or lease["fence"] != intent.fence or lease["expires"] <= self.clock():
            raise GuardError("stale fencing token", "BLOCK")
        return run

    def execute(self, intent, token):
        """Single mediated worker path. Local artifact writes and receipts commit together."""
        try:
            with self.transaction():
                run = self._authorize(intent, token)
                fingerprint = digest(canonical({"run": intent.run_id, "tool": intent.tool, "resource": intent.resource, "version": intent.expected_version, "args": intent.args, "fence": intent.fence}))
                old = self.db.execute("SELECT * FROM effects WHERE key=?", (intent.key,)).fetchone()
                if old:
                    if old["fingerprint"] != fingerprint:
                        raise GuardError("idempotency key collision")
                    if old["state"] != "COMMITTED":
                        raise GuardError("effect needs reconciliation", "RECONCILE")
                    self._event(run["worker"], "replay", intent.key, "NO_NEW_EFFECT")
                    return {**json.loads(old["receipt"]), "replayed": True}
                if run["state"] != "RUNNING":
                    raise GuardError("run not active", "BLOCK")
                task = self.task(run["task"])
                if not self._dependencies_current(intent.run_id):
                    raise GuardError("stale dependency contract", "BLOCK")
                if self.resource(task["input"])["version"] != run["input_version"]:
                    raise GuardError("stale input version", "BLOCK")
                row = self.resource(intent.resource)
                if row["version"] != intent.expected_version:
                    raise GuardError("stale resource version", "BLOCK")
                if intent.tool == "artifact.read":
                    self._event(run["worker"], intent.tool, intent.resource, "READ", {"version": row["version"], "sha": row["sha"]})
                    return {"content": row["content"], "version": row["version"], "sha": row["sha"]}
                version = row["version"] + 1
                content = intent.args["content"]
                self.db.execute("UPDATE resources SET content=?,version=?,sha=? WHERE id=? AND version=?", (content, version, digest(content), intent.resource, row["version"]))
                self._invalidate(intent.resource)
                receipt = {"resource": intent.resource, "version": version, "sha": digest(content), "replayed": False}
                self.db.execute("INSERT INTO effects VALUES(?,?,?,?,?,?)", (intent.key, intent.run_id, fingerprint, intent.resource, "COMMITTED", canonical(receipt)))
                self.db.execute("UPDATE runs SET state='SUCCEEDED',ended=?,output_version=? WHERE id=?", (self.clock(), version, intent.run_id))
                self.db.execute("UPDATE tasks SET status='RESULT_READY',revision=revision+1 WHERE id=?", (run["task"],))
                self._event(run["worker"], intent.tool, intent.resource, "COMMITTED", {"run": intent.run_id, "version": version, "sha": digest(content)})
                return receipt
        except GuardError as error:
            with self.transaction():
                # Do not trust attacker-controlled payloads for the audit log.
                self._event("worker", "intent.refused", "arbiter", error.decision, {"reason": error.reason})
            raise

    def verify(self, task_id, environment, expected_run_id=None):
        """Controller-owned deterministic verifier, never accepts a caller's PASS."""
        if not isinstance(environment, str) or not environment or len(environment) > 200:
            raise GuardError("invalid environment identity")
        if expected_run_id is not None and not isinstance(expected_run_id, str):
            raise GuardError("invalid expected run identity", "BLOCK")
        with self.transaction():
            task = self.task(task_id)
            if task["validation_mode"] != "DETERMINISTIC_EXACT_SHA":
                raise GuardError("independent generative policy verifier required", "BLOCK")
            if task["status"] != "RESULT_READY":
                raise GuardError("no terminal result to verify", "BLOCK")
            run = self.db.execute("SELECT * FROM runs WHERE task=? AND state='SUCCEEDED' ORDER BY started DESC LIMIT 1", (task_id,)).fetchone()
            if expected_run_id is not None and (not run or run["id"] != expected_run_id):
                raise GuardError("verification run identity changed", "BLOCK")
            source, output = self.resource(task["input"]), self.resource(task["output"])
            if task["input_mode"] != "PINNED_VERSION":
                binding = self.db.execute("SELECT environment FROM run_input_bindings WHERE run=?", (run["id"],)).fetchone() if run else None
                if not binding or binding["environment"] != environment:
                    raise GuardError("upstream verification environment changed", "BLOCK")
            if not run or not self._dependencies_current(run["id"]) or source["version"] != run["input_version"] or output["version"] != run["output_version"]:
                raise GuardError("stale evidence target", "BLOCK")
            passed = hmac.compare_digest(output["sha"], task["expected_sha"])
            evidence_id = str(uuid.uuid4())
            self.db.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?)", (evidence_id, task_id, run["id"], "sha256_equals_owner_contract", "PASS" if passed else "FAIL", source["version"], output["version"], output["sha"], environment, self.clock()))
            self.db.execute("UPDATE tasks SET status=?,revision=revision+1 WHERE id=?", ("VERIFIED" if passed else "FAILED", task_id))
            self.db.execute("UPDATE runs SET state=? WHERE id=?", ("VERIFIED" if passed else "FAILED", run["id"]))
            self.db.execute("UPDATE leases SET expires=? WHERE run=?", (self.clock(), run["id"]))
            self._event("verifier", "verify", task_id, "PASS" if passed else "FAIL", {"evidence": evidence_id})
            return {"evidence": evidence_id, "outcome": "PASS" if passed else "FAIL"}

    def _evidence(self, evidence_id):
        row = self.db.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row:
            raise GuardError("unknown evidence")
        return row

    def _proof_is_fresh(self, row):
        task = self.task(row["task"])
        return (self._dependencies_current(row["run"]) and row["input_version"] == self.resource(task["input"])["version"] and row["output_version"] == self.resource(task["output"])["version"] and row["output_sha"] == self.resource(task["output"])["sha"])

    def proof_is_fresh(self, evidence_id):
        """Whether the captured resources/dependencies still describe today.

        Freshness is deliberately independent of PASS, revocation and execution
        environment. A freshly measured failure remains useful diagnostic data.
        This informational predicate must never be used as a positive gate.
        """
        # Hold one read snapshot across the resource and dependency queries.
        with self.transaction():
            return self._proof_is_fresh(self._evidence(evidence_id))

    def proof_current(self, evidence_id):
        """V5 compatibility alias for freshness ONLY; never a gate predicate."""
        return self.proof_is_fresh(evidence_id)

    def proof_is_accepted_for_gate(self, evidence_id, environment):
        """Owner/controller gate decision in a consistent database snapshot.

        The gate supplies its trusted verification-environment identity; a worker
        must not select it. Exact equality is the conservative applicability
        policy, not an assertion of OS isolation or permission to publish.
        """
        if not isinstance(environment, str) or not environment or len(environment) > 200:
            raise GuardError("invalid environment identity")
        with self.transaction():
            return self._proof_is_accepted_for_gate(self._evidence(evidence_id), environment)

    def _proof_is_accepted_for_gate(self, row, environment):
        """Trusted transaction-owned gate helper; never starts a nested transaction."""
        return bool(self._proof_base_is_accepted(row, environment) and self._dependencies_current(row["run"]))

    def revoke_evidence(self, evidence_id, reason):
        """Trusted owner revocation; evidence and revocation remain append-only.

        Repeated revocation is a no-op. Revoking a verified task also invalidates
        its descendants so future claims cannot consume the revoked prerequisite.
        """
        if not isinstance(reason, str) or not reason or len(reason) > 200:
            raise GuardError("invalid revocation reason")
        with self.transaction():
            row = self._evidence(evidence_id)
            if self.db.execute("SELECT 1 FROM events WHERE action='evidence.revoke' AND target=? AND outcome='REVOKED' LIMIT 1", (evidence_id,)).fetchone():
                return False
            self._event("owner", "evidence.revoke", evidence_id, "REVOKED", {"reason": reason})
            if self.task(row["task"])["status"] == "VERIFIED":
                self._invalidate_tasks({row["task"]}, {"evidence": evidence_id})
            return True

    def recover(self):
        with self.transaction():
            runs = self.db.execute("SELECT * FROM runs WHERE state IN ('RUNNING','SUCCEEDED') AND NOT EXISTS(SELECT 1 FROM leases WHERE leases.run=runs.id AND leases.expires>?)", (self.clock(),)).fetchall()
            for run in runs:
                self.db.execute("UPDATE runs SET state='SUSPECT' WHERE id=?", (run["id"],))
                self.db.execute("UPDATE tasks SET status='BLOCKED',revision=revision+1 WHERE id=? AND status IN ('RUNNING','RESULT_READY')", (run["task"],))
                self.db.execute("UPDATE effects SET state='UNKNOWN' WHERE run=? AND state='PREPARED'", (run["id"],))
                self._event("controller", "recover", run["task"], "SUSPECT", {"run": run["id"]})
            return len(runs)

    def resume(self, task_id, *, environment=None):
        with self.transaction():
            task = self.task(task_id)
            if task["status"] != "BLOCKED":
                raise GuardError("task not blocked")
            if self.db.execute("SELECT 1 FROM effects JOIN runs ON runs.id=effects.run WHERE runs.task=? AND effects.state IN ('UNKNOWN','PREPARED')", (task_id,)).fetchone():
                raise GuardError("effect needs reconciliation", "RECONCILE")
            if task["input_mode"] != "PINNED_VERSION":
                self._resolve_upstream(task, environment)
            elif self.resource(task["input"])["version"] != task["input_version"]:
                raise GuardError("source contract must be refreshed", "BLOCK")
            self.db.execute("UPDATE tasks SET status='READY',revision=revision+1 WHERE id=?", (task_id,))
            self._event("owner", "resume", task_id, "READY")

    def source_snapshot(self, source_id, resource, classification="untrusted"):
        self._id(source_id)
        if classification not in {"owner_contract", "untrusted"}:
            raise GuardError("unknown trust classification")
        with self.transaction():
            row = self.resource(resource)
            old = self.db.execute("SELECT * FROM sources WHERE id=?", (source_id,)).fetchone()
            self.db.execute("INSERT INTO sources VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET resource=excluded.resource,version=excluded.version,sha=excluded.sha,classification=excluded.classification", (source_id, resource, row["version"], row["sha"], classification))
            if old is None or (old["resource"],old["version"],old["sha"],old["classification"]) != (resource,row["version"],row["sha"],classification):
                touched={resource} | ({old["resource"]} if old else set())
                affected={r[0] for item in touched for r in self.db.execute("SELECT id FROM tasks WHERE input=? AND input_mode='PINNED_VERSION' AND validation_mode='GENERATIVE_POLICY_VALIDATED' AND status='VERIFIED'",(item,))}
                self._invalidate_tasks(affected,{"source_pin":source_id})
            self._event("owner", "source.snapshot", source_id, "CAPTURED", {"version": row["version"], "sha": row["sha"]})

    def source_current(self, source_id):
        row = self.db.execute("SELECT * FROM sources WHERE id=?", (source_id,)).fetchone()
        if not row:
            raise GuardError("unknown source")
        resource = self.resource(row["resource"])
        return row["version"] == resource["version"] and row["sha"] == resource["sha"]

    def backup(self, target):
        """Owner backup of the DB; refuses overwrite and the active DB target."""
        target = Path(target)
        if target.exists() or target.resolve() == self.path.resolve():
            raise GuardError("backup target exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        # Publish a completed backup atomically without overwriting a race-created file.
        fd, temporary = tempfile.mkstemp(prefix=".universal-backup-", dir=target.parent)
        os.close(fd)
        copy = sqlite3.connect(temporary)
        try:
            self.db.backup(copy)
            copy.close()
            with open(temporary, "rb") as stream:
                os.fsync(stream.fileno())
            os.link(temporary, target)
            return digest_bytes(Path(temporary).read_bytes())
        finally:
            copy.close()
            Path(temporary).unlink(missing_ok=True)

    def snapshot(self):
        """Read-only owner export, omitting credentials, grants and resource content."""
        with self.transaction():
            result = {table: [dict(r) for r in self.db.execute(f"SELECT * FROM {table}")] for table in ("tasks", "deps", "sources", "evidence", "events", "run_input_bindings")}
            for task in result["tasks"]:
                if task["validation_mode"] == "GENERATIVE_POLICY_VALIDATED":
                    task["expected_sha"] = None
            result["validation_policies"] = [dict(r) for r in self.db.execute("SELECT id,sha,created FROM validation_policies")]
            result["resources"] = [dict(r) for r in self.db.execute("SELECT id,version,sha FROM resources")]
            result["schema_version"] = self.db.execute("PRAGMA user_version").fetchone()[0]
        return result


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()
