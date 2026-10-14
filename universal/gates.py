"""Owner-only, authenticated local gates; no release operation or worker endpoint.

The built-in fixture runners are deliberately synthetic validators. They
do not execute project tests, resolve a legal license, or certify absence of
secrets. Registering a runner is a trusted owner operation, not an agent right.
"""
from dataclasses import dataclass
import hashlib
import hmac
import inspect
import json
import math
import secrets
import uuid

from .core import GuardError, canonical, digest


CRITERIA = frozenset({"tests", "licenses", "secrets", "provenance", "consent", "environment"})
OUTCOMES = frozenset({"PASS", "FAIL", "UNKNOWN", "STALE"})
MAX_OBSERVATION_BYTES = 65_536


@dataclass(frozen=True)
class CheckResult:
    outcome: str
    reason: str
    expires_at: float | None = None


DDL = (
    "CREATE TABLE IF NOT EXISTS gate_keys(epoch INTEGER PRIMARY KEY, secret BLOB NOT NULL, created REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS gate_verifiers(id TEXT PRIMARY KEY, method TEXT NOT NULL, implementation_sha TEXT NOT NULL, criteria TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS gate_contracts(id TEXT PRIMARY KEY, epoch INTEGER NOT NULL REFERENCES gate_keys(epoch), body TEXT NOT NULL, signature TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS gate_attestations(sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, contract_id TEXT NOT NULL REFERENCES gate_contracts(id), criterion TEXT NOT NULL, epoch INTEGER NOT NULL REFERENCES gate_keys(epoch), body TEXT NOT NULL, signature TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS gate_revocations(attestation_id TEXT PRIMARY KEY REFERENCES gate_attestations(id), created REAL NOT NULL, reason TEXT NOT NULL)",
)


class GateEngine:
    """Trusted controller API; shares Runtime's one SQLite transaction owner."""

    def __init__(self, runtime):
        self.runtime = runtime
        self.runners = {}
        self.transactional_runners = set()
        with runtime.transaction():
            for sql in DDL:
                runtime.db.execute(sql)
            for table in ("gate_keys", "gate_verifiers", "gate_contracts", "gate_attestations", "gate_revocations"):
                for operation in ("UPDATE", "DELETE"):
                    runtime.db.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'immutable gate record'); END")
            if not runtime.db.execute("SELECT 1 FROM gate_keys LIMIT 1").fetchone():
                runtime.db.execute("INSERT INTO gate_keys VALUES(1,?,?)", (secrets.token_bytes(32), runtime.clock()))
                runtime._event("owner", "gate.key", "signer", "INITIALIZED", {"epoch": 1})

    def _key(self):
        return self.runtime.db.execute("SELECT * FROM gate_keys ORDER BY epoch DESC LIMIT 1").fetchone()

    @staticmethod
    def _signature(secret, body):
        return hmac.new(secret, canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _environment(environment):
        if not isinstance(environment, str) or not environment or len(environment) > 200:
            raise GuardError("invalid gate environment")
        try:
            environment.encode("utf-8")
        except UnicodeEncodeError:
            raise GuardError("invalid gate environment") from None

    def register_verifier(self, verifier_id, method, criteria, runner, *, transactional=False):
        """Pin an owner checker. Transactional mode is for bounded DB lookups only."""
        rt = self.runtime
        rt._id(verifier_id)
        rt._id(method)
        if not isinstance(criteria, (set, frozenset, list, tuple)) or not criteria or not set(criteria) <= CRITERIA or not callable(runner) or type(transactional) is not bool:
            raise GuardError("invalid verifier registration")
        try:
            source = inspect.getsource(runner)
        except (OSError, TypeError):
            raise GuardError("verifier source unavailable") from None
        # The existing nontransactional identity remains byte-for-byte stable.
        # Transactional runners are bounded owner DB checks, never subprocesses
        # or project/plugin code. Their execution mode is part of the pin.
        implementation_sha = digest(canonical({"source": source, "transactional": True})) if transactional else digest(source)
        allowed = canonical(sorted(set(criteria)))
        with rt.transaction():
            old = rt.db.execute("SELECT * FROM gate_verifiers WHERE id=?", (verifier_id,)).fetchone()
            if old and (old["method"], old["implementation_sha"], old["criteria"]) != (method, implementation_sha, allowed):
                raise GuardError("verifier registration changed", "BLOCK")
            if not old:
                rt.db.execute("INSERT INTO gate_verifiers VALUES(?,?,?,?)", (verifier_id, method, implementation_sha, allowed))
                rt._event("owner", "gate.verifier", verifier_id, "REGISTERED", {"method": method, "implementation_sha": implementation_sha})
        self.runners[verifier_id] = runner
        if transactional:
            self.transactional_runners.add(verifier_id)
        else:
            self.transactional_runners.discard(verifier_id)

    def _runner_current(self, verifier_id, runner, registration):
        try:
            source = inspect.getsource(runner)
            identity = digest(canonical({"source": source, "transactional": True})) if verifier_id in self.transactional_runners else digest(source)
            return identity == registration["implementation_sha"]
        except (OSError, TypeError):
            return False

    def _execute_check(self, runner, copied, context):
        if runner is None or copied.get("executed") is not True:
            result = CheckResult("UNKNOWN", "check_not_executed")
        elif copied.get("artifact_sha") != context["artifact_sha"]:
            result = CheckResult("FAIL", "observation_artifact_mismatch")
        else:
            try:
                result = runner(copied, dict(context), self.runtime.clock())
            except Exception:
                result = CheckResult("UNKNOWN", "checker_error")
        if not isinstance(result, CheckResult) or result.outcome not in OUTCOMES:
            result = CheckResult("UNKNOWN", "checker_invalid_result")
        self.runtime._id(result.reason)
        if result.expires_at is not None and (type(result.expires_at) not in (int, float) or not math.isfinite(result.expires_at)):
            result = CheckResult("UNKNOWN", "checker_invalid_expiry")
        return result

    def register_synthetic_verifiers(self):
        """Install the bounded fixture runners; their synthetic origin is explicit."""
        for criterion, runner in SYNTHETIC_RUNNERS.items():
            self.register_verifier("synthetic-" + criterion, "synthetic_" + criterion + "_fixture_v1", {criterion}, runner)
        return {criterion: "synthetic-" + criterion for criterion in CRITERIA}

    def _binding(self, task_id, run_id, evidence_id, environment):
        rt = self.runtime
        evidence = rt._evidence(evidence_id)
        if evidence["task"] != task_id or evidence["run"] != run_id or not rt._proof_is_accepted_for_gate(evidence, environment):
            raise GuardError("terminal proof not accepted for gate", "BLOCK")
        task = rt.task(task_id)
        source, artifact = rt.resource(task["input"]), rt.resource(task["output"])
        parents = [dict(r) for r in rt.db.execute("SELECT tasks.id,tasks.revision FROM deps JOIN tasks ON tasks.id=deps.parent WHERE deps.task=? ORDER BY tasks.id", (task_id,))]
        contract = {"task": task, "dependencies": parents}
        return {"task_id": task_id, "run_id": run_id, "terminal_evidence_id": evidence_id,
                "task_revision": task["revision"], "task_contract_sha": digest(canonical(contract)),
                "artifact_id": artifact["id"], "artifact_version": artifact["version"], "artifact_sha": artifact["sha"],
                "source_id": source["id"], "source_version": source["version"], "source_sha": source["sha"],
                "environment": environment}

    def define_contract(self, task_id, run_id, terminal_evidence_id, environment, required_verifiers):
        """Freeze all six mandatory checks on one verified artifact/run and policy."""
        rt = self.runtime
        self._environment(environment)
        for value in (task_id, run_id, terminal_evidence_id):
            rt._id(value)
        if not isinstance(required_verifiers, dict) or set(required_verifiers) != CRITERIA:
            raise GuardError("all gate criteria must be explicitly required")
        required_verifiers = dict(required_verifiers)
        with rt.transaction():
            for criterion, verifier_id in required_verifiers.items():
                rt._id(verifier_id)
                row = rt.db.execute("SELECT * FROM gate_verifiers WHERE id=?", (verifier_id,)).fetchone()
                if not row or criterion not in json.loads(row["criteria"]):
                    raise GuardError("required verifier is not registered for criterion")
            body = self._binding(task_id, run_id, terminal_evidence_id, environment)
            key = self._key()
            contract_id = str(uuid.uuid4())
            body.update({"schema": "owner-local-gate-v1", "contract_id": contract_id,
                         "signing_epoch": key["epoch"], "required_verifiers": required_verifiers,
                         "purpose": "local_validation_only", "created": rt.clock()})
            rt.db.execute("INSERT INTO gate_contracts VALUES(?,?,?,?)", (contract_id, key["epoch"], canonical(body), self._signature(key["secret"], body)))
            rt._event("owner", "gate.contract", contract_id, "FROZEN", {"task": task_id, "run": run_id, "epoch": key["epoch"]})
            return contract_id

    def _contract(self, contract_id, environment=None):
        rt = self.runtime
        rt._id(contract_id)
        row = rt.db.execute("SELECT * FROM gate_contracts WHERE id=?", (contract_id,)).fetchone()
        if not row:
            raise GuardError("unknown gate contract", "BLOCK")
        try:
            body = json.loads(row["body"])
            key = self._key()
            if not isinstance(body, dict) or row["epoch"] != key["epoch"] or body["signing_epoch"] != key["epoch"] or body["contract_id"] != contract_id or not hmac.compare_digest(row["signature"], self._signature(key["secret"], body)):
                raise GuardError("gate contract authentication failed", "BLOCK")
            if environment is not None and body["environment"] != environment:
                raise GuardError("gate environment changed", "BLOCK")
            current = self._binding(body["task_id"], body["run_id"], body["terminal_evidence_id"], body["environment"])
            if any(body.get(field) != value for field, value in current.items()):
                raise GuardError("gate artifact or contract is stale", "BLOCK")
            if set(body["required_verifiers"]) != CRITERIA or body["purpose"] != "local_validation_only":
                raise GuardError("gate policy invalid", "BLOCK")
            return body
        except (KeyError, TypeError, ValueError):
            raise GuardError("gate contract invalid", "BLOCK") from None

    def contract_context(self, contract_id):
        """Owner-only metadata for deterministic checks; no signer secret returned."""
        with self.runtime.transaction():
            return self._contract(contract_id)

    def run_check(self, contract_id, criterion, observations):
        """Run the registered trusted checker; callers cannot supply a verdict."""
        if not isinstance(criterion, str) or criterion not in CRITERIA or not isinstance(observations, dict):
            raise GuardError("invalid gate check request")
        try:
            encoded = json.dumps(observations, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
            if len(encoded) > MAX_OBSERVATION_BYTES:
                raise GuardError("gate observation too large")
            copied = json.loads(encoded)
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise GuardError("invalid gate observation") from None
        rt = self.runtime
        with rt.transaction():
            context = self._contract(contract_id)
            verifier_id = context["required_verifiers"][criterion]
            registration = dict(rt.db.execute("SELECT * FROM gate_verifiers WHERE id=?", (verifier_id,)).fetchone())
            runner = self.runners.get(verifier_id)
            transactional = verifier_id in self.transactional_runners
            epoch = self._key()["epoch"]
        # Trusted bounded algorithms, separate from the producer worker. Running
        # a new arbitrary/plugin checker needs its own isolation design first.
        if runner is not None:
            if not self._runner_current(verifier_id, runner, registration):
                raise GuardError("registered verifier implementation changed", "BLOCK")
        if not transactional:
            result = self._execute_check(runner, copied, context)
        with rt.transaction():
            current = self._contract(contract_id)
            key = self._key()
            if key["epoch"] != epoch or current != context:
                raise GuardError("gate changed during check", "BLOCK")
            if transactional:
                if runner is not self.runners.get(verifier_id) or not self._runner_current(verifier_id, runner, registration):
                    raise GuardError("registered verifier implementation changed", "BLOCK")
                # Revocation and the consent lookup/signature share this owner
                # write transaction. A pre-revocation read cannot sign later.
                result = self._execute_check(runner, copied, context)
            attestation_id = str(uuid.uuid4())
            body = {"schema": "owner-local-check-v1", "attestation_id": attestation_id, "contract_id": contract_id,
                    "contract_sha": digest(canonical(context)), "criterion": criterion, "signing_epoch": epoch,
                    "task_id": context["task_id"], "run_id": context["run_id"], "artifact_id": context["artifact_id"],
                    "artifact_version": context["artifact_version"], "artifact_sha": context["artifact_sha"],
                    "task_contract_sha": context["task_contract_sha"], "environment": context["environment"],
                    "verifier_id": verifier_id, "method": registration["method"], "implementation_sha": registration["implementation_sha"],
                    "outcome": result.outcome, "reason": result.reason, "expires_at": result.expires_at,
                    "observations_sha": hashlib.sha256(encoded).hexdigest(), "created": rt.clock()}
            rt.db.execute("INSERT INTO gate_attestations(id,contract_id,criterion,epoch,body,signature) VALUES(?,?,?,?,?,?)", (attestation_id, contract_id, criterion, epoch, canonical(body), self._signature(key["secret"], body)))
            rt._event("verifier", "gate.check", attestation_id, result.outcome, {"criterion": criterion, "verifier": verifier_id, "epoch": epoch})
            return {"attestation": attestation_id, "outcome": result.outcome, "reason": result.reason}

    def _check_attestation(self, row, context, criterion, key):
        try:
            body = json.loads(row["body"])
            if not isinstance(body, dict) or row["epoch"] != key["epoch"] or body["signing_epoch"] != key["epoch"] or not hmac.compare_digest(row["signature"], self._signature(key["secret"], body)):
                return "authentication_failed"
            expected = {"attestation_id": row["id"], "contract_id": context["contract_id"], "contract_sha": digest(canonical(context)),
                        "criterion": criterion, "task_id": context["task_id"], "run_id": context["run_id"],
                        "artifact_id": context["artifact_id"], "artifact_version": context["artifact_version"],
                        "artifact_sha": context["artifact_sha"], "task_contract_sha": context["task_contract_sha"],
                        "environment": context["environment"], "verifier_id": context["required_verifiers"][criterion]}
            if any(body.get(field) != value for field, value in expected.items()):
                return "binding_mismatch"
            registration = self.runtime.db.execute("SELECT * FROM gate_verifiers WHERE id=?", (body["verifier_id"],)).fetchone()
            if not registration or criterion not in json.loads(registration["criteria"]) or body.get("method") != registration["method"] or body.get("implementation_sha") != registration["implementation_sha"]:
                return "verifier_mismatch"
            if self.runtime.db.execute("SELECT 1 FROM gate_revocations WHERE attestation_id=?", (row["id"],)).fetchone():
                return "revoked"
            if body.get("outcome") != "PASS":
                return "outcome_" + str(body.get("outcome", "UNKNOWN"))
            created, now = body.get("created"), self.runtime.clock()
            if (type(created) not in (int, float) or not math.isfinite(created)
                    or type(now) not in (int, float) or not math.isfinite(now) or now < created):
                return "invalid_check_time"
            expiry = body.get("expires_at")
            if expiry is not None and (type(expiry) not in (int, float) or not math.isfinite(expiry) or expiry <= now):
                return "expired"
            return None
        except (KeyError, TypeError, ValueError):
            return "invalid_attestation"

    def evaluate(self, contract_id, environment):
        """Return a local decision only; this never authorizes or performs release."""
        self._environment(environment)
        rt = self.runtime
        with rt.transaction():
            try:
                context = self._contract(contract_id, environment)
            except GuardError as error:
                return {"accepted": False, "decision": "BLOCK", "purpose": "local_validation_only", "reason": error.reason, "criteria": {}}
            key = self._key()
            outcomes = {}
            for criterion in sorted(CRITERIA):
                row = rt.db.execute("SELECT * FROM gate_attestations WHERE contract_id=? AND criterion=? ORDER BY sequence DESC LIMIT 1", (contract_id, criterion)).fetchone()
                reason = "missing" if not row else self._check_attestation(row, context, criterion, key)
                outcomes[criterion] = "PASS" if reason is None else reason
            accepted = all(result == "PASS" for result in outcomes.values())
            rt._event("controller", "gate.evaluate", contract_id, "PASS" if accepted else "BLOCK", {"required": len(CRITERIA), "epoch": key["epoch"]})
            return {"accepted": accepted, "decision": "PASS" if accepted else "BLOCK", "purpose": "local_validation_only", "criteria": outcomes}

    def revoke_attestation(self, attestation_id, reason="owner_withdrawal"):
        rt = self.runtime
        rt._id(attestation_id)
        rt._id(reason)
        with rt.transaction():
            if not rt.db.execute("SELECT 1 FROM gate_attestations WHERE id=?", (attestation_id,)).fetchone():
                raise GuardError("unknown attestation")
            if rt.db.execute("SELECT 1 FROM gate_revocations WHERE attestation_id=?", (attestation_id,)).fetchone():
                return False
            rt.db.execute("INSERT INTO gate_revocations VALUES(?,?,?)", (attestation_id, rt.clock(), reason))
            rt._event("owner", "gate.revoke", attestation_id, "REVOKED")
            return True

    def rotate_signing_key(self):
        """Conservative rotation: old contracts and attestations become unusable."""
        rt = self.runtime
        with rt.transaction():
            epoch = self._key()["epoch"] + 1
            rt.db.execute("INSERT INTO gate_keys VALUES(?,?,?)", (epoch, secrets.token_bytes(32), rt.clock()))
            rt._event("owner", "gate.key", "signer", "ROTATED", {"epoch": epoch})
            return epoch


def synthetic_tests(observations, context, now):
    cases = observations.get("cases")
    if not isinstance(cases, list) or not cases or len(cases) > 1024 or any(type(case) is not bool for case in cases):
        return CheckResult("UNKNOWN", "test_fixture_missing")
    return CheckResult("PASS" if all(cases) else "FAIL", "synthetic_test_cases")


def synthetic_licenses(observations, context, now):
    licenses, allowed = observations.get("licenses"), observations.get("allowed")
    if not isinstance(licenses, list) or not licenses or not isinstance(allowed, list) or not allowed or len(licenses) > 1024 or len(allowed) > 1024 or any(not isinstance(value, str) or not value for value in licenses + allowed):
        return CheckResult("UNKNOWN", "license_fixture_missing")
    return CheckResult("PASS" if set(licenses) <= set(allowed) else "FAIL", "synthetic_license_allowlist")


def synthetic_secrets(observations, context, now):
    content, markers = observations.get("artifact_content"), observations.get("forbidden_markers")
    if not isinstance(content, str) or digest(content) != context["artifact_sha"] or not isinstance(markers, list) or not markers or len(markers) > 1024 or any(not isinstance(marker, str) or not marker for marker in markers):
        return CheckResult("UNKNOWN", "secret_fixture_missing")
    return CheckResult("FAIL" if any(marker in content for marker in markers) else "PASS", "synthetic_literal_marker_scan")


def synthetic_provenance(observations, context, now):
    source = observations.get("source")
    expected = {"id": context["source_id"], "version": context["source_version"], "sha": context["source_sha"], "origin": "owner_fixture"}
    return CheckResult("PASS" if source == expected else "FAIL", "synthetic_source_reference")


def synthetic_consent(observations, context, now):
    expiry = observations.get("expires_at")
    if type(expiry) not in (int, float) or not math.isfinite(expiry):
        return CheckResult("UNKNOWN", "consent_fixture_missing")
    if expiry <= now:
        return CheckResult("STALE", "synthetic_consent_expired", expiry)
    accepted = observations.get("approved") is True and observations.get("contract_id") == context["contract_id"] and observations.get("scope") == "local_validation_only"
    return CheckResult("PASS" if accepted else "FAIL", "synthetic_owner_consent", expiry)


def synthetic_environment(observations, context, now):
    return CheckResult("PASS" if observations.get("environment") == context["environment"] else "FAIL", "synthetic_environment_equality")


SYNTHETIC_RUNNERS = {"tests": synthetic_tests, "licenses": synthetic_licenses, "secrets": synthetic_secrets,
                     "provenance": synthetic_provenance, "consent": synthetic_consent, "environment": synthetic_environment}
