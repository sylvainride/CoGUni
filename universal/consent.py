"""Owner-issued, expiring consent for one exact local gate contract.

This API belongs to the trusted controller, never the worker IPC interface.
It records the controller's explicit decision; it does not authenticate a human
or grant publication, deployment, spending or remote application permissions.
"""
import hashlib
import hmac
import json
import math
from pathlib import Path
import uuid

from .core import GuardError, canonical, digest
from .gates import CheckResult, GateEngine

MAX_TTL_SECONDS = 86_400
VERIFIER_ID = "owner-consent-v1"
SCOPE = "local_validation_only"
DDL = (
    "CREATE TABLE IF NOT EXISTS owner_consents(id TEXT PRIMARY KEY, contract_id TEXT NOT NULL REFERENCES gate_contracts(id), epoch INTEGER NOT NULL REFERENCES gate_keys(epoch), body TEXT NOT NULL, signature TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS owner_consent_revocations(id TEXT PRIMARY KEY REFERENCES owner_consents(id), created REAL NOT NULL, reason TEXT NOT NULL)",
)


def implementation_identity():
    """Pin this module and the gate implementation, including their helpers."""
    from . import gates
    return digest(canonical({name: hashlib.sha256(path.read_bytes()).hexdigest()
                             for name, path in (("consent", Path(__file__)),
                                                ("gates", Path(gates.__file__)))}))


class ConsentAuthority:
    def __init__(self, gate):
        if not isinstance(gate, GateEngine):
            raise GuardError("owner gate required")
        self.gate = gate
        self.implementation = implementation_identity()
        rt = gate.runtime
        with rt.transaction():
            for statement in DDL:
                rt.db.execute(statement)
            for table in ("owner_consents", "owner_consent_revocations"):
                for operation in ("UPDATE", "DELETE"):
                    rt.db.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'immutable consent record'); END")
        gate.register_verifier(VERIFIER_ID, "owner_consent_record_v1_" + self.implementation,
                               {"consent"}, self.check, transactional=True)

    def _context(self, contract_id):
        from .broker import environment_identity
        context = self.gate._contract(contract_id)
        if (context["required_verifiers"]["consent"] != VERIFIER_ID
                or context["purpose"] != SCOPE
                or context["environment"] != environment_identity()
                or implementation_identity() != self.implementation):
            raise GuardError("consent target or implementation changed", "BLOCK")
        return context

    def grant(self, contract_id, *, expires_at):
        """Explicit owner decision for this exact contract; no worker approval flag."""
        rt = self.gate.runtime
        with rt.transaction():
            context = self._context(contract_id)
            now = rt.clock()
            if (type(now) not in (int, float) or not math.isfinite(now)
                    or type(expires_at) not in (int, float) or not math.isfinite(expires_at)
                    or not now < expires_at <= now + MAX_TTL_SECONDS):
                raise GuardError("invalid consent expiry", "BLOCK")
            key = self.gate._key()
            consent_id = str(uuid.uuid4())
            body = {"schema": "owner-consent-v1", "consent_id": consent_id,
                    "contract_id": contract_id, "contract_sha": digest(canonical(context)),
                    "scope": SCOPE, "epoch": key["epoch"], "created": now,
                    "expires_at": expires_at, "implementation": self.implementation}
            rt.db.execute("INSERT INTO owner_consents VALUES(?,?,?,?,?)",
                          (consent_id, contract_id, key["epoch"], canonical(body),
                           self.gate._signature(key["secret"], body)))
            rt._event("owner", "consent.grant", consent_id, "GRANTED",
                      {"contract": contract_id, "scope": SCOPE, "expires_at": expires_at})
            return consent_id

    def check(self, observations, context, now):
        """Bounded DB lookup under the gate's signing transaction, not a verdict input."""
        rt = self.gate.runtime
        if not rt.db.in_transaction:
            return CheckResult("UNKNOWN", "consent_owner_transaction_required")
        if set(observations) != {"executed", "artifact_sha", "consent_id"}:
            return CheckResult("UNKNOWN", "consent_reference_required")
        consent_id = observations["consent_id"]
        try:
            rt._id(consent_id)
            current = self._context(context["contract_id"])
            if current != context:
                return CheckResult("STALE", "consent_contract_changed")
            row = rt.db.execute("SELECT * FROM owner_consents WHERE id=?", (consent_id,)).fetchone()
            if not row:
                return CheckResult("UNKNOWN", "consent_record_missing")
            if rt.db.execute("SELECT 1 FROM owner_consent_revocations WHERE id=?", (consent_id,)).fetchone():
                return CheckResult("FAIL", "consent_revoked")
            key = self.gate._key()
            body = json.loads(row["body"])
            fields = {"schema", "consent_id", "contract_id", "contract_sha", "scope",
                      "epoch", "created", "expires_at", "implementation"}
            if (type(body) is not dict or set(body) != fields
                    or row["contract_id"] != context["contract_id"]
                    or row["epoch"] != key["epoch"]
                    or body["schema"] != "owner-consent-v1" or body["consent_id"] != consent_id
                    or body["contract_id"] != context["contract_id"]
                    or body["contract_sha"] != digest(canonical(context))
                    or body["scope"] != SCOPE or body["epoch"] != key["epoch"]
                    or body["implementation"] != self.implementation
                    or not hmac.compare_digest(row["signature"], self.gate._signature(key["secret"], body))):
                return CheckResult("FAIL", "consent_authentication_failed")
            created, expiry = body["created"], body["expires_at"]
            if (any(type(value) not in (int, float) or not math.isfinite(value)
                    for value in (now, created, expiry))
                    or not created < expiry <= created + MAX_TTL_SECONDS):
                return CheckResult("FAIL", "consent_invalid_time")
            if not created <= now < expiry:
                return CheckResult("STALE", "consent_expired_or_clock_rollback", expiry)
            return CheckResult("PASS", "owner_consent_record", expiry)
        except (GuardError, KeyError, TypeError, ValueError):
            return CheckResult("FAIL", "consent_binding_invalid")

    def revoke(self, consent_id, *, reason="owner_withdrawal"):
        """Revoke the receipt and existing consent attestations atomically."""
        rt = self.gate.runtime
        rt._id(consent_id)
        rt._id(reason)
        with rt.transaction():
            row = rt.db.execute("SELECT contract_id FROM owner_consents WHERE id=?", (consent_id,)).fetchone()
            if not row:
                raise GuardError("unknown owner consent", "BLOCK")
            if rt.db.execute("SELECT 1 FROM owner_consent_revocations WHERE id=?", (consent_id,)).fetchone():
                return False
            now = rt.clock()
            rt.db.execute("INSERT INTO owner_consent_revocations VALUES(?,?,?)", (consent_id, now, reason))
            # Conservatively invalidate every consent attestation on this
            # contract. A separate live receipt needs a fresh owner check.
            rt.db.execute("INSERT OR IGNORE INTO gate_revocations SELECT id,?,? FROM gate_attestations WHERE contract_id=? AND criterion='consent'",
                          (now, reason, row["contract_id"]))
            rt._event("owner", "consent.revoke", consent_id, "REVOKED", {"contract": row["contract_id"]})
            return True
