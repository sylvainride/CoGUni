"""Owner-only fake outbox. No network connector, worker tool, or release gate.

Two independent SQLite stores deliberately model the owner/effect commit gap.
The fake adapter's deduplication is a tested fixture contract, not a guarantee for
an actual remote API. UNKNOWN is queried before any explicitly permitted retry.
"""
from contextlib import contextmanager
import hmac
import json
from pathlib import Path
import sqlite3
import uuid

from .core import GuardError, Intent, canonical, digest


_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS simulated_outbox(key TEXT PRIMARY KEY,run TEXT NOT NULL REFERENCES runs(id),resource TEXT NOT NULL REFERENCES resources(id),expected_version INTEGER NOT NULL,fence INTEGER NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL,budget INTEGER NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,attempts INTEGER NOT NULL,receipt TEXT,adapter_id TEXT)",
    "CREATE TABLE IF NOT EXISTS simulated_outbox_attempts(id TEXT PRIMARY KEY,key TEXT NOT NULL REFERENCES simulated_outbox(key),number INTEGER NOT NULL,state TEXT NOT NULL,UNIQUE(key,number))",
    "CREATE TABLE IF NOT EXISTS simulated_compensations(key TEXT PRIMARY KEY,original TEXT NOT NULL REFERENCES simulated_outbox(key),fingerprint TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,receipt TEXT)",
    "CREATE TRIGGER IF NOT EXISTS simulated_outbox_immutable BEFORE UPDATE OF key,run,resource,expected_version,fence,payload,fingerprint,budget ON simulated_outbox BEGIN SELECT RAISE(ABORT,'immutable outbox intent'); END",
    "CREATE TRIGGER IF NOT EXISTS simulated_compensation_immutable BEFORE UPDATE OF key,original,fingerprint ON simulated_compensations BEGIN SELECT RAISE(ABORT,'immutable compensation intent'); END",
)


class FakeAdapter:
    """Instrumented local effect service with an independent durable database.

    Calls and semantic effects are separate: duplicate calls are observable,
    while a matching immutable business key returns the existing fake effect.
    Owners must close this adapter, including on construction failure.
    """
    simulate_only = True

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            existing = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if existing and not {"fake_effects", "fake_compensations", "fake_calls"} <= existing:
                raise GuardError("fake adapter refuses foreign database", "BLOCK")
            self.db.execute("PRAGMA busy_timeout=10000")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            with self.transaction():
                self.db.execute("CREATE TABLE IF NOT EXISTS fake_effects(key TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,content TEXT NOT NULL,effect_id TEXT NOT NULL,compensated INTEGER NOT NULL DEFAULT 0)")
                self.db.execute("CREATE TABLE IF NOT EXISTS fake_compensations(key TEXT PRIMARY KEY,original TEXT NOT NULL,fingerprint TEXT NOT NULL)")
                self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS one_fake_compensation ON fake_compensations(original)")
                self.db.execute("CREATE TABLE IF NOT EXISTS fake_calls(id INTEGER PRIMARY KEY AUTOINCREMENT,operation TEXT NOT NULL,key TEXT NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS fake_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),uuid TEXT NOT NULL UNIQUE)")
                self.db.execute("INSERT OR IGNORE INTO fake_identity VALUES(1,?)", (str(uuid.uuid4()),))
                self.db.execute("CREATE TRIGGER IF NOT EXISTS fake_identity_no_update BEFORE UPDATE ON fake_identity BEGIN SELECT RAISE(ABORT,'immutable fake identity'); END")
                self.db.execute("CREATE TRIGGER IF NOT EXISTS fake_identity_no_delete BEFORE DELETE ON fake_identity BEGIN SELECT RAISE(ABORT,'immutable fake identity'); END")
                self.identity  # Reject malformed stores before exposing the adapter.
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException as original:
            # Keep the original storage error if SQLite already rolled back.
            try:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
            except BaseException as cleanup:
                # A failed rollback leaves a poisoned connection: never allow a
                # later operation to accidentally commit the unfinished write.
                original.add_note("Rollback failed: " + type(cleanup).__name__)
                try:
                    self.db.close()
                except BaseException as closing:
                    original.add_note("Connection close failed: " + type(closing).__name__)
            raise

    @property
    def identity(self):
        """Durable store UUID plus canonical locator, never a credential.

        Copying a DB to another path does not silently redirect an outstanding
        effect. Reopening/restoring at the same locator preserves this identity.
        Rollback of both trusted stores remains outside this local contract.
        """
        row = self.db.execute("SELECT uuid FROM fake_identity WHERE singleton=1").fetchone()
        try:
            store_uuid = str(uuid.UUID(row["uuid"]))
        except (TypeError, ValueError, AttributeError):
            raise GuardError("invalid fake store identity", "BLOCK") from None
        return digest(canonical({"uuid": store_uuid, "locator": str(self.path.resolve())}))

    def _receipt(self, row):
        return {"key": row["key"], "fingerprint": row["fingerprint"], "payload_sha": digest(row["content"]), "effect_id": row["effect_id"], "adapter_id": self.identity, "simulate_only": True}

    def apply(self, key, fingerprint, content):
        with self.transaction():
            self.db.execute("INSERT INTO fake_calls(operation,key) VALUES('apply',?)", (key,))
            row = self.db.execute("SELECT * FROM fake_effects WHERE key=?", (key,)).fetchone()
            if row:
                if row["fingerprint"] != fingerprint or row["content"] != content:
                    raise GuardError("fake adapter key collision")
            else:
                self.db.execute("INSERT INTO fake_effects(key,fingerprint,content,effect_id) VALUES(?,?,?,?)", (key, fingerprint, content, str(uuid.uuid4())))
                row = self.db.execute("SELECT * FROM fake_effects WHERE key=?", (key,)).fetchone()
            return self._receipt(row)

    def lookup(self, key):
        with self.transaction():
            self.db.execute("INSERT INTO fake_calls(operation,key) VALUES('lookup',?)", (key,))
            row = self.db.execute("SELECT * FROM fake_effects WHERE key=?", (key,)).fetchone()
            return self._receipt(row) if row else None

    def compensate(self, original, key, fingerprint):
        with self.transaction():
            self.db.execute("INSERT INTO fake_calls(operation,key) VALUES('compensate',?)", (key,))
            row = self.db.execute("SELECT * FROM fake_compensations WHERE key=?", (key,)).fetchone()
            if row and (row["original"] != original or row["fingerprint"] != fingerprint):
                raise GuardError("fake compensation key collision")
            effect = self.db.execute("SELECT 1 FROM fake_effects WHERE key=?", (original,)).fetchone()
            if not effect:
                raise GuardError("fake effect absent", "BLOCK")
            if not row:
                self.db.execute("INSERT INTO fake_compensations VALUES(?,?,?)", (key, original, fingerprint))
                self.db.execute("UPDATE fake_effects SET compensated=1 WHERE key=?", (original,))
            return {"key": key, "original": original, "fingerprint": fingerprint, "adapter_id": self.identity, "simulate_only": True}

    def lookup_compensation(self, key):
        with self.transaction():
            self.db.execute("INSERT INTO fake_calls(operation,key) VALUES('lookup_compensation',?)", (key,))
            row = self.db.execute("SELECT * FROM fake_compensations WHERE key=?", (key,)).fetchone()
            return {**dict(row), "adapter_id": self.identity, "simulate_only": True} if row else None

    def statistics(self):
        return {"semantic_effects": self.db.execute("SELECT count(*) FROM fake_effects").fetchone()[0], "compensations": self.db.execute("SELECT count(*) FROM fake_compensations").fetchone()[0], "calls": {row[0]: row[1] for row in self.db.execute("SELECT operation,count(*) FROM fake_calls GROUP BY operation")}}


class Outbox:
    """Trusted owner facade; deliberately absent from worker/broker IPC schema.

    Exact per-run artifact.write grants authorize this owner-invoked simulation
    only. They confer no connector permission, network permission, publication
    permission, or successful artifact verification.
    """
    MAX_BUDGET = 8

    def __init__(self, runtime):
        self.runtime = runtime
        with runtime.transaction():
            for statement in _SCHEMA:
                runtime.db.execute(statement)
            columns = {row[1] for row in runtime.db.execute("PRAGMA table_info(simulated_outbox)")}
            if "adapter_id" not in columns:
                runtime.db.execute("ALTER TABLE simulated_outbox ADD COLUMN adapter_id TEXT")
            runtime.db.execute("CREATE TRIGGER IF NOT EXISTS simulated_outbox_adapter_immutable BEFORE UPDATE OF adapter_id ON simulated_outbox WHEN OLD.adapter_id IS NOT NULL AND NEW.adapter_id IS NOT OLD.adapter_id BEGIN SELECT RAISE(ABORT,'immutable outbox adapter'); END")

    def _event(self, key, outcome, **metadata):
        self.runtime._event("owner", "outbox.simulation", key, outcome, metadata)

    @staticmethod
    def _revision(value):
        if type(value) is not int or value < 1:
            raise GuardError("invalid outbox revision")

    def _row(self, key, expected_revision=None):
        self.runtime._id(key)
        row = self.runtime.db.execute("SELECT * FROM simulated_outbox WHERE key=?", (key,)).fetchone()
        if not row:
            raise GuardError("unknown outbox intent")
        if expected_revision is not None:
            self._revision(expected_revision)
            if row["revision"] != expected_revision:
                raise GuardError("stale outbox revision", "BLOCK")
        return dict(row)

    @staticmethod
    def _intent(row, key=None):
        return Intent(row["run"], "artifact.write", row["resource"], row["expected_version"], key or row["key"], row["fence"], {"content": row["payload"]})

    def _authorize(self, intent, token, *, active=True):
        rt = self.runtime
        run = rt._authorize(intent, token)
        if intent.tool != "artifact.write":
            raise GuardError("simulation requires exact write scope")
        task = rt.task(run["task"])
        if intent.resource != task["output"] or rt.resource(intent.resource)["version"] != intent.expected_version:
            raise GuardError("stale simulation resource", "BLOCK")
        if active and run["state"] != "RUNNING":
            raise GuardError("simulation run not active", "BLOCK")
        if not rt._dependencies_current(intent.run_id) or rt.resource(task["input"])["version"] != run["input_version"]:
            raise GuardError("stale simulation input", "BLOCK")
        return run

    def _adapter(self, adapter):
        # No arbitrary plug-in invocation: this lot supports the local fake only.
        if type(adapter) is not FakeAdapter or adapter.path.resolve() == self.runtime.path.resolve() or adapter.path.samefile(self.runtime.path):
            raise GuardError("only independent local fake adapter permitted", "BLOCK")

    def _bound_adapter(self, row, adapter, *, allow_first_binding=False):
        identity = adapter.identity
        if row["adapter_id"] is None:
            # An old uncertain/committed intent cannot infer its backend from
            # absence in an arbitrary store. Only an unattempted intent binds.
            if not allow_first_binding or row["state"] != "PREPARED" or row["attempts"] != 0 or row["receipt"] is not None:
                raise GuardError("unbound historical effect requires owner investigation", "RECONCILE")
            self.runtime.db.execute("UPDATE simulated_outbox SET adapter_id=? WHERE key=? AND adapter_id IS NULL", (identity, row["key"]))
            self._event(row["key"], "ADAPTER_BOUND", adapter_id=identity)
            row["adapter_id"] = identity
        if not hmac.compare_digest(row["adapter_id"], identity):
            raise GuardError("outbox adapter identity mismatch", "RECONCILE")

    @staticmethod
    def _crash(hook, point):
        if hook is not None:
            hook(point)  # Trusted test/owner hook, never worker-controlled.

    def prepare(self, intent, token, *, action="simulate_only", budget=1, crash_hook=None):
        if action != "simulate_only" or type(budget) is not int or not 1 <= budget <= self.MAX_BUDGET:
            raise GuardError("simulation action or budget denied", "BLOCK")
        rt = self.runtime
        with rt.transaction():
            self._authorize(intent, token)
            fingerprint = digest(canonical({"action": action, "run": intent.run_id, "resource": intent.resource, "version": intent.expected_version, "fence": intent.fence, "payload": intent.args["content"], "budget": budget}))
            old = rt.db.execute("SELECT * FROM simulated_outbox WHERE key=?", (intent.key,)).fetchone()
            if old:
                if not hmac.compare_digest(old["fingerprint"], fingerprint):
                    raise GuardError("outbox business key collision")
                return self._public(dict(old))
            rt.db.execute("INSERT INTO simulated_outbox(key,run,resource,expected_version,fence,payload,fingerprint,budget,state,revision,attempts,receipt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (intent.key, intent.run_id, intent.resource, intent.expected_version, intent.fence, intent.args["content"], fingerprint, budget, "PREPARED", 1, 0, None))
            self._event(intent.key, "PREPARED", fingerprint=fingerprint, budget=budget)
            self._crash(crash_hook, "before_prepare_commit")
        self._crash(crash_hook, "after_prepare_commit")
        return self.status(intent.key)

    def _accept_receipt(self, row, receipt):
        if not isinstance(receipt, dict) or set(receipt) != {"key", "fingerprint", "payload_sha", "effect_id", "adapter_id", "simulate_only"} or receipt["simulate_only"] is not True or receipt["key"] != row["key"] or receipt["fingerprint"] != row["fingerprint"] or receipt["payload_sha"] != digest(row["payload"]) or receipt["adapter_id"] != row["adapter_id"] or not isinstance(receipt["effect_id"], str) or not receipt["effect_id"]:
            raise GuardError("simulation receipt contract mismatch", "RECONCILE")

    def _unknown(self, key):
        with self.runtime.transaction():
            row = self._row(key)
            if row["state"] == "INFLIGHT":
                self.runtime.db.execute("UPDATE simulated_outbox SET state='UNKNOWN',revision=revision+1 WHERE key=?", (key,))
                self.runtime.db.execute("UPDATE simulated_outbox_attempts SET state='UNKNOWN' WHERE key=? AND state='INFLIGHT'", (key,))
                self._event(key, "UNKNOWN")

    def dispatch(self, key, token, expected_revision, adapter, *, crash_hook=None):
        self._adapter(adapter)
        rt = self.runtime
        with rt.transaction():
            row = self._row(key, expected_revision)
            self._authorize(self._intent(row), token)
            self._bound_adapter(row, adapter, allow_first_binding=True)
            if row["state"] == "COMMITTED":
                self._event(key, "REPLAY_NO_NEW_EFFECT")
                return self._public(row)
            if row["state"] != "PREPARED":
                raise GuardError("outbox requires reconciliation", "RECONCILE")
            if row["attempts"] >= row["budget"]:
                raise GuardError("simulation attempt budget exhausted", "BLOCK")
            attempt = str(uuid.uuid4())
            rt.db.execute("INSERT INTO simulated_outbox_attempts VALUES(?,?,?,'INFLIGHT')", (attempt, key, row["attempts"] + 1))
            rt.db.execute("UPDATE simulated_outbox SET state='INFLIGHT',attempts=attempts+1,revision=revision+1 WHERE key=?", (key,))
            self._event(key, "ATTEMPT", number=row["attempts"] + 1)
        self._crash(crash_hook, "after_attempt_before_effect")
        try:
            # The owner lock linearizes revocation versus emission. The fake
            # database still commits separately: a process crash cannot roll it
            # back together with this owner's acknowledgement transaction.
            with rt.transaction():
                row = self._row(key, expected_revision + 1)
                self._authorize(self._intent(row), token)
                self._bound_adapter(row, adapter)
                if row["state"] != "INFLIGHT":
                    raise GuardError("outbox attempt replaced", "BLOCK")
                receipt = adapter.apply(key, row["fingerprint"], row["payload"])
                self._crash(crash_hook, "after_effect_before_ack")
                self._accept_receipt(row, receipt)
                rt.db.execute("UPDATE simulated_outbox SET state='ACKED',revision=revision+1,receipt=? WHERE key=?", (canonical(receipt), key))
                rt.db.execute("UPDATE simulated_outbox_attempts SET state='ACKED' WHERE id=?", (attempt,))
                self._event(key, "ACKED", effect_id=receipt["effect_id"])
            self._crash(crash_hook, "after_ack_before_commit")
            with rt.transaction():
                row = self._row(key, expected_revision + 2)
                self._authorize(self._intent(row), token)
                self._bound_adapter(row, adapter)
                if row["state"] != "ACKED":
                    raise GuardError("outbox acknowledgement replaced", "BLOCK")
                rt.db.execute("UPDATE simulated_outbox SET state='COMMITTED',revision=revision+1 WHERE key=?", (key,))
                self._event(key, "COMMITTED")
            return self.status(key)
        except Exception:
            self._unknown(key)
            raise

    def recover_uncertain(self, key, expected_revision):
        """Explicit owner crash/disconnection observation, no effect re-emission."""
        with self.runtime.transaction():
            row = self._row(key, expected_revision)
            if row["state"] != "INFLIGHT":
                raise GuardError("no inflight attempt to recover", "BLOCK")
            self.runtime.db.execute("UPDATE simulated_outbox SET state='UNKNOWN',revision=revision+1 WHERE key=?", (key,))
            self.runtime.db.execute("UPDATE simulated_outbox_attempts SET state='UNKNOWN' WHERE key=? AND state='INFLIGHT'", (key,))
            self._event(key, "UNKNOWN_OWNER_RECOVERY")
            return self._public(self._row(key))

    def reconcile(self, key, expected_revision, adapter):
        """Owner observation only, even after expiration/revocation; no apply."""
        self._adapter(adapter)
        rt = self.runtime
        with rt.transaction():
            row = self._row(key, expected_revision)
            self._bound_adapter(row, adapter)
            if row["state"] == "COMMITTED":
                return self._public(row)
            if row["state"] not in {"INFLIGHT", "UNKNOWN", "ACKED"}:
                raise GuardError("outbox has no uncertain attempt", "BLOCK")
            receipt = adapter.lookup(key)
            if receipt is None:
                if row["state"] == "ACKED":
                    raise GuardError("acknowledged fake effect disappeared", "RECONCILE")
                rt.db.execute("UPDATE simulated_outbox SET state='PREPARED',revision=revision+1 WHERE key=?", (key,))
                outcome = "RECONCILED_ABSENT"
            else:
                self._accept_receipt(row, receipt)
                rt.db.execute("UPDATE simulated_outbox SET state='COMMITTED',revision=revision+1,receipt=? WHERE key=?", (canonical(receipt), key))
                outcome = "RECONCILED_PRESENT"
            rt.db.execute("UPDATE simulated_outbox_attempts SET state=? WHERE key=? AND state IN ('INFLIGHT','UNKNOWN','ACKED')", (outcome, key))
            self._event(key, outcome)
            return self._public(self._row(key))

    def compensate(self, original, compensation_key, token, expected_revision, adapter, *, crash_hook=None):
        """Explicit separate owner contract; reverses the fake flag, not history."""
        self._adapter(adapter)
        self.runtime._id(compensation_key)
        if compensation_key == original:
            raise GuardError("compensation needs a distinct business key")
        rt = self.runtime
        with rt.transaction():
            row = self._row(original, expected_revision)
            self._authorize(self._intent(row, compensation_key), token)
            self._bound_adapter(row, adapter)
            if row["state"] != "COMMITTED":
                raise GuardError("uncommitted effect cannot be compensated", "BLOCK")
            other = rt.db.execute("SELECT key FROM simulated_compensations WHERE original=?", (original,)).fetchone()
            if other and other["key"] != compensation_key:
                raise GuardError("one compensation contract per effect", "BLOCK")
            fingerprint = digest(canonical({"action": "simulate_compensation", "original": original, "original_fingerprint": row["fingerprint"], "key": compensation_key}))
            old = rt.db.execute("SELECT * FROM simulated_compensations WHERE key=?", (compensation_key,)).fetchone()
            if old:
                if old["fingerprint"] != fingerprint:
                    raise GuardError("compensation business key collision")
                if old["state"] == "COMMITTED":
                    self._event(compensation_key, "COMPENSATION_REPLAY_NO_NEW_EFFECT")
                    return dict(old)
                raise GuardError("compensation requires reconciliation", "RECONCILE")
            rt.db.execute("INSERT INTO simulated_compensations VALUES(?,?,?,'INFLIGHT',1,NULL)", (compensation_key, original, fingerprint))
            self._event(compensation_key, "COMPENSATION_PREPARED", original=original)
        try:
            with rt.transaction():
                self._authorize(self._intent(row, compensation_key), token)
                self._bound_adapter(self._row(original, expected_revision), adapter)
                receipt = adapter.compensate(original, compensation_key, fingerprint)
                self._crash(crash_hook, "after_compensation_before_ack")
                if receipt != {"key": compensation_key, "original": original, "fingerprint": fingerprint, "adapter_id": row["adapter_id"], "simulate_only": True}:
                    raise GuardError("compensation receipt mismatch", "RECONCILE")
                rt.db.execute("UPDATE simulated_compensations SET state='COMMITTED',revision=revision+1,receipt=? WHERE key=?", (canonical(receipt), compensation_key))
                self._event(compensation_key, "COMPENSATION_COMMITTED", original=original)
            return self.compensation_status(compensation_key)
        except Exception:
            with rt.transaction():
                rt.db.execute("UPDATE simulated_compensations SET state='UNKNOWN',revision=revision+1 WHERE key=? AND state='INFLIGHT'", (compensation_key,))
                self._event(compensation_key, "COMPENSATION_UNKNOWN")
            raise

    def reconcile_compensation(self, key, expected_revision, adapter):
        self._adapter(adapter)
        self._revision(expected_revision)
        with self.runtime.transaction():
            row = self.runtime.db.execute("SELECT * FROM simulated_compensations WHERE key=?", (key,)).fetchone()
            if not row or row["revision"] != expected_revision:
                raise GuardError("unknown or stale compensation", "BLOCK")
            original = self._row(row["original"])
            self._bound_adapter(original, adapter)
            if row["state"] == "COMMITTED":
                return dict(row)
            receipt = adapter.lookup_compensation(key)
            expected = {"key": key, "original": row["original"], "fingerprint": row["fingerprint"], "adapter_id": original["adapter_id"], "simulate_only": True}
            if receipt != expected:
                # Unlike apply retry, compensation has a one-attempt contract.
                raise GuardError("compensation not positively reconciled", "RECONCILE")
            self.runtime.db.execute("UPDATE simulated_compensations SET state='COMMITTED',revision=revision+1,receipt=? WHERE key=?", (canonical(receipt), key))
            self._event(key, "COMPENSATION_RECONCILED", original=row["original"])
            return self.compensation_status(key)

    @staticmethod
    def _public(row):
        # Redact payload, credentials and paths; receipts contain hashes only.
        return {key: row[key] for key in ("key", "state", "revision", "attempts", "budget", "fingerprint", "adapter_id")}

    def status(self, key):
        return self._public(self._row(key))

    def compensation_status(self, key):
        self.runtime._id(key)
        row = self.runtime.db.execute("SELECT * FROM simulated_compensations WHERE key=?", (key,)).fetchone()
        if not row:
            raise GuardError("unknown compensation")
        return dict(row)
