"""Bounded, durable owner scheduling; no worker tool, model, or evidence gate.

This separate SQLite journal remembers local scheduling decisions. It executes
no action. A checkpoint cannot add authority; the immutable owner contract is
copied exactly into every checkpoint. Closing means owner scheduling closure,
never a verified artifact, PASS, or a promise to run after the current session.
"""
from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import time
import uuid

from .core import GuardError, canonical, digest


MAX_CONTEXT_BYTES = 8192
MAX_CONTRACT_BYTES = 16384
MAX_LEASE_SECONDS = 300
MAX_SOURCE_BYTES = 4 * 1024 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CONTRACT_FIELDS = {"version", "mission", "constraints", "decisions", "sources",
                    "files", "criteria", "actions", "dependencies", "max_attempts", "budget"}
_CONTEXT_FIELDS = {"contract_sha", "version", "mission", "constraints", "decisions",
                   "sources", "criteria", "active_action", "next_action"}
_SCHEMA = (
    "CREATE TABLE continuity_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,uuid TEXT NOT NULL,locator TEXT NOT NULL,last_now REAL NOT NULL)",
    "CREATE TABLE continuity_tasks(id TEXT PRIMARY KEY,contract TEXT NOT NULL,contract_sha TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,fence INTEGER NOT NULL,attempts INTEGER NOT NULL,spent INTEGER NOT NULL,owner TEXT,lease_until REAL,checkpoint TEXT,tool TEXT,quota_tools TEXT NOT NULL,reason TEXT,disposition TEXT)",
    "CREATE TABLE continuity_receipts(key TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,result TEXT NOT NULL)",
    "CREATE TABLE continuity_events(id INTEGER PRIMARY KEY,body TEXT NOT NULL,previous TEXT NOT NULL,hash TEXT NOT NULL)",
    "CREATE TRIGGER continuity_contract_immutable BEFORE UPDATE OF id,contract,contract_sha ON continuity_tasks BEGIN SELECT RAISE(ABORT,'immutable continuity contract'); END",
    "CREATE TRIGGER continuity_receipts_no_update BEFORE UPDATE ON continuity_receipts BEGIN SELECT RAISE(ABORT,'immutable continuity receipt'); END",
    "CREATE TRIGGER continuity_receipts_no_delete BEFORE DELETE ON continuity_receipts BEGIN SELECT RAISE(ABORT,'immutable continuity receipt'); END",
    "CREATE TRIGGER continuity_events_no_update BEFORE UPDATE ON continuity_events BEGIN SELECT RAISE(ABORT,'immutable continuity event'); END",
    "CREATE TRIGGER continuity_events_no_delete BEFORE DELETE ON continuity_events BEGIN SELECT RAISE(ABORT,'immutable continuity event'); END",
)


def _id(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise GuardError("invalid continuity identifier")
    return value


def _bounded_json(value, limit):
    try:
        serialized = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False, allow_nan=False)
        if len(serialized.encode("utf-8")) > limit:
            raise GuardError("continuity request exceeds UTF-8 bound")
        return serialized
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise GuardError("invalid continuity JSON") from None


def _integer(value, minimum=1, maximum=1024):
    if type(value) is not int or not minimum <= value <= maximum:
        raise GuardError("invalid continuity integer")
    return value


def _text(value, limit=512):
    try:
        valid = isinstance(value, str) and 0 < len(value.encode("utf-8")) <= limit
    except UnicodeError:
        valid = False
    if not valid:
        raise GuardError("invalid or oversized UTF-8 text")
    return value


def _texts(value, maximum=16, allow_empty=False):
    if not isinstance(value, list) or not (0 if allow_empty else 1) <= len(value) <= maximum:
        raise GuardError("invalid continuity list")
    for item in value:
        _text(item)
    if len(set(value)) != len(value):
        raise GuardError("duplicate continuity list entry")


def _path(value):
    _text(value, 1024)
    path = Path(value)
    if not path.is_absolute() or str(path.resolve()) != value:
        raise GuardError("continuity file path must be canonical and absolute")
    return path


def source_sha(path):
    """Hash a regular local source. Caller must still pin the returned digest.

    This is an observation, not a snapshot lock on a filesystem another process
    can change. The journal never reads credentials or discovers source paths.
    """
    path = _path(str(path))
    if path.is_symlink() or not path.is_file():
        raise GuardError("continuity source missing or not a regular file", "BLOCK")
    before = path.stat()
    if before.st_size > MAX_SOURCE_BYTES:
        raise GuardError("continuity source exceeds local hashing bound", "BLOCK")
    result = hashlib.sha256()
    consumed = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            consumed += len(chunk)
            if consumed > MAX_SOURCE_BYTES:
                raise GuardError("continuity source grew beyond local hashing bound", "BLOCK")
            result.update(chunk)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise GuardError("continuity source changed while hashing", "BLOCK")
    return result.hexdigest()


class ContinuityJournal:
    """Trusted owner-only API with a database independent of Runtime.

    A lease reserves an attempt and local budget atomically. No refund, implicit
    retry, lease extension, platform capacity discovery, or permission escalation
    exists. Do not expose this object or its database to workers.
    """

    def __init__(self, path, clock=time.time):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA busy_timeout=10000")
            expected = {"continuity_meta", "continuity_tasks", "continuity_receipts", "continuity_events"}
            tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and tables != expected:
                raise GuardError("continuity refuses foreign database", "BLOCK")
            if tables:
                # WAL is persistent: inspect/reject existing stores before any
                # PRAGMA which can change their on-disk configuration.
                meta = self.db.execute("SELECT * FROM continuity_meta WHERE singleton=1").fetchone()
                if not meta or meta["version"] != 1 or meta["locator"] != digest(str(self.path)) or not self.verify_chain():
                    raise GuardError("continuity existing store invalid", "BLOCK")
                self.identity = digest(canonical({"uuid": str(uuid.UUID(meta["uuid"])), "locator": meta["locator"]}))
                for row in self.db.execute("SELECT id FROM continuity_tasks"):
                    self.get(row["id"])
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            with self._transaction():
                tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if tables and tables != expected:
                    raise GuardError("continuity refuses foreign database", "BLOCK")
                if not tables:
                    for statement in _SCHEMA:
                        self.db.execute(statement)
                    self.db.execute("INSERT INTO continuity_meta VALUES(1,1,?,?,0)",
                                    (str(uuid.uuid4()), digest(str(self.path))))
                meta = self.db.execute("SELECT * FROM continuity_meta WHERE singleton=1").fetchone()
                if not meta or meta["version"] != 1 or meta["locator"] != digest(str(self.path)):
                    raise GuardError("continuity schema or locator mismatch", "BLOCK")
                self.identity = digest(canonical({"uuid": str(uuid.UUID(meta["uuid"])), "locator": meta["locator"]}))
                if not self.verify_chain():
                    raise GuardError("continuity journal chain invalid", "BLOCK")
        except BaseException:
            self.db.close()
            raise

    def close(self):
        """Close the connection only; never schedules work after a session."""
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    @contextmanager
    def _transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException as original:
            # Some SQLite storage errors automatically abort the transaction.
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

    def _now(self):
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now) or now < 0:
            raise GuardError("invalid continuity clock", "BLOCK")
        previous = self.db.execute("SELECT last_now FROM continuity_meta").fetchone()[0]
        if now < previous:
            raise GuardError("continuity clock moved backwards", "BLOCK")
        self.db.execute("UPDATE continuity_meta SET last_now=?", (now,))
        return now

    def _row(self, task, revision=None):
        row = self.db.execute("SELECT * FROM continuity_tasks WHERE id=?", (_id(task),)).fetchone()
        if row is None:
            raise GuardError("unknown continuity task")
        if revision is not None and row["revision"] != _integer(revision, maximum=2**63-1):
            raise GuardError("stale continuity revision", "BLOCK")
        if digest(row["contract"]) != row["contract_sha"]:
            raise GuardError("continuity contract hash mismatch", "BLOCK")
        return row

    def get(self, task):
        row = dict(self._row(task))
        try:
            row["contract"] = json.loads(row["contract"])
            row["checkpoint"] = json.loads(row["checkpoint"])
            context = row["checkpoint"]
            if not isinstance(context, dict) or set(context) != _CONTEXT_FIELDS:
                raise GuardError("stored continuity context invalid", "BLOCK")
            expected = self._context(row["contract"], row["contract_sha"], context["active_action"], context["next_action"])
            if canonical(context) != canonical(expected):
                raise GuardError("stored continuity context differs from owner contract", "BLOCK")
            row["quota_tools"] = json.loads(row["quota_tools"])
            if not isinstance(row["quota_tools"], list) or not set(row["quota_tools"]) <= {a["tool"] for a in row["contract"]["actions"]}:
                raise GuardError("stored quota tool scope invalid", "BLOCK")
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise GuardError("stored continuity JSON invalid", "BLOCK") from None
        row["journal_id"] = self.identity
        return row

    def _operation(self, key, request, change):
        """Receipt and state transition share one commit; replay has no effect."""
        _id(key)
        fingerprint = digest(_bounded_json({"journal_id": self.identity, **request}, 32768))
        with self._transaction():
            existing = self.db.execute("SELECT * FROM continuity_receipts WHERE key=?", (key,)).fetchone()
            if existing:
                if existing["fingerprint"] != fingerprint:
                    raise GuardError("continuity operation key collision")
                return {**json.loads(existing["result"]), "replayed": True}
            now = self._now()
            task = change(now)
            result = {**self.get(task), "replayed": False}
            previous_row = self.db.execute("SELECT id,hash FROM continuity_events ORDER BY id DESC LIMIT 1").fetchone()
            sequence = previous_row["id"] + 1 if previous_row else 1
            previous = previous_row["hash"] if previous_row else "0" * 64
            body = canonical({"sequence": sequence, "at": now, "key": key,
                              "request": request, "state": result["state"],
                              "revision": result["revision"], "fence": result["fence"],
                              "journal_id": self.identity})
            event_hash = digest(previous + body)
            self.db.execute("INSERT INTO continuity_events VALUES(?,?,?,?)", (sequence, body, previous, event_hash))
            self.db.execute("INSERT INTO continuity_receipts VALUES(?,?,?)", (key, fingerprint, canonical(result)))
            return result

    def verify_chain(self):
        previous = "0" * 64
        for sequence, row in enumerate(self.db.execute("SELECT * FROM continuity_events ORDER BY id"), 1):
            if row["id"] != sequence or row["previous"] != previous or row["hash"] != digest(previous + row["body"]):
                return False
            previous = row["hash"]
        return True

    def events(self):
        return [{"body": json.loads(r["body"]), "previous": r["previous"], "hash": r["hash"]}
                for r in self.db.execute("SELECT * FROM continuity_events ORDER BY id")]

    def _validate_contract(self, contract):
        if not isinstance(contract, dict) or set(contract) != _CONTRACT_FIELDS:
            raise GuardError("exact continuity contract fields required")
        _integer(contract["version"], maximum=2**31-1)
        _text(contract["mission"], 2048)
        for field in ("constraints", "criteria"):
            _texts(contract[field])
        _texts(contract["decisions"], allow_empty=True)
        _integer(contract["max_attempts"], maximum=32)
        _integer(contract["budget"])
        _texts(contract["files"], maximum=32, allow_empty=True)
        for path in contract["files"]:
            _path(path)
        sources = contract["sources"]
        if not isinstance(sources, dict) or not 1 <= len(sources) <= 32:
            raise GuardError("continuity requires pinned sources")
        for path, sha in sources.items():
            _path(path)
            if not isinstance(sha, str) or not _SHA.fullmatch(sha):
                raise GuardError("invalid continuity source hash")
        if set(sources) & set(contract["files"]):
            raise GuardError("pinned sources and writable files must be separate")
        actions = contract["actions"]
        if not isinstance(actions, list) or not 1 <= len(actions) <= 16:
            raise GuardError("invalid continuity actions")
        ids = []
        for action in actions:
            if not isinstance(action, dict) or set(action) != {"id", "tool", "files", "description"}:
                raise GuardError("exact continuity action fields required")
            ids.append(_id(action["id"]))
            _id(action["tool"])
            _text(action["description"])
            _texts(action["files"], maximum=32, allow_empty=True)
            if not set(action["files"]) <= set(contract["files"]):
                raise GuardError("action exceeds owner file scope")
        if len(set(ids)) != len(ids):
            raise GuardError("duplicate continuity action")
        deps = contract["dependencies"]
        if not isinstance(deps, dict) or len(deps) > 32:
            raise GuardError("invalid continuity dependencies")
        for task, pin in deps.items():
            parent = self._row(task)
            if not isinstance(pin, dict) or set(pin) != {"version", "contract_sha"}:
                raise GuardError("exact dependency pins required")
            if pin != {"version": json.loads(parent["contract"])["version"], "contract_sha": parent["contract_sha"]}:
                raise GuardError("dependency contract mismatch", "BLOCK")
        serialized = canonical(contract)
        if len(serialized.encode("utf-8")) > MAX_CONTRACT_BYTES:
            raise GuardError("continuity contract exceeds UTF-8 bound")
        self._context(contract, digest(serialized), ids[0], None)
        return serialized

    @staticmethod
    def _context(contract, sha, active_action, next_action):
        _id(active_action)
        if next_action is not None:
            _id(next_action)
        ids = {a["id"] for a in contract["actions"]}
        if active_action not in ids or (next_action is not None and next_action not in ids):
            raise GuardError("checkpoint action outside owner contract")
        context = {key: contract[key] for key in ("version", "mission", "constraints", "decisions", "sources", "criteria")}
        context.update(contract_sha=sha, active_action=active_action, next_action=next_action)
        if len(canonical(context).encode("utf-8")) > MAX_CONTEXT_BYTES:
            raise GuardError("checkpoint exceeds UTF-8 bound")
        return context

    def context_for(self, task, active_action, next_action=None):
        row = self.get(task)
        return self._context(row["contract"], row["contract_sha"], active_action, next_action)

    def create_task(self, task, contract, *, key):
        _id(task)
        contract = json.loads(_bounded_json(contract, MAX_CONTRACT_BYTES))
        def change(now):
            serialized = self._validate_contract(contract)
            if self.db.execute("SELECT 1 FROM continuity_tasks WHERE id=?", (task,)).fetchone():
                raise GuardError("continuity task already exists")
            planned = self._context(contract, digest(serialized), contract["actions"][0]["id"], None)
            self.db.execute("INSERT INTO continuity_tasks VALUES(?,?,?,'READY',1,0,0,0,NULL,NULL,?,NULL,'[]',NULL,NULL)",
                            (task, serialized, digest(serialized), canonical(planned)))
            return task
        return self._operation(key, {"operation": "create", "task": task, "contract": contract}, change)

    def _sources_current(self, contract):
        try:
            return all(source_sha(path) == sha for path, sha in contract["sources"].items())
        except (OSError, GuardError):
            return False

    def _block(self, task, reason):
        self.db.execute("UPDATE continuity_tasks SET state=?,reason=?,revision=revision+1,fence=fence+1,owner=NULL,lease_until=NULL WHERE id=?",
                        ("BLOCKED_" + reason, reason, task))

    def claim(self, task, owner, tool, *, expected_revision, key, cost=1, ttl=60):
        _id(owner); _id(tool); _integer(cost); _integer(ttl, maximum=MAX_LEASE_SECONDS)
        def change(now):
            row = self._row(task, expected_revision)
            if row["state"] not in ("READY", "PAUSED"):
                raise GuardError("continuity task is not claimable", "BLOCK")
            contract = json.loads(row["contract"])
            if tool not in {a["tool"] for a in contract["actions"]}:
                raise GuardError("tool outside owner contract")
            if tool in json.loads(row["quota_tools"]):
                raise GuardError("tool still has a reported hard quota", "BLOCK")
            for parent, pin in contract["dependencies"].items():
                dependency = self.get(parent)
                if dependency["contract_sha"] != pin["contract_sha"] or dependency["contract"]["version"] != pin["version"]:
                    raise GuardError("dependency changed", "BLOCK")
                if dependency["state"] != "CLOSED" or dependency["disposition"] != "OWNER_COMPLETED":
                    raise GuardError("dependency is not owner-completed", "BLOCK")
            sources_current = self._sources_current(contract)
            now = self._now()  # Lease starts after bounded local source I/O.
            if not sources_current:
                self._block(task, "SOURCE")
            elif row["attempts"] >= contract["max_attempts"] or row["spent"] + cost > contract["budget"]:
                self._block(task, "BUDGET")
            else:
                self.db.execute("UPDATE continuity_tasks SET state='RUNNING',revision=revision+1,fence=fence+1,attempts=attempts+1,spent=spent+?,owner=?,lease_until=?,tool=?,reason=NULL WHERE id=?",
                                (cost, owner, now + ttl, tool, task))
            return task
        return self._operation(key, {"operation": "claim", "task": task, "owner": owner, "tool": tool,
                                    "revision": expected_revision, "cost": cost, "ttl": ttl}, change)

    def _live(self, task, revision, owner, fence, now):
        row = self._row(task, revision)
        _id(owner); _integer(fence, maximum=2**63-1)
        if row["state"] != "RUNNING" or row["owner"] != owner or row["fence"] != fence or now >= row["lease_until"]:
            raise GuardError("continuity lease expired or fenced", "BLOCK")
        return row

    def checkpoint(self, task, context, *, expected_revision, owner, fence, key):
        context = json.loads(_bounded_json(context, MAX_CONTEXT_BYTES))
        def change(now):
            row = self._live(task, expected_revision, owner, fence, now)
            if not isinstance(context, dict) or set(context) != _CONTEXT_FIELDS:
                raise GuardError("exact structured checkpoint fields required")
            expected = self._context(json.loads(row["contract"]), row["contract_sha"], context["active_action"], context["next_action"])
            if canonical(context) != canonical(expected):
                raise GuardError("checkpoint cannot alter owner mission, authority, sources or criteria")
            active = next(a for a in json.loads(row["contract"])["actions"] if a["id"] == context["active_action"])
            if active["tool"] != row["tool"]:
                raise GuardError("checkpoint action differs from claimed tool")
            sources_current = self._sources_current(json.loads(row["contract"]))
            self._live(task, expected_revision, owner, fence, self._now())
            if not sources_current:
                self._block(task, "SOURCE")
            else:
                self.db.execute("UPDATE continuity_tasks SET checkpoint=?,revision=revision+1 WHERE id=?", (canonical(context), task))
            return task
        return self._operation(key, {"operation": "checkpoint", "task": task, "context": context,
                                    "revision": expected_revision, "owner": owner, "fence": fence}, change)

    def interrupt(self, task, *, expected_revision, owner, fence, key, reason="INTERRUPTED"):
        if reason not in ("INTERRUPTED", "SOFT_QUOTA"):
            raise GuardError("invalid continuity interruption reason")
        def change(now):
            self._live(task, expected_revision, owner, fence, now)
            self.db.execute("UPDATE continuity_tasks SET state='PAUSED',revision=revision+1,fence=fence+1,owner=NULL,lease_until=NULL,reason=? WHERE id=?", (reason, task))
            return task
        return self._operation(key, {"operation": "interrupt", "task": task, "revision": expected_revision,
                                    "owner": owner, "fence": fence, "reason": reason}, change)

    def recover(self, task, *, expected_revision, key):
        """Owner explicitly recovers an expired lease; quota/budget stay blocked."""
        def change(now):
            row = self._row(task, expected_revision)
            if row["state"] != "RUNNING" or now < row["lease_until"]:
                raise GuardError("only an expired running lease is recoverable", "BLOCK")
            contract = json.loads(row["contract"])
            if not self._sources_current(contract):
                self._block(task, "SOURCE")
            elif row["attempts"] >= contract["max_attempts"] or row["spent"] >= contract["budget"]:
                self._block(task, "BUDGET")
            else:
                self.db.execute("UPDATE continuity_tasks SET state='PAUSED',revision=revision+1,fence=fence+1,owner=NULL,lease_until=NULL,reason='EXPIRED_LEASE' WHERE id=?", (task,))
            return task
        return self._operation(key, {"operation": "recover", "task": task, "revision": expected_revision}, change)

    def report_hard_quota(self, task, *, expected_revision, owner, fence, key):
        def change(now):
            row = self._live(task, expected_revision, owner, fence, now)
            self._block(task, "QUOTA")
            blocked = sorted(set(json.loads(row["quota_tools"])) | {row["tool"]})
            self.db.execute("UPDATE continuity_tasks SET quota_tools=? WHERE id=?", (canonical(blocked), task))
            return task
        return self._operation(key, {"operation": "hard_quota", "task": task, "revision": expected_revision,
                                    "owner": owner, "fence": fence}, change)

    def release_quota(self, task, *, expected_revision, key, capacity_available=False, alternate_tool=None):
        """Owner assertion only; never discovers or removes platform quota.

        The alternate must already be in the immutable contract. Budget and
        attempts remain charged, and the next claim still checks their limits.
        """
        if type(capacity_available) is not bool or (alternate_tool is not None and capacity_available):
            raise GuardError("one explicit quota release reason required")
        def change(now):
            row = self._row(task, expected_revision)
            if row["state"] != "BLOCKED_QUOTA":
                raise GuardError("continuity task is not quota-blocked", "BLOCK")
            tool = row["tool"]
            blocked = json.loads(row["quota_tools"])
            if alternate_tool is not None:
                _id(alternate_tool)
                if alternate_tool == tool or alternate_tool in blocked or alternate_tool not in {a["tool"] for a in json.loads(row["contract"])["actions"]}:
                    raise GuardError("alternate tool is not already authorized")
                tool = alternate_tool
            elif not capacity_available:
                raise GuardError("hard quota requires explicit available capacity", "BLOCK")
            else:
                blocked.remove(tool)
            self.db.execute("UPDATE continuity_tasks SET state='PAUSED',revision=revision+1,tool=?,quota_tools=?,reason='OWNER_QUOTA_RELEASE' WHERE id=?", (tool, canonical(blocked), task))
            return task
        return self._operation(key, {"operation": "release_quota", "task": task, "revision": expected_revision,
                                    "capacity_available": capacity_available, "alternate_tool": alternate_tool}, change)

    def close_task(self, task, *, expected_revision, key, disposition="OWNER_ABANDONED"):
        if disposition not in ("OWNER_COMPLETED", "OWNER_ABANDONED"):
            raise GuardError("closure is not a PASS or verification")
        def change(now):
            row = self._row(task, expected_revision)
            if row["state"] == "CLOSED":
                raise GuardError("continuity task already closed")
            self.db.execute("UPDATE continuity_tasks SET state='CLOSED',revision=revision+1,fence=fence+1,owner=NULL,lease_until=NULL,disposition=?,reason='OWNER_CLOSED' WHERE id=?", (disposition, task))
            return task
        return self._operation(key, {"operation": "close", "task": task, "revision": expected_revision,
                                    "disposition": disposition}, change)
