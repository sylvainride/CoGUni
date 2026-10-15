"""Non-authoritative resume descriptors pinned to the ORIGINAL ContinuityJournal.

This is neither a storage migration nor a permission/lease/dispatch credential.
Every import reopens the original trusted SQLite journal via OwnerScheduler and
rechecks live identity, source pins, revision, fence and exact provider binding.
"""
from dataclasses import dataclass
import json
import re

from .core import GuardError, canonical, digest
from .parallel_scheduler import OwnerScheduler

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BYTES = 8192
_FIELDS = {"schema", "kind", "authority", "journal_id", "tasks", "digest"}
_ENTRY = {"task_id", "revision", "fence", "contract_sha256", "code_ref",
          "request_sha256", "state", "provider"}


@dataclass(frozen=True, slots=True)
class ValidatedResume:
    task_ids: tuple[str, ...]
    states: tuple[str, ...]
    action: str = "OBSERVE_ONLY"
    execution_authorized: bool = False


def _original(scheduler):
    if type(scheduler) is not OwnerScheduler:
        raise GuardError("original existing OwnerScheduler required")
    if not scheduler.journal.verify_chain():
        raise GuardError("original owner event chain failed")
    return scheduler


def export_resume(scheduler, task_ids):
    """Portable *hint* only; output has no path, secret, receipt or grant."""
    _original(scheduler)
    if (type(task_ids) not in (tuple, list) or not 1 <= len(task_ids) <= 16
            or any(type(t) is not str or not _ID.fullmatch(t) for t in task_ids)
            or len(set(task_ids)) != len(task_ids)):
        raise GuardError("bounded unique owner resume selection required")
    entries = []
    for task_id in task_ids:
        status = scheduler.status(task_id)
        entries.append({field: status[field] for field in _ENTRY})
    body = {"schema": 1, "kind": "coguni-passive-resume-v1", "authority": "NONE",
            "journal_id": scheduler.journal.identity, "tasks": entries}
    wire = canonical({**body, "digest": digest(canonical(body))})
    if len(wire.encode("utf-8")) > _MAX_BYTES:
        raise GuardError("resume hint exceeds bounded size")
    return wire


def validate_resume(scheduler, wire):
    """Always consult SAME durable journal; reject stale/foreign/copy by identity."""
    _original(scheduler)
    if type(wire) is not str or not 0 < len(wire) <= _MAX_BYTES:
        raise GuardError("invalid resume hint")
    try:
        raw = wire.encode("utf-8")
        if len(raw) > _MAX_BYTES:
            raise ValueError("oversized resume hint")
        data = json.loads(raw)
        if (type(data) is not dict or set(data) != _FIELDS
                or type(data["schema"]) is not int or data["schema"] != 1
                or data["kind"] != "coguni-passive-resume-v1"
                or data["authority"] != "NONE"
                or type(data["journal_id"]) is not str
                or not _SHA64.fullmatch(data["journal_id"])
                or type(data["digest"]) is not str or not _SHA64.fullmatch(data["digest"])
                or canonical(data) != wire):
            raise ValueError("noncanonical or unknown descriptor")
        body = {key: value for key, value in data.items() if key != "digest"}
        if data["digest"] != digest(canonical(body)) or data["journal_id"] != scheduler.journal.identity:
            raise ValueError("foreign/tampered owner journal")
        entries = data["tasks"]
        if type(entries) is not list or not 1 <= len(entries) <= 16:
            raise ValueError("invalid number of resume entries")
        ids = []
        states = []
        for entry in entries:
            if type(entry) is not dict or set(entry) != _ENTRY:
                raise ValueError("invalid task reference")
            task_id = entry["task_id"]
            if type(task_id) is not str or not _ID.fullmatch(task_id) or task_id in ids:
                raise ValueError("duplicate or invalid task")
            # .status => scheduler._row => current code/source pin, journal authority.
            current = scheduler.status(task_id)
            if (any(type(entry[n]) is not int or type(entry[n]) is bool
                    for n in ("revision", "fence"))
                    or any(entry[field] != current[field] for field in _ENTRY)):
                raise ValueError("stale fence/revision/provider/source/state")
            ids.append(task_id)
            states.append(current["state"])
        return ValidatedResume(tuple(ids), tuple(states))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise GuardError("stale, malformed or foreign resume descriptor") from exc
