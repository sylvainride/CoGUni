"""P6: pure, fail-closed proposal checker and inert systemd example renderer.

No host checks, imports from a deployed runtime, filesystem writes, network,
subprocess, grants, or installation. Even a validated proposal is UNTRUSTED
INTENT, never owner consent, host attestation or authorization to start P5.
"""

from dataclasses import dataclass
import json
import math
from pathlib import PurePosixPath
import re


MAX_PLAN_BYTES = 8192
P5_COMMIT = "5a000d8a4c719665534480d065cf5150b772f0a3"
P5_TREE = "43071a27f344b823d88a0f5118dca4753bd79cde"
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_FIELDS = frozenset({
    "schema", "repository", "repository_id", "owner_id", "source_commit",
    "source_tree", "host_type", "source_dir", "private_dir", "owner_user",
    "unit_basename", "scope", "network_scope", "credentials",
    "github_permissions", "cost_eur", "scheduler_enabled", "installed",
    "service_enabled", "timer_enabled", "timer_persistent", "github_write",
    "autonomous_ai", "paid_ai", "deployment_authorized", "p5_limits",
    "cadence_seconds", "backup_freshness", "storage_kind",
})
_CONSTANTS = {
    "schema": 1,
    "repository": "sylvainride/CoGUni",
    "repository_id": 1418009675,
    "owner_id": 265171248,
    "source_commit": P5_COMMIT,
    "source_tree": P5_TREE,
    "host_type": "LINUX_PRIVATE_OWNER",
    "source_dir": "/srv/coguni/source",
    "private_dir": "/var/lib/coguni-private",
    "owner_user": "coguni-observer",
    "unit_basename": "coguni-observer",
    "scope": "READ_ONLY_PUBLIC_SYNTHETIC",
    "network_scope": "PUBLIC_GITHUB_HTTPS_GET_ONLY",
    "credentials": "NONE",
    "github_permissions": "NONE",
    "cost_eur": 0,
    "scheduler_enabled": False,
    "installed": False,
    "service_enabled": False,
    "timer_enabled": False,
    "timer_persistent": False,
    "github_write": False,
    "autonomous_ai": False,
    "paid_ai": False,
    "deployment_authorized": False,
    "backup_freshness": "NOT_ATTESTED",
    "storage_kind": "LOCAL_PERSISTENT_TO_QUALIFY",
}
_LIMIT_KEYS = frozenset({"hard_timeout_seconds", "max_ticks", "max_seconds", "interval_seconds"})


class ProposalRejected(ValueError):
    """Generic public rejection: never echo an untrusted plan or host path."""


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ProposalRejected("invalid proposal")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ProposalRejected("invalid proposal")


def decode_plan(raw):
    """Parse bounded untrusted JSON; duplicated keys and invalid UTF-8 refuse."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_PLAN_BYTES:
        raise ProposalRejected("invalid proposal")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                         parse_constant=_reject_constant)
        validate_plan(obj)
        return obj
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise ProposalRejected("invalid proposal") from exc


def _fixed_path(value, fixed):
    # Pure validation; no resolution through the local host filesystem.
    if (type(value) is not str or value != fixed or not value.startswith("/")
            or "//" in value or "\\" in value or "\x00" in value
            or any(part in (".", "..") for part in value.split("/"))
            or str(PurePosixPath(value)) != value):
        raise ProposalRejected("invalid proposal")


def validate_plan(plan):
    """Return a non-authoritative intent verdict with all host gates NOT_RUN."""
    if type(plan) is not dict or set(plan) != _FIELDS:
        raise ProposalRejected("invalid proposal")
    for key, expected in _CONSTANTS.items():
        if type(plan[key]) is not type(expected) or plan[key] != expected:
            raise ProposalRejected("invalid proposal")
    if not _SHA40.fullmatch(plan["source_commit"]) or not _SHA40.fullmatch(plan["source_tree"]):
        raise ProposalRejected("invalid proposal")
    _fixed_path(plan["source_dir"], "/srv/coguni/source")
    _fixed_path(plan["private_dir"], "/var/lib/coguni-private")
    if (plan["source_dir"] == plan["private_dir"] or
            plan["private_dir"].startswith(plan["source_dir"] + "/") or
            plan["source_dir"].startswith(plan["private_dir"] + "/")):
        raise ProposalRejected("invalid proposal")
    limits = plan["p5_limits"]
    if type(limits) is not dict or set(limits) != _LIMIT_KEYS:
        raise ProposalRejected("invalid proposal")
    for name, low, high in (("max_ticks", 1, 16), ("interval_seconds", 1, 60),
                            ("max_seconds", 1, 300), ("hard_timeout_seconds", 0.1, 30)):
        value = limits[name]
        if (type(value) not in ((int, float) if name == "hard_timeout_seconds" else (int,))
                or not math.isfinite(value) or not low <= value <= high):
            raise ProposalRejected("invalid proposal")
    # P5 physical guardian has a measured 3s overhead, plus a preflight margin.
    if limits["max_seconds"] < math.ceil(limits["hard_timeout_seconds"] + 4):
        raise ProposalRejected("invalid proposal")
    cadence = plan["cadence_seconds"]
    if (type(cadence) is not int or not 600 <= cadence <= 86400
            or cadence < limits["max_seconds"] + 30):
        raise ProposalRejected("invalid proposal")
    return {
        "schema": 1, "status": "PREPARED_NOT_INSTALLED",
        "authority": "NONE", "inspection_scope": "STATIC_INTENT_ONLY",
        "source_commit": P5_COMMIT, "source_tree": P5_TREE,
        "external_scheduler_installed": False, "service_enabled": False,
        "timer_enabled": False, "autonomous_ai_installed": False,
        "human_approval_required": True, "allowed_external_effects": [],
        "host_permissions": "NOT_RUN", "host_os_process_and_storage": "NOT_RUN",
        "host_source_integrity": "NOT_RUN", "backup_freshness": "NOT_RUN",
        "provider_live_get": "NOT_RUN", "p5_pr_virtual_merge_ci": "NOT_RUN",
        "deployment": "NOT_RUN",
    }


def render_examples(plan):
    """Produce inert text, not files or a request to run systemctl.

    Templates intentionally contain NO [Install] sections and a false
    ConditionPathExists so copying a file alone never activates the observer.
    """
    validate_plan(plan)
    timeout = plan["p5_limits"]["max_seconds"] + 13  # 3s guardian + 10s margin
    cadence = plan["cadence_seconds"]
    service = f"""# EXAMPLE ONLY: NOT INSTALLED. REMOVE FAIL-CLOSED CONDITION ONLY AFTER HUMAN APPROVAL.
[Unit]
Description=CoGUni passive synthetic owner observer (EXAMPLE DISABLED)
ConditionPathExists=/__COGUNI_P6_DISABLED_UNTIL_APPROVED__
RefuseManualStart=yes

[Service]
Type=oneshot
User=coguni-observer
Group=coguni-observer
WorkingDirectory=/srv/coguni/source
ExecStart=/usr/bin/python3 -B -m universal.host_main observe-once --config /var/lib/coguni-private/host.json --checkpoint /var/lib/coguni-private/checkpoint.json
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/coguni-private
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
LockPersonality=yes
KillMode=control-group
TimeoutStartSec={timeout}s
TimeoutStopSec=5s
StandardOutput=null
StandardError=null
"""
    timer = f"""# EXAMPLE ONLY: NOT INSTALLED OR ENABLED; NO INSTALL SECTION.
[Unit]
Description=CoGUni passive synthetic observer timer (EXAMPLE DISABLED)
ConditionPathExists=/__COGUNI_P6_DISABLED_UNTIL_APPROVED__
RefuseManualStart=yes

[Timer]
Unit=coguni-observer.service
OnUnitInactiveSec={cadence}s
AccuracySec=1min
Persistent=false
"""
    return {"coguni-observer.service.example": service,
            "coguni-observer.timer.example": timer}
