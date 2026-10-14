"""Owner-side checks of bounded, untrusted Python function candidates.

The return value is unsigned evidence, never an acceptance or an attestation.
Only the owner may freeze the policy/context, recheck the exact target and sign.
Expected test values stay in this process and are never sent into the sandbox.
"""
from __future__ import annotations

import ast
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import unicodedata

from .isolation import (FILE_BYTES, MEMORY_BYTES, IsolationUnavailable,
                        build_command)
from .protocol import ProtocolError, VERSION, send_message


CRITERIA = frozenset({"tests", "lint", "security", "licenses", "provenance", "environment"})
MAX_FILES = 32
MAX_FILE_BYTES = 131_072
MAX_TREE_BYTES = 524_288
MAX_POLICY_BYTES = 65_536
MAX_CONTEXT_BYTES = 16_384
MAX_RESULT_BYTES = 16_384
MAX_FRAME_BYTES = 32_768
MAX_OUTPUT_BYTES = 65_536
CAPTURE_BYTES = 512
_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_SPDX = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+-]+)\s*\Z")
_POLICY_FIELDS = {"version", "entrypoint", "function", "tests", "allowed_licenses", "forbidden_markers", "max_seconds"}
_SAFE_IMPORTS = frozenset({"math", "statistics", "decimal", "fractions", "itertools", "functools", "collections", "re", "json"})
_DANGEROUS_NAMES = frozenset({"open", "eval", "exec", "compile", "__import__", "globals", "locals", "vars", "getattr", "setattr", "delattr", "input", "breakpoint", "exit", "quit"})


def _json(value, limit):
    """Copy plain finite JSON with bounded depth/nodes, then canonicalize it."""
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 8_192 or depth > 16:
            raise ValueError("JSON structure exceeds limits")
        kind = type(item)
        if kind is str:
            try:
                if len(item.encode("utf-8")) > limit:
                    raise ValueError("JSON string exceeds limit")
            except UnicodeError:
                raise ValueError("invalid UTF-8") from None
        elif kind is float:
            if not math.isfinite(item):
                raise ValueError("nonfinite JSON")
        elif kind in (type(None), bool, int):
            if kind is int and item.bit_length() > 4_096:
                raise ValueError("JSON integer exceeds limit")
        elif kind is list:
            if len(item) > 1_024:
                raise ValueError("JSON list exceeds limit")
            pending.extend((child, depth + 1) for child in item)
        elif kind is dict:
            if len(item) > 1_024 or any(type(key) is not str for key in item):
                raise ValueError("invalid JSON object")
            pending.extend((key, depth + 1) for key in item)
            pending.extend((child, depth + 1) for child in item.values())
        else:
            raise ValueError("plain JSON required")
    try:
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("invalid JSON") from None
    if len(encoded) > limit:
        raise ValueError("JSON exceeds byte limit")
    return json.loads(encoded), encoded


def _files(files):
    if type(files) is not dict or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("candidate must contain 1..32 text files")
    copied, total = {}, 0
    for name, content in files.items():
        if (type(name) is not str or len(name) > 160 or not _PATH.fullmatch(name)
                or any(part in {".", ".."} or part.casefold() == ".git" for part in name.split("/"))):
            raise ValueError("unsafe candidate path")
        if type(content) is not str:
            raise ValueError("candidate files must be plain text, never symlinks/binary")
        try:
            raw = content.encode("utf-8")
        except UnicodeError:
            raise ValueError("candidate file is not UTF-8") from None
        if len(raw) > MAX_FILE_BYTES or any(unicodedata.category(char) in {"Cc", "Cs"} and char not in "\t\n\r" for char in content):
            raise ValueError("binary or oversized candidate file")
        total += len(raw)
        if total > MAX_TREE_BYTES:
            raise ValueError("candidate tree exceeds byte limit")
        copied[name] = content
    names = set(copied)
    if any("/".join(name.split("/")[:index]) in names
           for name in names for index in range(1, len(name.split("/")))):
        raise ValueError("candidate file/directory collision")
    return copied


def validate_policy(policy):
    """Return a bounded snapshot; defining a policy remains an owner operation."""
    if type(policy) is dict and policy.get("profile") == "python-project-v1":
        from .project_runner import validate_project_policy
        return validate_project_policy(policy)
    copied, _ = _json(policy, MAX_POLICY_BYTES)
    if type(copied) is not dict or set(copied) != _POLICY_FIELDS:
        raise ValueError("invalid policy schema")
    if type(copied["version"]) is not int or copied["version"] != 1 or copied["entrypoint"] != "candidate.py":
        raise ValueError("invalid policy version/entrypoint")
    if type(copied["function"]) is not str or not _IDENTIFIER.fullmatch(copied["function"]):
        raise ValueError("invalid policy function")
    tests = copied["tests"]
    if type(tests) is not list or not 1 <= len(tests) <= 20:
        raise ValueError("policy requires 1..20 cases")
    for case in tests:
        if type(case) is not dict or set(case) != {"args", "expected"} or type(case["args"]) is not list or len(case["args"]) > 64:
            raise ValueError("invalid policy case")
        _json(case["args"], MAX_RESULT_BYTES)
        _json(case["expected"], MAX_RESULT_BYTES)
    licenses = copied["allowed_licenses"]
    if (type(licenses) is not list or not 1 <= len(licenses) <= 20
            or any(type(value) is not str or not re.fullmatch(r"[A-Za-z0-9.+-]{1,80}", value) for value in licenses)
            or len(set(licenses)) != len(licenses)):
        raise ValueError("invalid license allowlist")
    markers = copied["forbidden_markers"]
    if (type(markers) is not list or len(markers) > 32
            or any(type(value) is not str or not value or len(value.encode("utf-8")) > 256 for value in markers)):
        raise ValueError("invalid forbidden markers")
    seconds = copied["max_seconds"]
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0.05 <= seconds <= 10:
        raise ValueError("invalid policy deadline")
    return copied


def _git_tree(files, deadline):
    executable = shutil.which("git", path=os.defpath)
    if not executable:
        raise IsolationUnavailable("Git is required to calculate a real tree")
    with tempfile.TemporaryDirectory(prefix="cup-v8-git-") as directory:
        root = Path(directory)
        database = root / "objects.git"
        environment = {"PATH": os.defpath, "LANG": "C.UTF-8", "HOME": directory,
                       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null",
                       "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_INDEX_FILE": str(root / "index"),
                       "GIT_DEFAULT_HASH": "sha1", "GIT_ATTR_NOSYSTEM": "1"}

        def git(*arguments, data=None):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Git tree deadline")
            process = subprocess.run([executable, "--git-dir=" + str(database),
                                      "-c", "core.hooksPath=/dev/null", *arguments],
                                     input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=environment, cwd=directory, timeout=remaining, check=False)
            if process.returncode or len(process.stdout) > 1_024 or len(process.stderr) > 8_192:
                raise IsolationUnavailable("Git tree calculation failed")
            return process.stdout.strip().decode("ascii")

        git("init", "--bare", "--quiet", "--object-format=sha1")
        records = bytearray()
        for name in sorted(files):
            blob = git("hash-object", "-w", "--stdin", data=files[name].encode("utf-8"))
            if not re.fullmatch(r"[0-9a-f]{40}", blob):
                raise IsolationUnavailable("invalid Git blob identity")
            records.extend(b"100644 " + blob.encode("ascii") + b"\t" + name.encode("ascii") + b"\0")
        git("update-index", "-z", "--index-info", data=bytes(records))
        tree = git("write-tree")
        if not re.fullmatch(r"[0-9a-f]{40}", tree):
            raise IsolationUnavailable("invalid Git tree identity")
        return tree


def git_tree_sha(files: dict[str, str]) -> str:
    """Compute a real mode-100644 SHA-1 Git tree in a private temporary DB."""
    return _git_tree(_files(files), time.monotonic() + 10)


def _criterion(outcome, reason):
    return {"outcome": outcome, "reason": reason}


def _static_checks(files, policy):
    syntax_errors, dangerous, markers = [], [], []
    function_found = False
    for name, source in sorted(files.items()):
        markers.extend(name for marker in policy["forbidden_markers"] if marker in source)
        if not name.endswith(".py"):
            continue
        try:
            tree = ast.parse(source, filename=name)
            nodes = list(ast.walk(tree))
            if len(nodes) > 20_000:
                raise ValueError("AST exceeds node limit")
            compile(tree, name, "exec", dont_inherit=True, optimize=0)
            if name == "candidate.py":
                function_found = any(type(node) is ast.FunctionDef and node.name == policy["function"] for node in tree.body)
            for node in nodes:
                if isinstance(node, ast.Import) and any(alias.name.split(".")[0] not in _SAFE_IMPORTS for alias in node.names):
                    dangerous.append(name)
                elif isinstance(node, ast.ImportFrom) and (node.level or (node.module or "").split(".")[0] not in _SAFE_IMPORTS):
                    dangerous.append(name)
                elif isinstance(node, ast.Name) and node.id in _DANGEROUS_NAMES:
                    dangerous.append(name)
                elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
                    dangerous.append(name)
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
            syntax_errors.append(name)
    lint = _criterion("FAIL", "syntax_or_ast_limit") if syntax_errors else _criterion("PASS", "python_ast_compile")
    if not syntax_errors and not function_found:
        lint = _criterion("FAIL", "entrypoint_function_missing")
    security = _criterion("FAIL", "forbidden_marker_or_dangerous_ast") if markers or dangerous else _criterion("PASS", "bounded_literal_and_ast_scan")
    if syntax_errors and security["outcome"] == "PASS":
        security = _criterion("UNKNOWN", "security_ast_unavailable")
    license_source = files.get("LICENSE")
    identifiers = [] if license_source is None else [match.group(1) for line in license_source.splitlines() if (match := _SPDX.fullmatch(line.strip()))]
    if not identifiers:
        licenses = _criterion("UNKNOWN", "license_spdx_missing")
    elif len(identifiers) != 1 or identifiers[0] not in policy["allowed_licenses"]:
        licenses = _criterion("FAIL", "license_spdx_not_allowed")
    else:
        licenses = _criterion("PASS", "license_file_spdx_allowlist")
    return {"lint": lint, "security": security, "licenses": licenses}, {
        "syntax_files": sorted(set(syntax_errors)), "security_files": sorted(set(dangerous + markers)),
        "license_identifiers": [identifier[:80] for identifier in identifiers[:20]],
        "license_identifier_count": len(identifiers),
        "security_scope": "literal markers and restricted Python AST only"}


class _ChildFailure(Exception):
    def __init__(self, reason, unavailable=False):
        self.reason, self.unavailable = reason, unavailable
        super().__init__(reason)


class _Capture:
    def __init__(self):
        self.total = 0
        self.stdout, self.stderr = bytearray(), bytearray()
        self.frames = bytearray()

    def observation(self):
        return {"output_bytes": self.total,
                "stdout": self.stdout.decode("utf-8", errors="replace"),
                "stderr": self.stderr.decode("utf-8", errors="replace")}


def _decode_frame(payload):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite JSON")

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        copied, _ = _json(value, MAX_FRAME_BYTES)
        if type(copied) is not dict:
            raise ValueError("object required")
        return copied
    except (ValueError, UnicodeError, RecursionError):
        raise _ChildFailure("invalid_child_frame") from None


def _receive(channel, process, capture, deadline):
    """Read IPC while continuously draining both bounded output streams."""
    with selectors.DefaultSelector() as selector:
        for stream, kind in ((channel, "ipc"), (process.stdout, "stdout"), (process.stderr, "stderr")):
            selector.register(stream, selectors.EVENT_READ, kind)
        while True:
            if len(capture.frames) >= 4:
                size = struct.unpack("!I", capture.frames[:4])[0]
                if not 0 < size <= MAX_FRAME_BYTES:
                    raise _ChildFailure("child_frame_limit")
                if len(capture.frames) >= 4 + size:
                    payload = bytes(capture.frames[4:4 + size])
                    del capture.frames[:4 + size]
                    return _decode_frame(payload)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _ChildFailure("child_deadline")
            events = selector.select(remaining)
            if not events:
                raise _ChildFailure("child_deadline")
            for key, _ in events:
                try:
                    chunk = os.read(key.fd, 8_192)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    if key.data == "ipc":
                        raise _ChildFailure("child_ipc_closed", unavailable=True)
                    continue
                if key.data == "ipc":
                    capture.frames.extend(chunk)
                    if len(capture.frames) > MAX_FRAME_BYTES + 4:
                        raise _ChildFailure("child_frame_limit")
                else:
                    capture.total += len(chunk)
                    stored = getattr(capture, key.data)
                    stored.extend(chunk[:max(0, CAPTURE_BYTES - len(stored))])
                    if capture.total > MAX_OUTPUT_BYTES:
                        raise _ChildFailure("child_output_limit")


def _finish(channel, process, capture, deadline):
    """Observe clean exit and drain every byte, including output after result."""
    if capture.frames:
        raise _ChildFailure("unexpected_child_frame")
    with selectors.DefaultSelector() as selector:
        for stream, kind in ((channel, "ipc"), (process.stdout, "stdout"), (process.stderr, "stderr")):
            selector.register(stream, selectors.EVENT_READ, kind)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _ChildFailure("child_deadline")
            events = selector.select(remaining)
            if not events:
                raise _ChildFailure("child_deadline")
            for key, _ in events:
                try:
                    chunk = os.read(key.fd, 8_192)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "ipc":
                    raise _ChildFailure("unexpected_child_frame")
                capture.total += len(chunk)
                stored = getattr(capture, key.data)
                stored.extend(chunk[:max(0, CAPTURE_BYTES - len(stored))])
                if capture.total > MAX_OUTPUT_BYTES:
                    raise _ChildFailure("child_output_limit")
    process.wait(timeout=max(0.001, deadline - time.monotonic()))


def _ready(message, nonce, tree_sha, context_digest, index):
    fields = {"version", "type", "nonce", "tree_sha", "context_digest", "case_index", "pid", "uid", "gid", "limits", "no_new_privs", "seccomp", "environment", "namespaces", "visible_pids", "fds"}
    if type(message) is not dict or set(message) != fields or type(message["version"]) is not int or message["version"] != VERSION:
        return False
    if any(message[key] != expected for key, expected in {"type": "ready", "nonce": nonce, "tree_sha": tree_sha, "context_digest": context_digest, "case_index": index}.items()):
        return False
    expected_limits = {"address_space": MEMORY_BYTES, "cpu_seconds": 3, "file_bytes": FILE_BYTES, "processes": 0, "files": 64, "core": 0}
    if (type(message["pid"]) is not int or message["pid"] <= 0 or type(message["uid"]) is not int or message["uid"] != 65534
            or type(message["gid"]) is not int or message["gid"] != 65534 or message["limits"] != expected_limits
            or message["no_new_privs"] is not True or message["seccomp"] is not True
            or message["environment"] != {"LANG": "C.UTF-8", "PWD": "/tmp"}):
        return False
    namespaces = message["namespaces"]
    names = {"pid", "net", "mnt", "user", "ipc", "uts"}
    if type(namespaces) is not dict or set(namespaces) != names:
        return False
    if any(type(value) is not str or value == os.readlink("/proc/self/ns/" + name) for name, value in namespaces.items()):
        return False
    pids, fds = message["visible_pids"], message["fds"]
    return (type(pids) is list and 1 <= len(pids) <= 3 and all(type(pid) is int and pid > 0 for pid in pids)
            and type(fds) is list and len(fds) <= 5 and all(type(fd) is int and fd >= 0 for fd in fds))


def _run_case(files, policy, args, index, tree_sha, context_digest, deadline, *, project=None):
    parent, child = socket.socketpair()
    process, capture, ready, staging = None, _Capture(), None, None
    nonce = secrets.token_hex(24)
    result = {"index": index, "outcome": "UNKNOWN", "reason": "child_not_started"}
    try:
        trusted_package = Path(__file__).resolve().parent
        staging = tempfile.TemporaryDirectory(prefix="cup-v8-bootstrap-")
        package = Path(staging.name) / "universal"
        package.mkdir()
        # Do not bind the owner's package directory: it could acquire private
        # files later. This immutable mount contains only these trusted sources.
        bootstrap = "generative_child.py" if project is None else "project_child.py"
        for name in ("isolation.py", "protocol.py", bootstrap):
            source = trusted_package / name
            if not source.is_file() or source.is_symlink():
                raise IsolationUnavailable("trusted generative bootstrap is missing")
            shutil.copyfile(source, package / name)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "child.py").write_text("", encoding="utf-8")
        command = build_command(package, child.fileno(), "probe")
        position = command.index("/app/universal/child.py")
        command[position] = "/app/universal/" + bootstrap
        process = subprocess.Popen(command, pass_fds=(child.fileno(),), close_fds=True,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={"PATH": os.defpath, "LANG": "C.UTF-8"})
        child.close()
        parent.settimeout(max(0.001, deadline - time.monotonic()))
        payload = {"version": VERSION, "type": "execute", "nonce": nonce,
                   "tree_sha": tree_sha, "context_digest": context_digest,
                   "case_index": index, "args": args}
        if project is None:
            payload.update(source=files["candidate.py"], function=policy["function"])
        else:
            payload.update(modules=project, module=policy["tests"][index]["module"],
                           function=policy["tests"][index]["function"])
        send_message(parent, payload, deadline=deadline)
        for stream in (parent, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        ready = _receive(parent, process, capture, deadline)
        if not _ready(ready, nonce, tree_sha, context_digest, index):
            raise _ChildFailure("sandbox_readiness_invalid", unavailable=True)
        result["ready"] = ready
        response = _receive(parent, process, capture, deadline)
        fields = {"version", "type", "nonce", "tree_sha", "context_digest", "case_index", "ok", "value", "error"}
        binding = {"version": VERSION, "type": "result", "nonce": nonce, "tree_sha": tree_sha,
                   "context_digest": context_digest, "case_index": index}
        if (set(response) != fields or any(response.get(key) != expected for key, expected in binding.items())
                or type(response["version"]) is not int or type(response["case_index"]) is not int
                or type(response["ok"]) is not bool or type(response["error"]) is not str or len(response["error"]) > 80):
            raise _ChildFailure("child_result_schema")
        _, actual = _json(response["value"], MAX_RESULT_BYTES)
        if not response["ok"]:
            result.update(outcome="FAIL", reason="candidate_error")
        elif response["error"]:
            raise _ChildFailure("child_result_schema")
        else:
            # The oracle is deliberately looked up only here, outside the child.
            _, expected = _json(policy["tests"][index]["expected"], MAX_RESULT_BYTES)
            result.update(outcome="PASS" if actual == expected else "FAIL", reason="external_json_comparison")
        # No unbounded communicate(): drain all output, even from an exited child.
        _finish(parent, process, capture, deadline)
        if process.returncode != 0:
            result.update(outcome="FAIL", reason="child_exit_error")
    except IsolationUnavailable:
        result.update(outcome="NOT_RUN", reason="sandbox_unavailable")
    except _ChildFailure as error:
        result.update(outcome="UNKNOWN" if error.unavailable and ready is None else "FAIL", reason=error.reason)
    except (OSError, TimeoutError, subprocess.TimeoutExpired, ProtocolError, ValueError):
        result.update(outcome="FAIL" if ready else "UNKNOWN", reason="child_execution_error")
    finally:
        child.close()
        parent.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()
        if staging is not None:
            staging.cleanup()
        result.update(capture.observation())
    return result


def _bound_observations(observations):
    # Invalid UTF-8 output expands when represented by replacement characters;
    # enforce an aggregate encoded bound as well as each raw-byte capture cap.
    encoded = json.dumps(observations, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_POLICY_BYTES:
        for case in observations["cases"]:
            for stream in ("stdout", "stderr"):
                if stream in case:
                    case[stream] = case[stream][:128]
        observations["captures_truncated"] = True
    _json(observations, MAX_POLICY_BYTES)


def run_policy_checks(files: dict[str, str], policy: dict, context: dict, *, timeout=10.0) -> dict:
    """Run six mandatory checks with one total wall deadline and fresh children.

    Invalid owner inputs raise ValueError. Confinement/tool unavailability yields
    nonpositive evidence. Context must be nonsecret JSON audit metadata; only
    its SHA-256, never its contents, crosses the child boundary.
    """
    if type(policy) is dict and policy.get("profile") == "python-project-v1":
        from .project_runner import run_project_checks
        return run_project_checks(files, policy, context, timeout=timeout)
    started = time.monotonic()
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0.05 <= timeout <= 10:
        raise ValueError("invalid runner deadline")
    files, policy = _files(files), validate_policy(policy)
    if type(context) is not dict:
        raise ValueError("context must be a plain object")
    _, context_bytes = _json(context, MAX_CONTEXT_BYTES)
    _, policy_bytes = _json(policy, MAX_POLICY_BYTES)
    context_digest = hashlib.sha256(context_bytes).hexdigest()
    deadline = started + min(timeout, policy["max_seconds"])
    criteria, observations = _static_checks(files, policy)
    result = {"schema": "generative-policy-checks-v1", "context_digest": context_digest,
              "policy_digest": hashlib.sha256(policy_bytes).hexdigest(), "tree_sha": None,
              "criteria": criteria, "observations": observations}
    observations["cases"] = []
    try:
        result["tree_sha"] = _git_tree(files, deadline)
    except (IsolationUnavailable, TimeoutError, subprocess.TimeoutExpired, OSError):
        for name in ("tests", "provenance", "environment"):
            criteria[name] = _criterion("NOT_RUN", "git_tree_unavailable")
        return result
    if "candidate.py" not in files:
        criteria["tests"] = _criterion("FAIL", "entrypoint_missing")
        for name in ("provenance", "environment"):
            criteria[name] = _criterion("NOT_RUN", "entrypoint_missing")
        return result
    for index, case in enumerate(policy["tests"]):
        if time.monotonic() >= deadline:
            observations["cases"].append({"index": index, "outcome": "NOT_RUN", "reason": "total_deadline"})
            continue
        observations["cases"].append(_run_case(files, policy, case["args"], index,
                                                result["tree_sha"], context_digest, deadline))
    cases = observations["cases"]
    outcomes = {case["outcome"] for case in cases}
    outcome = "PASS" if outcomes == {"PASS"} else "FAIL" if "FAIL" in outcomes else "UNKNOWN" if "UNKNOWN" in outcomes else "NOT_RUN"
    criteria["tests"] = _criterion(outcome, "external_json_cases")
    all_ready = all("ready" in case for case in cases)
    criteria["provenance"] = _criterion("PASS" if all_ready else "NOT_RUN", "fresh_child_nonce_tree_context_binding" if all_ready else "child_binding_incomplete")
    criteria["environment"] = _criterion("PASS" if all_ready else "NOT_RUN", "linux_namespaces_seccomp_hard_limits" if all_ready else "sandbox_readiness_incomplete")
    _bound_observations(observations)
    return result
