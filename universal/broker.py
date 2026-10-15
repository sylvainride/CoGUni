"""Trusted SQLite owner; worker/verifier capabilities derive from separate FDs."""
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import secrets
import select
import signal
import socket
import sqlite3
import shutil
import subprocess
import sys
import time

from .core import GuardError, Intent, Runtime
from .credentials import assert_run_credentials_active, rotate_run_token
from .isolation import build_command
from .protocol import ProtocolError, VERSION, recv_message, require, send_message


def environment_identity():
    directory = Path(__file__).parent
    files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(directory.glob("*.py"))}
    driver = shutil.which("bwrap")
    driver_sha = hashlib.sha256(Path(driver).read_bytes()).hexdigest() if driver else None
    return hashlib.sha256(json.dumps({"files": files, "python": platform.python_version(), "platform": platform.system(), "kernel": platform.release(), "architecture": platform.machine(), "sqlite": sqlite3.sqlite_version, "driver_sha": driver_sha}, sort_keys=True).encode()).hexdigest()


class WorkerGate:
    MAX_REQUESTS_PER_JOB = 8

    def __init__(self, runtime, claim):
        self.runtime, self.claim, self.last_request = runtime, claim, 0
        self.request_count = 0

    def rotate_credentials(self):
        """Owner-only operation; no worker IPC opcode exposes this method."""
        rotated = rotate_run_token(self.runtime, self.claim["run_id"], self.claim["token"], expected_fence=self.claim["fence"])
        self.claim["token"] = rotated.token
        return rotated

    def handle(self, message):
        if not isinstance(message, dict) or type(message.get("op")) is not str:
            raise ProtocolError("invalid message schema")
        fields = {"version", "request_id", "job_id", "op"}
        if message.get("op") in {"read", "write"}:
            fields |= {"resource", "expected_version", "key", "fence", "args"}
        require(message, fields)
        if self.request_count >= self.MAX_REQUESTS_PER_JOB:
            raise GuardError("worker request budget exhausted", "BLOCK")
        self.request_count += 1
        sequence = message["request_id"]
        if type(sequence) is not int or not self.last_request < sequence <= 2**31 - 1 or message["job_id"] != self.claim["run_id"]:
            raise ProtocolError("invalid request identity or sequence")
        self.last_request = sequence
        operation = message["op"]
        if operation == "done":
            assert_run_credentials_active(self.runtime, self.claim["run_id"], self.claim["token"], expected_fence=self.claim["fence"])
            if self.runtime.task(self.claim["task"]["id"])["status"] != "RESULT_READY":
                raise GuardError("no committed result")
            return {"result_ready": True}
        if operation not in {"read", "write"}:
            raise GuardError("worker operation forbidden")
        expected_key = self.claim["run_id"] + (".read" if operation == "read" else ".write")
        if message["key"] != expected_key:
            raise GuardError("operation key does not match contract")
        intent = Intent(self.claim["run_id"], "artifact." + operation, message["resource"], message["expected_version"], expected_key, message["fence"], message["args"])
        return self.runtime.execute(intent, self.claim["token"])


class VerifierGate:
    def __init__(self, runtime, claim, environment):
        self.runtime, self.claim, self.environment = runtime, claim, environment
        self.nonce = secrets.token_hex(16)
        self.issued_snapshot = None

    def _bound_run(self):
        run = self.runtime.db.execute("SELECT * FROM runs WHERE id=?", (self.claim["run_id"],)).fetchone()
        source = self.runtime.resource(self.claim["task"]["input"])
        output = self.runtime.resource(self.claim["task"]["output"])
        if not run or run["task"] != self.claim["task"]["id"] or run["state"] != "SUCCEEDED" or run["input_version"] != self.claim["task"]["input_version"] or run["output_version"] != self.claim["output_version"] + 1 or source["version"] != run["input_version"] or output["version"] != run["output_version"]:
            raise GuardError("verifier run binding stale", "BLOCK")
        return source, output

    def snapshot(self):
        source, output = self._bound_run()
        if self.issued_snapshot is None:
            self.issued_snapshot = {"run_id": self.claim["run_id"], "nonce": self.nonce, "input_version": source["version"], "output_version": output["version"], "content": output["content"]}
        return dict(self.issued_snapshot)

    def accept(self, message):
        require(message, {"version", "type", "run_id", "nonce", "input_version", "output_version", "observed_sha"})
        source, output = self._bound_run()
        if self.issued_snapshot is None or message["type"] != "verification" or message["run_id"] != self.claim["run_id"] or message["nonce"] != self.nonce or type(message["input_version"]) is not int or type(message["output_version"]) is not int or message["input_version"] != self.issued_snapshot["input_version"] or message["output_version"] != self.issued_snapshot["output_version"] or source["version"] != self.issued_snapshot["input_version"] or output["version"] != self.issued_snapshot["output_version"] or message["observed_sha"] != output["sha"]:
            raise GuardError("verifier snapshot mismatch")
        result = self.runtime.verify(self.claim["task"]["id"], self.environment, expected_run_id=self.claim["run_id"])
        result["accepted_for_gate"] = self.runtime.proof_is_accepted_for_gate(result["evidence"], self.environment)
        return result


@dataclass
class Channel:
    process: object
    socket: object
    role: str
    worker: str = ""
    claim: object = None
    gate: object = None
    jobs: int = 0
    ready: bool = False
    stopped: bool = False
    report: object = None
    verifier: object = None


def launch(role):
    parent, child = socket.socketpair()
    parent.settimeout(1)
    try:
        command = build_command(Path(__file__).parent, child.fileno(), role)
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(child.fileno(),), close_fds=True, start_new_session=True, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"})
    except BaseException:
        parent.close()
        child.close()
        raise
    child.close()
    return Channel(process, parent, role)


def stop_channel(channel):
    if channel.stopped:
        return
    channel.stopped = True
    channel.socket.close()
    try:
        channel.process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(channel.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            channel.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(channel.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            channel.process.wait(timeout=2)
    for stream in (channel.process.stdout, channel.process.stderr):
        stream.close()


def _trace(runtime, role, reason):
    with runtime.transaction():
        runtime._event(role, "ipc.refused", "channel", "DENY", {"reason": reason})


def verify_pending(runtime, environment, deadline, *, task_id=None):
    """Recover committed local candidates without re-emitting their mutations."""
    results = []
    rows = runtime.db.execute("SELECT tasks.id, runs.id AS run_id, runs.output_version FROM tasks JOIN runs ON runs.task=tasks.id WHERE tasks.validation_mode='DETERMINISTIC_EXACT_SHA' AND tasks.status='RESULT_READY' AND runs.state='SUCCEEDED' ORDER BY tasks.id,runs.started DESC").fetchall()
    seen = set()
    for row in rows:
        if task_id is not None and row["id"] != task_id:
            continue
        if row["id"] in seen:
            continue
        seen.add(row["id"])
        if time.monotonic() >= deadline:
            raise TimeoutError("pending verification deadline")
        claim = {"task": runtime.task(row["id"]), "run_id": row["run_id"], "output_version": row["output_version"] - 1}
        gate = VerifierGate(runtime, claim, environment)
        child = launch("verifier")
        child.socket.settimeout(max(.01, min(1, deadline - time.monotonic())))
        try:
            ready = recv_message(child.socket, deadline=deadline)
            require(ready, {"version", "type", "pid", "uid", "limits"})
            if ready["type"] != "ready" or ready["uid"] == 0:
                raise ProtocolError("invalid child bootstrap")
            send_message(child.socket, {"version": VERSION, "type": "verify", "snapshot": gate.snapshot()}, deadline=deadline)
            result = gate.accept(recv_message(child.socket, deadline=deadline))
            output = runtime.resource(claim["task"]["output"])
            results.append({"task": row["id"], "run": row["run_id"], "verification": result, "receipt": {"resource": output["id"], "version": output["version"], "sha": output["sha"]}, "verifier_process": child.process.pid, "recovered_committed_result": True})
        except (GuardError, ProtocolError, EOFError, OSError) as error:
            _trace(runtime, "verifier", type(error).__name__)
            results.append({"task": row["id"], "run": row["run_id"], "decision": "BLOCK", "reason": type(error).__name__, "recovered_committed_result": False})
        finally:
            stop_channel(child)
    return results


def run_pool(db_path, workers=2, max_jobs=100, timeout=30, worker_names=None, *, task_id=None):
    if type(workers) is not int or not 1 <= workers <= 8 or type(max_jobs) is not int or not 1 <= max_jobs <= 10000 or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise GuardError("invalid worker budget")
    if task_id is not None:
        Runtime._id(task_id)
    package, database = Path(__file__).parent.resolve(), Path(db_path).resolve()
    if database.is_relative_to(package) or database.is_relative_to(Path(sys.base_prefix).resolve()) or any(database.is_relative_to(Path(p).resolve()) for p in ("/lib", "/lib64", "/usr/lib")):
        raise GuardError("DB location intersects sandbox read mounts")
    names = worker_names or ["worker-" + str(i) for i in range(workers)]
    if len(names) != workers:
        raise GuardError("invalid worker names")
    environment = environment_identity()
    runtime = Runtime(database)
    channels = []
    reports = [{"worker": name, "results": [], "transport": "isolated_ipc"} for name in names]
    deadline = time.monotonic() + timeout

    def assign(channel):
        if channel.jobs >= max_jobs:
            send_message(channel.socket, {"version": VERSION, "type": "stop"}, deadline=deadline)
            stop_channel(channel)
            return
        claim = runtime.claim(channel.worker, ttl=min(3600, max(1, math.ceil(deadline - time.monotonic()))), environment=environment, supported_actions=Runtime.ACTIONS, task_id=task_id)
        if claim is None:
            send_message(channel.socket, {"version": VERSION, "type": "stop"}, deadline=deadline)
            stop_channel(channel)
            return
        channel.claim, channel.gate = claim, WorkerGate(runtime, claim)
        channel.jobs += 1
        task = claim["task"]
        job = {"job_id": claim["run_id"], "input": task["input"], "output": task["output"], "input_version": task["input_version"], "output_version": claim["output_version"], "fence": claim["fence"], "action": task["action"]}
        send_message(channel.socket, {"version": VERSION, "type": "job", "job": job}, deadline=deadline)

    def start_verifier(worker):
        verifier = launch("verifier")
        verifier.worker, verifier.claim, verifier.report = worker.worker, worker.claim, worker.report
        verifier.gate, verifier.verifier = VerifierGate(runtime, worker.claim, environment), worker
        worker.verifier = verifier
        channels.append(verifier)

    try:
        recovered = verify_pending(runtime, environment, deadline, task_id=task_id)
        if recovered:
            reports.append({"worker": "controller-recovery", "role": "controller", "results": recovered})
        for name, report in zip(names, reports):
            child = launch("worker")
            child.worker, child.report = name, report
            channels.append(child)
        while any(not c.stopped for c in channels):
            if time.monotonic() >= deadline:
                raise TimeoutError("isolated worker pool deadline")
            active = [c for c in channels if not c.stopped and not (c.role == "worker" and c.verifier is not None)]
            readable, _, _ = select.select([c.socket for c in active], [], [], min(.1, max(0, deadline - time.monotonic())))
            for current in list(active):
                if current.socket not in readable:
                    continue
                try:
                    message = recv_message(current.socket, deadline=deadline)
                    if not current.ready:
                        require(message, {"version", "type", "pid", "uid", "limits"})
                        if message["type"] != "ready" or message["uid"] == 0:
                            raise ProtocolError("invalid child bootstrap")
                        current.ready = True
                        current.report.setdefault("sandbox", {"uid": message["uid"], "limits": message["limits"]})
                        if current.role == "worker":
                            assign(current)
                        else:
                            send_message(current.socket, {"version": VERSION, "type": "verify", "snapshot": current.gate.snapshot()}, deadline=deadline)
                    elif current.role == "worker":
                        result = current.gate.handle(message)
                        send_message(current.socket, {"version": VERSION, "request_id": message["request_id"], "ok": True, "result": result}, deadline=deadline)
                        if message["op"] == "done":
                            start_verifier(current)
                    else:
                        result = current.gate.accept(message)
                        task, output = current.claim["task"], runtime.resource(current.claim["task"]["output"])
                        current.report["results"].append({"task": task["id"], "run": current.claim["run_id"], "receipt": {"resource": task["output"], "version": output["version"], "sha": output["sha"], "replayed": False}, "verification": result, "verifier_process": current.process.pid})
                        worker = current.verifier
                        worker.verifier = None
                        stop_channel(current)
                        if not worker.stopped:
                            assign(worker)
                except (GuardError, ProtocolError, EOFError, OSError) as error:
                    _trace(runtime, current.role, type(error).__name__)
                    current.report["results"].append({"task": current.claim["task"]["id"] if current.claim else None, "decision": "DENY", "reason": type(error).__name__})
                    if current.claim:
                        abandoned = runtime.abandon_run(current.claim["run_id"])
                        if current.role == "worker" and not abandoned and current.verifier is None:
                            state = runtime.db.execute("SELECT state FROM runs WHERE id=?", (current.claim["run_id"],)).fetchone()[0]
                            if state == "SUCCEEDED":
                                # ACK loss cannot erase a committed local receipt or rerun its effect.
                                start_verifier(current)
                    stop_channel(current)
                    if current.role == "verifier":
                        stop_channel(current.verifier)
        return reports
    finally:
        for current in channels:
            if not current.stopped:
                if current.claim:
                    runtime.abandon_run(current.claim["run_id"])
                stop_channel(current)
        runtime.close()
