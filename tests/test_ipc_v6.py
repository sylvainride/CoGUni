"""Real socket framing, broker permissions and confined hostile child probes.

Only disposable databases and package fixtures are used.  A hostile fixture is
still launched through the production Linux namespace/seccomp command builder.
No model, arbitrary host shell, external API or user data is involved.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from universal import broker
from universal.broker import Channel, VerifierGate, WorkerGate
from universal.core import GuardError, Runtime, digest
from universal.isolation import build_command
from universal.protocol import Client, MAX_FRAME, ProtocolError, VERSION, recv_message, send_message


HOSTILE_CHILD = r'''
import argparse, hashlib, json, os, resource, socket, struct, sys, time
sys.path.insert(0, "/app")
from universal.isolation import inside_child_limits
from universal.protocol import Client, MAX_FRAME, VERSION, recv_message, send_message
from universal.worker import worker_loop
p = argparse.ArgumentParser()
p.add_argument("--fd", type=int, required=True)
p.add_argument("--role", required=True)
p.add_argument("--scenario", required=True)
p.add_argument("--host-db", required=True)
p.add_argument("--host-canary", required=True)
a = p.parse_args()
s = socket.socket(fileno=a.fd)
s.settimeout(5)
inside_child_limits()
probe = {"db_read_blocked": False, "db_write_blocked": False,
         "canary_read_blocked": False, "fd_links": []}
for key, path, mode in (("db_read_blocked", a.host_db, "rb"),
                        ("db_write_blocked", a.host_db, "wb"),
                        ("canary_read_blocked", a.host_canary, "r")):
    try:
        with open(path, mode) as f:
            if mode != "wb": f.read()
    except OSError:
        probe[key] = True
for name in os.listdir("/proc/self/fd"):
    try: probe["fd_links"].append(os.readlink("/proc/self/fd/" + name))
    except OSError: pass
send_message(s, {"version": VERSION, "type": "ready", "pid": os.getpid(),
                "uid": os.geteuid(), "limits": {"probe": probe,
                "address_space": resource.getrlimit(resource.RLIMIT_AS)[0]}})
if a.role == "verifier":
    snapshot = recv_message(s)["snapshot"]
    if a.scenario == "verifier-crash":
        s.close(); os._exit(42)
    sha = hashlib.sha256(snapshot["content"].encode()).hexdigest()
    if a.scenario == "verifier-forgery": sha = "0" * 64
    send_message(s, {"version": VERSION, "type": "verification",
                    "run_id": snapshot["run_id"], "nonce": snapshot["nonce"],
                    "input_version": snapshot["input_version"],
                    "output_version": snapshot["output_version"], "observed_sha": sha})
    s.close(); sys.exit(0)
if a.scenario in {"correct", "verifier-forgery", "verifier-crash"}:
    worker_loop(s); s.close(); sys.exit(0)
job = recv_message(s)["job"]
c = Client(s)
common = {"job_id": job["job_id"], "resource": job["input"],
          "expected_version": job["input_version"], "key": job["job_id"] + ".read",
          "fence": job["fence"], "args": {}}
if a.scenario in {"owner", "grant", "verify"}:
    operation = {"owner": "put_resource", "grant": "grant", "verify": "verify"}[a.scenario]
    c.request(job_id=job["job_id"], op=operation)
elif a.scenario in {"duplicate-key", "nonfinite", "oversized", "truncated"}:
    if a.scenario == "oversized":
        s.sendall(struct.pack("!I", MAX_FRAME + 1))
    else:
        raw = (b'{"version":1,"version":1}' if a.scenario == "duplicate-key"
               else b'{"version":1,"x":NaN}' if a.scenario == "nonfinite"
               else b'{"x"')
        size = 100 if a.scenario == "truncated" else len(raw)
        s.sendall(struct.pack("!I", size) + raw)
    s.shutdown(socket.SHUT_WR)
    s.recv(100)
elif a.scenario == "slow-frame":
    raw = b'{"op":"verify"}'
    s.sendall(struct.pack("!I", len(raw)))
    for byte in raw:
        s.sendall(bytes([byte]))
        time.sleep(.15)
elif a.scenario == "role-spoof":
    send_message(s, {"version": VERSION, "request_id": 1,
                    "job_id": job["job_id"], "op": "verify", "role": "verifier"})
elif a.scenario == "malformed-op":
    c.request(job_id=job["job_id"], op=[])
elif a.scenario == "wrong-resource":
    common["resource"] = "controller-private"
    c.request(op="read", **common)
elif a.scenario == "crash-before":
    s.close(); os._exit(42)
elif a.scenario == "stall":
    time.sleep(10)
else:
    read = c.request(op="read", **common)
    content = read["content"].upper()
    if a.scenario == "wrong-output": content = "incorrect"
    write = {"job_id": job["job_id"], "op": "write", "resource": job["output"],
             "expected_version": job["output_version"], "key": job["job_id"] + ".write",
             "fence": job["fence"], "args": {"content": content}}
    if a.scenario == "unicode-content":
        write["args"]["content"] = chr(0xd800)
        raw = json.dumps({"version": VERSION, "request_id": 2, **write}).encode("ascii")
        s.sendall(struct.pack("!I", len(raw)) + raw)
        s.recv(100)
        s.close(); sys.exit(0)
    if a.scenario == "crash-after":
        send_message(s, {"version": VERSION, "request_id": 2, **write})
        s.shutdown(socket.SHUT_RDWR); s.close(); os._exit(42)
    receipt = c.request(**write)
    if a.scenario == "replay":
        replay = c.request(**write)
        assert replay["replayed"] is True
        assert receipt["version"] == replay["version"]
    if a.scenario == "write-stall":
        time.sleep(10)
    c.request(job_id=job["job_id"], op="done")
    message = recv_message(s)
    assert message["type"] == "stop"
s.close()
'''


class FramingV6Tests(unittest.TestCase):
    def pair(self):
        left, right = socket.socketpair()
        left.settimeout(1)
        right.settimeout(1)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return left, right

    def raw(self, payload):
        sender, receiver = self.pair()
        sender.sendall(struct.pack("!I", len(payload)) + payload)
        return recv_message(receiver)

    def test_real_socketpair_roundtrip_and_fragmented_header(self):
        sender, receiver = self.pair()
        value = {"version": VERSION, "nested": {"text": "épreuve"}}
        payload = json.dumps(value).encode()
        header = struct.pack("!I", len(payload))
        for byte in header:
            sender.sendall(bytes([byte]))
        for chunk in (payload[:3], payload[3:]):
            sender.sendall(chunk)
        self.assertEqual(recv_message(receiver), value)

    def test_duplicate_nonfinite_nonobject_and_invalid_utf8_frames_refused(self):
        for payload in (b'{"version":1,"version":1}', b'{"x":{"x":1,"x":2}}',
                        b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
                        b'{"x":1e309}', b'{"x":-1e309}', b'{"nested":[1e309]}',
                        b'[]', b'null', b'{"x":"\xff"}', b'{incomplete'):
            with self.subTest(payload=payload):
                with self.assertRaises(ProtocolError):
                    self.raw(payload)

    def test_unpaired_unicode_surrogates_refused_but_valid_pairs_accepted(self):
        for payload in (br'{"x":"\ud800"}', br'{"x":"\udfff"}',
                        br'{"\ud800":"key"}', br'{"x":["\ud800"]}'):
            with self.subTest(payload=payload):
                with self.assertRaises(ProtocolError):
                    self.raw(payload)
        self.assertEqual(self.raw(br'{"x":"\ud83d\ude00"}'), {"x": "\U0001f600"})

    def test_zero_and_oversized_frame_headers_refused_without_body(self):
        for size in (0, MAX_FRAME + 1, 2**32 - 1):
            with self.subTest(size=size):
                sender, receiver = self.pair()
                sender.sendall(struct.pack("!I", size))
                with self.assertRaises(ProtocolError):
                    recv_message(receiver)

    def test_truncated_header_and_body_refused(self):
        for raw in (b'\x00\x00', struct.pack("!I", 8) + b'{"x"'):
            with self.subTest(raw=raw):
                sender, receiver = self.pair()
                sender.sendall(raw)
                sender.shutdown(socket.SHUT_WR)
                with self.assertRaises(EOFError):
                    recv_message(receiver)

    def test_response_sequence_and_schema_cannot_be_substituted(self):
        for change in ({"request_id": 2}, {"request_id": True}, {"ok": 1},
                       {"role": "owner"}, {"version": True}):
            with self.subTest(change=change):
                client_socket, server_socket = self.pair()
                response = {"version": VERSION, "request_id": 1, "ok": True, "result": {}}
                response.update(change)
                send_message(server_socket, response)
                with self.assertRaises(ProtocolError):
                    Client(client_socket).request(job_id="test", op="read")

    def test_encoder_refuses_nonfinite_and_oversized_messages(self):
        sender, _ = self.pair()
        for value in ({"x": float("nan")}, {"x": "a" * MAX_FRAME}):
            with self.assertRaises(ProtocolError):
                send_message(sender, value)

    def test_absolute_frame_deadline_stops_slowloris_and_restores_socket_timeout(self):
        sender, receiver = self.pair()
        receiver.settimeout(.75)
        stop = threading.Event()
        payload = b'{"x":1}'

        def drip():
            try:
                sender.sendall(struct.pack("!I", len(payload)))
                for byte in payload:
                    sender.sendall(bytes([byte]))
                    if stop.wait(.08):
                        return
            except OSError:
                pass

        thread = threading.Thread(target=drip)
        thread.start()
        started = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                recv_message(receiver, deadline=started + .1)
            self.assertLess(time.monotonic() - started, .5)
            self.assertEqual(receiver.gettimeout(), .75)
        finally:
            stop.set()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_absolute_send_deadline_bounds_a_peer_that_does_not_read(self):
        sender, _ = self.pair()
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        sender.settimeout(.75)
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            send_message(sender, {"content": "a" * 1_000_000}, deadline=started + .1)
        self.assertLess(time.monotonic() - started, .5)
        self.assertEqual(sender.gettimeout(), .75)


class GateV6Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "controller.sqlite"
        self.now = [1000.0]
        self.rt = Runtime(self.path, clock=lambda: self.now[0])
        self.addCleanup(self.rt.close)
        self.rt.put_resource("input", "hello")
        self.rt.put_resource("output", "")
        self.rt.put_resource("controller-private", "DO-NOT-EXPOSE")
        self.rt.add_task("A", "input", "output", "uppercase", digest("HELLO"))
        self.claim = self.rt.claim("worker")
        self.gate = WorkerGate(self.rt, self.claim)

    def message(self, *, op="write", sequence=1, **changes):
        c = self.claim
        value = {"version": VERSION, "request_id": sequence, "job_id": c["run_id"], "op": op}
        if op in {"read", "write"}:
            value.update(resource="output" if op == "write" else "input",
                         expected_version=c["output_version"] if op == "write" else c["task"]["input_version"],
                         key=c["run_id"] + "." + op, fence=c["fence"],
                         args={"content": "HELLO"} if op == "write" else {})
        value.update(changes)
        return value

    def wire(self, gate, message):
        sender, receiver = socket.socketpair()
        try:
            send_message(sender, message)
            return gate.handle(recv_message(receiver))
        finally:
            sender.close()
            receiver.close()

    def assert_no_success(self):
        self.assertEqual(self.rt.resource("output")["version"], 1)
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 0)
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)

    def test_worker_owner_verification_grant_and_role_spoof_refused(self):
        for op in ("verify", "put_resource", "revoke", "grant", "claim", "proof_is_accepted_for_gate"):
            with self.subTest(op=op):
                gate = WorkerGate(self.rt, self.claim)
                with self.assertRaises((GuardError, ProtocolError)):
                    self.wire(gate, self.message(op=op))
                self.assert_no_success()
        with self.assertRaises(ProtocolError):
            self.wire(self.gate, self.message(role="verifier"))
        self.assert_no_success()

    def test_worker_malformed_op_types_refused_as_protocol_errors(self):
        for invalid in ([], {}, None, 1, True):
            with self.subTest(op=invalid):
                message = {"version": VERSION, "request_id": 1,
                           "job_id": self.claim["run_id"], "op": invalid}
                with self.assertRaises(ProtocolError):
                    self.wire(WorkerGate(self.rt, self.claim), message)
        self.assert_no_success()

    def test_wrong_job_fence_scope_key_and_version_have_no_effect(self):
        for change in ({"job_id": "different-run"}, {"fence": self.claim["fence"] + 1},
                       {"resource": "controller-private"}, {"key": "arbitrary-key"},
                       {"expected_version": 1000}, {"expected_version": True},
                       {"args": {"content": "HELLO", "owner": True}}):
            with self.subTest(change=change):
                with self.assertRaises((GuardError, ProtocolError)):
                    self.wire(WorkerGate(self.rt, self.claim), self.message(**change))
                self.assert_no_success()

    def test_revoked_capability_refuses_read_and_write(self):
        self.rt.revoke(self.claim["run_id"])
        for op in ("read", "write"):
            with self.assertRaises(GuardError):
                self.wire(WorkerGate(self.rt, self.claim), self.message(op=op))
        self.assert_no_success()

    def test_worker_request_id_type_and_boundaries_refused(self):
        for invalid in (0, -1, True, 1.0, "1", 2**31):
            with self.subTest(request_id=invalid):
                with self.assertRaises(ProtocolError):
                    self.wire(WorkerGate(self.rt, self.claim), self.message(sequence=invalid))
        self.assert_no_success()

    def test_worker_invalid_unicode_content_is_guarded_without_effect(self):
        with self.assertRaises(GuardError):
            self.gate.handle(self.message(args={"content": chr(0xd800)}))
        self.assert_no_success()

    def test_exact_request_replay_refused_but_new_request_same_effect_replays(self):
        first = self.wire(self.gate, self.message())
        with self.assertRaises(ProtocolError):
            self.wire(self.gate, self.message())
        replay = self.wire(self.gate, self.message(sequence=2))
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["version"], replay["version"])
        self.assertEqual(self.rt.resource("output")["version"], 2)
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 1)
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)

    def verification(self, gate):
        snapshot = gate.snapshot()
        return {"version": VERSION, "type": "verification", "run_id": snapshot["run_id"],
                "nonce": snapshot["nonce"], "input_version": snapshot["input_version"],
                "output_version": snapshot["output_version"], "observed_sha": digest(snapshot["content"])}

    def test_verifier_nonce_run_sha_versions_and_outcome_substitution_refused(self):
        self.wire(self.gate, self.message())
        gate = VerifierGate(self.rt, self.claim, "test-environment")
        original = self.verification(gate)
        for change in ({"nonce": "foreign-nonce"}, {"run_id": "foreign-run"},
                       {"observed_sha": "0" * 64}, {"input_version": 2},
                       {"output_version": 3}, {"output_version": True},
                       {"outcome": "PASS"}, {"role": "verifier"}):
            with self.subTest(change=change):
                message = {**original, **change}
                with self.assertRaises((GuardError, ProtocolError)):
                    gate.accept(message)
                self.assertEqual(self.rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)
                self.assertEqual(self.rt.task("A")["status"], "RESULT_READY")
        accepted = gate.accept(original)
        self.assertEqual(accepted["outcome"], "PASS")
        self.assertTrue(accepted["accepted_for_gate"])

    def test_correctly_hashed_wrong_output_is_fail_and_never_gate_pass(self):
        self.wire(self.gate, self.message(args={"content": "incorrect"}))
        gate = VerifierGate(self.rt, self.claim, "test-environment")
        result = gate.accept(self.verification(gate))
        self.assertEqual(result["outcome"], "FAIL")
        self.assertFalse(result["accepted_for_gate"])
        self.assertEqual(self.rt.task("A")["status"], "FAILED")

    def test_older_verifier_cannot_certify_a_newer_run_of_same_task(self):
        self.wire(self.gate, self.message())
        old_gate = VerifierGate(self.rt, self.claim, "test-environment")
        self.now[0] += 31
        self.rt.recover()
        self.rt.resume("A")
        newer = self.rt.claim("newer-worker")
        self.assertNotEqual(newer["run_id"], self.claim["run_id"])
        message = self.message()
        message.update(job_id=newer["run_id"], key=newer["run_id"] + ".write",
                       fence=newer["fence"], expected_version=newer["output_version"])
        self.wire(WorkerGate(self.rt, newer), message)
        with self.assertRaises(GuardError):
            old_gate.accept(self.verification(old_gate))
        self.assertEqual(self.rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)


class IsolatedBrokerV6Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cup_v6_ipc_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "controller.sqlite"
        self.canary = self.root / "host-canary"
        self.canary.write_text("PRIVATE-HOST-CANARY")
        self.package = self.root / "universal"
        self.package.mkdir()
        (self.package / "__init__.py").write_text("")
        source = Path(__file__).resolve().parents[1] / "universal"
        for name in ("isolation.py", "protocol.py", "worker.py"):
            shutil.copyfile(source / name, self.package / name)
        (self.package / "child.py").write_text(HOSTILE_CHILD)
        with Runtime(self.path) as rt:
            rt.put_resource("input", "hello")
            rt.put_resource("output", "")
            rt.put_resource("controller-private", "DO-NOT-EXPOSE")
            rt.add_task("A", "input", "output", "uppercase", digest("HELLO"))
        self.launched = []

    def fixture_launch(self, scenario):
        def launch(role):
            parent, child = socket.socketpair()
            parent.settimeout(1)
            try:
                command = build_command(self.package, child.fileno(), role,
                                        ["--scenario", scenario, "--host-db", str(self.path),
                                         "--host-canary", str(self.canary)])
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, close_fds=True,
                                           pass_fds=(child.fileno(),), start_new_session=True,
                                           env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            except BaseException:
                parent.close()
                child.close()
                raise
            child.close()
            channel = Channel(process, parent, role)
            self.launched.append(channel)
            return channel
        return launch

    def run_hostile(self, scenario, **budgets):
        with patch("universal.broker.launch", self.fixture_launch(scenario)):
            return broker.run_pool(self.path, workers=1, **budgets)

    def assert_stopped(self):
        for channel in self.launched:
            self.assertTrue(channel.stopped)
            self.assertIsNotNone(channel.process.poll())
        self.assertEqual(self.canary.read_text(), "PRIVATE-HOST-CANARY")

    def test_actual_child_cannot_read_db_canary_or_inherit_db_descriptor(self):
        result = self.run_hostile("correct")
        probe = result[0]["sandbox"]["limits"]["probe"]
        for name in ("db_read_blocked", "db_write_blocked", "canary_read_blocked"):
            self.assertTrue(probe[name], probe)
        self.assertTrue(any(link.startswith("socket:") for link in probe["fd_links"]))
        self.assertFalse(any(str(self.path) in link for link in probe["fd_links"]))
        self.assertEqual(result[0]["results"][0]["verification"]["outcome"], "PASS")
        self.assert_stopped()

    def test_actual_worker_owner_role_malformed_and_foreign_scope_refused(self):
        for scenario in ("owner", "grant", "verify", "role-spoof", "malformed-op", "wrong-resource", "unicode-content",
                         "duplicate-key", "nonfinite", "oversized", "truncated"):
            with self.subTest(scenario=scenario):
                # Each hostile case gets its own fixture DB/task/run.
                with Runtime(self.path) as rt:
                    if rt.task("A")["status"] == "BLOCKED":
                        rt.resume("A")
                result = self.run_hostile(scenario)
                self.assertTrue(any(row.get("decision") == "DENY" for row in result[0]["results"]))
                with Runtime(self.path) as rt:
                    self.assertEqual(rt.resource("output")["version"], 1)
                    self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 0)
                    self.assertEqual(rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)
                    self.assertTrue(rt.check_journal())
                self.assert_stopped()

    def test_actual_worker_write_replay_new_request_id_has_one_effect(self):
        result = self.run_hostile("replay")
        self.assertEqual(result[0]["results"][0]["verification"]["outcome"], "PASS")
        with Runtime(self.path) as rt:
            self.assertEqual(rt.resource("output")["version"], 2)
            self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 1)
            self.assertEqual(rt.db.execute("SELECT count(*) FROM events WHERE action='replay'").fetchone()[0], 1)
            self.assertTrue(rt.check_journal())
        self.assert_stopped()

    def check_independent_worker_survives(self, scenario):
        with Runtime(self.path) as rt:
            for index in range(1, 5):
                output = "output-" + str(index)
                rt.put_resource(output, "")
                rt.add_task("A" + str(index), "input", output, "uppercase", digest("HELLO"))
        workers = [0]
        hostile = self.fixture_launch(scenario)
        healthy = self.fixture_launch("correct")

        def split_launch(role):
            if role == "worker":
                workers[0] += 1
                if workers[0] == 1:
                    return hostile(role)
            return healthy(role)

        with patch("universal.broker.launch", split_launch):
            result = broker.run_pool(self.path, workers=2)
        self.assertTrue(any(row.get("decision") == "DENY" for report in result for row in report["results"]))
        with Runtime(self.path) as rt:
            self.assertEqual(rt.db.execute("SELECT count(*) FROM tasks WHERE status='VERIFIED'").fetchone()[0], 4)
            self.assertEqual(rt.db.execute("SELECT count(*) FROM tasks WHERE status='BLOCKED'").fetchone()[0], 1)
            self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 4)
            self.assertTrue(rt.check_journal())
        self.assert_stopped()

    def test_one_hostile_channel_does_not_stop_an_independent_worker(self):
        self.check_independent_worker_survives("owner")

    def test_unpaired_unicode_attack_does_not_stop_an_independent_worker(self):
        self.check_independent_worker_survives("unicode-content")

    def test_crash_before_effect_marks_run_suspect_without_mutation(self):
        result = self.run_hostile("crash-before")
        self.assertTrue(any(row.get("decision") == "DENY" for row in result[0]["results"]))
        with Runtime(self.path) as rt:
            self.assertEqual(rt.resource("output")["version"], 1)
            self.assertEqual(rt.task("A")["status"], "BLOCKED")
            self.assertEqual(rt.db.execute("SELECT state FROM runs").fetchone()[0], "SUSPECT")
            self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 0)
        self.assert_stopped()

    def test_crash_after_commit_before_ack_verifies_once_without_second_write(self):
        result = self.run_hostile("crash-after")
        with Runtime(self.path) as rt:
            self.assertEqual(rt.resource("output")["version"], 2)
            self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 1)
            self.assertEqual(rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 1)
            self.assertEqual(rt.task("A")["status"], "VERIFIED")
            self.assertTrue(rt.check_journal())
        self.assertTrue(any(row.get("verification", {}).get("accepted_for_gate") for row in result[0]["results"]))
        self.assert_stopped()

    def test_forged_verifier_sha_is_refused_without_terminal_evidence(self):
        result = self.run_hostile("verifier-forgery")
        self.assertTrue(any(row.get("decision") == "DENY" for row in result[0]["results"]))
        with Runtime(self.path) as rt:
            self.assertNotEqual(rt.task("A")["status"], "VERIFIED")
            self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 1)
            self.assertEqual(rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)
        self.assert_stopped()

    def test_actual_verifier_recomputes_wrong_output_as_fail(self):
        result = self.run_hostile("wrong-output")
        verification = result[0]["results"][0]["verification"]
        self.assertEqual(verification["outcome"], "FAIL")
        self.assertFalse(verification["accepted_for_gate"])
        with Runtime(self.path) as rt:
            self.assertEqual(rt.task("A")["status"], "FAILED")
        self.assert_stopped()

    def test_wall_timeout_stops_real_child_and_leaves_no_fake_success(self):
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            self.run_hostile("stall", timeout=0.3)
        self.assertLess(time.monotonic() - started, 4)
        with Runtime(self.path) as rt:
            self.assertEqual(rt.task("A")["status"], "BLOCKED")
            self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 0)
            self.assertEqual(rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)
        self.assert_stopped()

    def test_timeout_after_ack_preserves_committed_effect_without_fake_proof(self):
        with self.assertRaises(TimeoutError):
            self.run_hostile("write-stall", timeout=0.3)
        with Runtime(self.path) as rt:
            self.assertEqual(rt.resource("output")["version"], 2)
            self.assertNotEqual(rt.task("A")["status"], "VERIFIED")
            self.assertEqual(rt.db.execute("SELECT count(*) FROM effects WHERE state='COMMITTED'").fetchone()[0], 1)
            self.assertEqual(rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)
            rt.recover()
            self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 1)
            self.assertTrue(rt.check_journal())
        self.assert_stopped()

    def test_slowloris_child_cannot_hold_broker_past_global_deadline(self):
        started = time.monotonic()
        try:
            result = self.run_hostile("slow-frame", timeout=.3)
        except TimeoutError:
            pass
        else:
            self.assertTrue(any(row.get("decision") == "DENY" for row in result[0]["results"]))
        # Before the deadline fix, one byte every .15s held a 1s socket timeout
        # open for over two seconds. Cleanup may consume at most its own bound.
        self.assertLess(time.monotonic() - started, 1.5)
        with Runtime(self.path) as rt:
            self.assertNotEqual(rt.task("A")["status"], "VERIFIED")
            self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 0)
            self.assertEqual(rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 0)
        self.assert_stopped()

    def test_production_children_get_no_db_path_and_distinct_host_pids(self):
        original_launch = broker.launch
        original_popen = subprocess.Popen
        original_send = broker.send_message
        commands = []
        processes = []
        messages = []

        def record_popen(command, **kwargs):
            commands.append((command, copy.copy(kwargs)))
            return original_popen(command, **kwargs)

        def record_launch(role):
            channel = original_launch(role)
            processes.append((role, channel.process.pid))
            return channel

        def record_send(channel, message, **kwargs):
            messages.append(copy.deepcopy(message))
            return original_send(channel, message, **kwargs)

        with patch("universal.broker.subprocess.Popen", record_popen), patch("universal.broker.launch", record_launch), patch("universal.broker.send_message", record_send):
            result = broker.run_pool(self.path, workers=1)
        self.assertEqual([role for role, _ in processes], ["worker", "verifier"])
        self.assertEqual(len({pid for _, pid in processes} | {os.getpid()}), 3)
        self.assertEqual(result[0]["results"][0]["verifier_process"], processes[1][1])
        for command, kwargs in commands:
            self.assertNotIn(str(self.path), command)
            self.assertNotIn("--db", command)
            self.assertEqual(len(kwargs["pass_fds"]), 1)
            self.assertTrue(kwargs["close_fds"])
            self.assertNotIn(str(self.path), json.dumps(kwargs["env"]))
        self.assertNotIn("token", json.dumps(messages))
        self.assertNotIn(str(self.path), json.dumps(messages))
        self.assertNotIn("DO-NOT-EXPOSE", json.dumps(messages))

    def test_concurrent_real_brokers_claim_each_task_once(self):
        with Runtime(self.path) as rt:
            for index in range(1, 8):
                output = "output-" + str(index)
                rt.put_resource(output, "")
                rt.add_task("A" + str(index), "input", output, "uppercase", digest("HELLO"))
        command = [sys.executable, "-c",
                   "import sys; from universal.broker import run_pool; run_pool(sys.argv[1],workers=2)",
                   str(self.path)]
        processes = [subprocess.Popen(command, cwd=Path(__file__).resolve().parents[1],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        try:
            for process in processes:
                stdout, stderr = process.communicate(timeout=20)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
            with Runtime(self.path) as rt:
                self.assertEqual(rt.db.execute("SELECT count(*) FROM tasks WHERE status='VERIFIED'").fetchone()[0], 8)
                self.assertEqual(rt.db.execute("SELECT count(*) FROM runs").fetchone()[0], 8)
                self.assertEqual(rt.db.execute("SELECT count(*) FROM effects").fetchone()[0], 8)
                self.assertEqual(rt.db.execute("SELECT count(*) FROM evidence").fetchone()[0], 8)
                self.assertTrue(rt.check_journal())
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
