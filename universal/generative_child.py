"""Trusted one-case bootstrap: no owner API, policy, test oracle or database.

The child reports only a computed JSON value. Its report has no verdict authority.
All Python and OS dependencies are imported before installing hard restrictions.
"""
import argparse
import json
import math
import os
import resource
import socket
import sys

sys.path.insert(0, "/app")
from universal.isolation import inside_child_limits
from universal.protocol import VERSION, recv_message, require, send_message


def _value(value, depth=0, budget=None):
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 16 or budget[0] > 8_192:
        raise ValueError("JSON limit")
    kind = type(value)
    if kind in (type(None), bool):
        return
    if kind is int:
        if value.bit_length() > 4_096:
            raise ValueError("integer limit")
        return
    if kind is float and math.isfinite(value):
        return
    if kind is str:
        if len(value.encode("utf-8")) > 16_384:
            raise ValueError("string limit")
        return
    if kind is list and len(value) <= 1_024:
        for item in value:
            _value(item, depth + 1, budget)
        return
    if kind is dict and len(value) <= 1_024 and all(type(key) is str for key in value):
        for key, item in value.items():
            _value(key, depth + 1, budget)
            _value(item, depth + 1, budget)
        return
    raise ValueError("plain finite JSON required")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fd", type=int, required=True)
    parser.add_argument("--role", choices=("probe",), required=True)
    arguments = parser.parse_args()
    channel = socket.socket(fileno=arguments.fd)
    channel.settimeout(10)
    inside_child_limits()
    request = recv_message(channel)
    require(request, {"version", "type", "nonce", "tree_sha", "context_digest", "case_index", "source", "function", "args"})
    if (request["type"] != "execute" or type(request["source"]) is not str
            or len(request["source"].encode("utf-8")) > 131_072
            or type(request["function"]) is not str or not request["function"].isidentifier()
            or type(request["args"]) is not list or len(request["args"]) > 64
            or type(request["case_index"]) is not int or not 0 <= request["case_index"] < 20
            or type(request["nonce"]) is not str or len(request["nonce"]) != 48
            or type(request["tree_sha"]) is not str or len(request["tree_sha"]) != 40
            or type(request["context_digest"]) is not str or len(request["context_digest"]) != 64):
        raise ValueError("invalid execution schema")
    _value(request["args"])
    binding = {"version": VERSION, "nonce": request["nonce"], "tree_sha": request["tree_sha"],
               "context_digest": request["context_digest"], "case_index": request["case_index"]}
    limits = {"address_space": resource.getrlimit(resource.RLIMIT_AS)[0],
              "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
              "file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
              "processes": resource.getrlimit(resource.RLIMIT_NPROC)[0],
              "files": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
              "core": resource.getrlimit(resource.RLIMIT_CORE)[0]}
    status = open("/proc/self/status").read()
    send_message(channel, {**binding, "type": "ready", "pid": os.getpid(), "uid": os.getuid(),
                           "gid": os.getgid(), "limits": limits,
                           "no_new_privs": "NoNewPrivs:\t1" in status, "seccomp": "Seccomp:\t2" in status,
                           "environment": dict(os.environ),
                           "namespaces": {name: os.readlink("/proc/self/ns/" + name) for name in ("pid", "net", "mnt", "user", "ipc", "uts")},
                           "visible_pids": sorted(int(name) for name in os.listdir("/proc") if name.isdecimal()),
                           "fds": sorted(int(name) for name in os.listdir("/proc/self/fd") if name.isdecimal())})
    try:
        namespace = {"__name__": "candidate", "__file__": "/candidate/candidate.py"}
        code = compile(request["source"], "/candidate/candidate.py", "exec", dont_inherit=True)
        exec(code, namespace, namespace)
        function = namespace[request["function"]]
        if not callable(function):
            raise TypeError("candidate entrypoint is not callable")
        value = function(*request["args"])
        _value(value)
        if len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")) > 16_384:
            raise ValueError("result limit")
        response = {**binding, "type": "result", "ok": True, "value": value, "error": ""}
    except BaseException as error:
        response = {**binding, "type": "result", "ok": False, "value": None, "error": type(error).__name__[:80]}
    send_message(channel, response)
    channel.close()


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        sys.stderr.write(type(error).__name__[:80] + "\n")
        sys.exit(2)
