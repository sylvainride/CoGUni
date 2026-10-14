"""Trusted bootstrap, then irreversible restrictions before job input."""
import argparse
import hashlib
import os
import resource
import socket
import sys

sys.path.insert(0, "/app")
from universal.isolation import inside_child_limits
from universal.protocol import VERSION, recv_message, require, send_message
from universal.worker import worker_loop


def verifier_loop(channel):
    message = recv_message(channel)
    require(message, {"version", "type", "snapshot"})
    if message["type"] != "verify":
        raise ValueError("invalid verifier contract")
    snapshot = message["snapshot"]
    if not isinstance(snapshot, dict) or set(snapshot) != {"run_id", "nonce", "input_version", "output_version", "content"}:
        raise ValueError("invalid verifier snapshot")
    observed = hashlib.sha256(snapshot["content"].encode("utf-8")).hexdigest()
    send_message(channel, {"version": VERSION, "type": "verification", "run_id": snapshot["run_id"], "nonce": snapshot["nonce"], "input_version": snapshot["input_version"], "output_version": snapshot["output_version"], "observed_sha": observed})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fd", type=int, required=True)
    parser.add_argument("--role", choices=("worker", "verifier"), required=True)
    arguments = parser.parse_args()
    channel = socket.socket(fileno=arguments.fd)
    channel.settimeout(20)
    inside_child_limits()
    limits = {"address_space": resource.getrlimit(resource.RLIMIT_AS)[0], "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0], "file_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0], "processes": resource.getrlimit(resource.RLIMIT_NPROC)[0]}
    send_message(channel, {"version": VERSION, "type": "ready", "pid": os.getpid(), "uid": os.geteuid(), "limits": limits})
    try:
        if arguments.role == "worker":
            worker_loop(channel)
        else:
            verifier_loop(channel)
    finally:
        channel.close()


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        sys.stderr.write(type(error).__name__ + "\n")
        sys.exit(2)
