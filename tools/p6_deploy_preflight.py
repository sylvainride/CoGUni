"""P6 pure offline proposal preflight. Reads only its named JSON file.

No create, write, network, probing of the actual host, scheduler or install.
CLI exit 0 indicates only a well-formed proposal; not a deployment proof.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import sys

from universal.host_deploy_plan import decode_plan, validate_plan, ProposalRejected, MAX_PLAN_BYTES


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate an inert P6 proposal only")
    parser.add_argument("--plan", required=True)
    arguments = parser.parse_args(argv)
    try:
        path = Path(arguments.plan)
        # Only the operator's supplied file is read; this path is not a host
        # state attestation, and never becomes executable or a systemd unit.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ProposalRejected("invalid proposal")
            data = os.read(fd, MAX_PLAN_BYTES + 1)
            if len(data) > MAX_PLAN_BYTES:
                raise ProposalRejected("invalid proposal")
        finally:
            os.close(fd)
        verdict = decode_plan(data)
        print(json.dumps(validate_plan(verdict),
                         sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, UnicodeError, TypeError):
        print('{"status":"REJECTED","authority":"NONE","external_scheduler_installed":false}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
