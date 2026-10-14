#!/usr/bin/env python3
"""Reproduce FAIL freshness and reject it through the actual positive gate."""
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from universal.core import Intent, Runtime, digest


def main():
    with tempfile.TemporaryDirectory(prefix="cup-v6-proof-repro-") as directory:
        with Runtime(Path(directory) / "proof.sqlite") as runtime:
            runtime.put_resource("input", "bonjour")
            runtime.put_resource("output", "")
            runtime.add_task("T", "input", "output", "copy", digest("other expected output"))
            claim = runtime.claim("fixture-worker")
            runtime.execute(Intent(claim["run_id"], "artifact.write", "output", 1,
                                   claim["run_id"] + ".write", claim["fence"], {"content": "bonjour"}), claim["token"])
            result = runtime.verify("T", "trusted-repro-environment", expected_run_id=claim["run_id"])
            observed = {"verification_outcome": result["outcome"], "task_status": runtime.task("T")["status"],
                        "proof_current_legacy_freshness": runtime.proof_current(result["evidence"]),
                        "proof_is_fresh": runtime.proof_is_fresh(result["evidence"]),
                        "proof_is_accepted_for_gate": runtime.proof_is_accepted_for_gate(result["evidence"], "trusted-repro-environment"),
                        "event_chain_valid": runtime.check_journal()}
            assert observed == {"verification_outcome": "FAIL", "task_status": "FAILED", "proof_current_legacy_freshness": True,
                                "proof_is_fresh": True, "proof_is_accepted_for_gate": False, "event_chain_valid": True}
            print(json.dumps(observed, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
