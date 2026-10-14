#!/usr/bin/env python3
"""Derive a policy view from existing observations; never re-executes effects.

Original expected_v4 and status fields remain immutable in every output row.
This is a transparent re-evaluation under the explicit local replay decision,
not a new test execution or a permission mechanism for external operations.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def derive(matrix, decision_path, out):
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    if not (decision.get("origin") == "explicit_user_reply_in_this_conversation"
            and decision.get("scope") == "local_sqlite_committed_identical_intent_after_authorization_checks"
            and decision.get("selected_contract") == "REPLAY"
            and decision.get("external_effects_authorized") is False
            and decision.get("original_v4_oracle_must_remain_unchanged") is True):
        raise ValueError("reviewed local replay decision required")
    rows = [json.loads(line) for line in matrix.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != 320 or len({row["id"] for row in rows}) != 320:
        raise ValueError("unique 320-case source matrix required")
    before = sha(matrix)
    changed = []
    for row in rows:
        original = dict(row)
        row["expected_v6"] = row["expected_v4"]
        row["status_v6"] = row["status"]
        row["policy_view"] = "DERIVED_FROM_EXISTING_LOCAL_OBSERVATIONS_NOT_NEW_EXECUTION"
        if row["scenario"] == "DUPLICATE_EFFECT":
            observation = row.get("observation", {})
            checks = observation.get("checks", {})
            if not (row["expected_v4"] == "BLOCK" and row["status"] == "FAIL_CONTRACT"
                    and observation.get("decision") == "REPLAY" and observation.get("safety_invariant") == "PASS"
                    and checks and all(value is True for value in checks.values()) and "failure" not in row):
                raise ValueError("replay observation does not satisfy reviewed invariants")
            row["expected_v6"], row["status_v6"] = "REPLAY", "PASS"
            row["decision_id"] = decision["decision_id"]
            changed.append(row["id"])
        if any(row[key] != value for key, value in original.items()):
            raise AssertionError("historical observation changed")
    if len(changed) != 16 or before != sha(matrix):
        raise ValueError("unexpected replay scope or mutated original matrix")
    out.mkdir(parents=True, exist_ok=True)
    target = out / "V6_APPROVED_POLICY_VIEW.jsonl"
    with target.open("x", encoding="utf-8") as stream:
        stream.write("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows))
    summary = {"scope": "Derived interpretation only; no new execution. Original v4 fields retained.",
               "input_matrix_sha256": before, "decision_sha256": sha(decision_path),
               "harness_sha256": sha(Path(__file__)), "decision_id": decision["decision_id"],
               "rows": len(rows), "changed_case_ids": changed,
               "original_status_counts": dict(Counter(row["status"] for row in rows)),
               "approved_policy_status_counts": dict(Counter(row["status_v6"] for row in rows)),
               "output_matrix_sha256": sha(target)}
    with (out / "V6_APPROVED_POLICY_SUMMARY.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(derive(args.matrix, args.decision, args.out), ensure_ascii=False))


if __name__ == "__main__":
    main()
