#!/usr/bin/env python3
"""Bounded local provisioning profile; never executes workers or external tools.

Compare immutable v5 and current code with the same fixtures using --code paths.
Each repetition is a fresh Python subprocess and disposable SQLite database, with
a 30-second ceiling. Individual and batch methods are separate workloads; their
speedups are never presented as interchangeable. Source bytes are not modified.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc


def code_hashes(code):
    return {name: hashlib.sha256((code / "universal" / name).read_bytes()).hexdigest()
            for name in ("core.py", "dag.py")}


def sample(code, mode, size):
    sys.path.insert(0, str(code))
    from universal.core import Runtime, digest
    contracts = [{"id": "T" + str(i), "source": "source", "output": "output", "action": "copy",
                  "expected_sha": digest("hello"),
                  "dependencies": ["T" + str(j) for j in range(max(0, i - 3), i)]}
                 for i in range(size)]
    with tempfile.TemporaryDirectory(prefix="cup_dag_profile_") as temp:
        path = Path(temp) / "profile.sqlite"
        runtime = Runtime(path)
        try:
            runtime.put_resource("source", "hello")
            runtime.put_resource("output", "")
            queries = [0]

            def count_statement(_):
                queries[0] += 1

            runtime.db.set_trace_callback(count_statement)
            tracemalloc.start()
            start_wall, start_cpu = time.perf_counter(), time.process_time()
            if mode == "batch":
                runtime.add_tasks_batch(contracts)
            else:
                for contract in contracts:
                    runtime.add_task(contract["id"], contract["source"], contract["output"],
                                     contract["action"], contract["expected_sha"], contract["dependencies"])
            wall, cpu = time.perf_counter() - start_wall, time.process_time() - start_cpu
            _, python_peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            statement_count = queries[0]
            runtime.db.set_trace_callback(None)
            tasks = runtime.db.execute("SELECT count(*) FROM tasks").fetchone()[0]
            edges = runtime.db.execute("SELECT count(*) FROM deps").fetchone()[0]
            expected_edges = sum(min(i, 3) for i in range(size))
            integrity = runtime.db.execute("PRAGMA integrity_check").fetchone()[0]
            fk_errors = list(runtime.db.execute("PRAGMA foreign_key_check"))
            journal_ok = runtime.check_journal()
            source_version = runtime.resource("source")["version"]
            output_version = runtime.resource("output")["version"]
            if (tasks, edges) != (size, expected_edges) or integrity != "ok" or fk_errors or not journal_ok or (source_version, output_version) != (1, 1):
                raise RuntimeError("profile-state-validation-failed")
            result = {"status": "PASS", "mode": mode, "tasks": tasks, "edges": edges,
                      "wall_seconds": wall, "cpu_seconds": cpu, "sql_statements": statement_count,
                      "python_tracemalloc_peak_bytes": python_peak,
                      "sqlite_page_count": runtime.db.execute("PRAGMA page_count").fetchone()[0],
                      "sqlite_page_size": runtime.db.execute("PRAGMA page_size").fetchone()[0],
                      "journal_ok": journal_ok, "integrity_check": integrity, "foreign_key_errors": len(fk_errors),
                      "source_version": source_version, "output_version": output_version,
                      "verification_scope": "provisioning-only; no workers, LLM or external effects"}
            try:
                import resource
                result["process_peak_rss_native_units"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                result["process_peak_rss_unit"] = "KiB on Linux; bytes on macOS"
            except ImportError:
                result["process_peak_rss_native_units"] = None
            return result
        finally:
            runtime.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", type=Path, required=True)
    parser.add_argument("--label", default="runtime")
    parser.add_argument("--mode", choices=("individual", "batch"), default="individual")
    parser.add_argument("--sizes", default="100,300,600")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sample", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    code = args.code.resolve()
    if args.sample is not None:
        print(json.dumps(sample(code, args.mode, args.sample), sort_keys=True))
        return
    sizes = [int(value) for value in args.sizes.split(",")]
    if not sizes or any(value <= 0 for value in sizes) or not 1 <= args.repeat <= 10:
        parser.error("positive sizes and 1..10 repetitions required")
    hashes_before = code_hashes(code)
    results = []
    for size in sizes:
        for repetition in range(args.repeat):
            command = [sys.executable, "-B", str(Path(__file__).resolve()), "--code", str(code),
                       "--mode", args.mode, "--sample", str(size)]
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            try:
                completed = subprocess.run(command, capture_output=True, text=True,
                                           timeout=30, env=environment)
                if completed.returncode:
                    results.append({"status": "FAIL", "tasks": size, "repetition": repetition,
                                    "returncode": completed.returncode, "stderr": completed.stderr})
                else:
                    result = json.loads(completed.stdout)
                    result["repetition"] = repetition
                    results.append(result)
            except subprocess.TimeoutExpired:
                results.append({"status": "TIMEOUT", "tasks": size, "repetition": repetition,
                                "timeout_seconds": 30})
    grouped = defaultdict(list)
    for result in results:
        if result["status"] == "PASS":
            grouped[result["tasks"]].append(result)
    summaries = [{"tasks": size, "pass_samples": len(values),
                  "median_wall_seconds": statistics.median(value["wall_seconds"] for value in values),
                  "median_cpu_seconds": statistics.median(value["cpu_seconds"] for value in values),
                  "median_python_peak_bytes": statistics.median(value["python_tracemalloc_peak_bytes"] for value in values)}
                 for size, values in sorted(grouped.items())]
    result = {"label": args.label, "mode": args.mode, "created_utc": datetime.now(timezone.utc).isoformat(),
              "environment": {"python": sys.version, "sqlite": sqlite3.sqlite_version,
                              "platform": platform.platform()},
              "fixture": "shared immutable source/output; each node depends on previous up to 3 nodes",
              "measurement": "tracemalloc + SQL trace enabled identically; fixture setup excluded",
              "subprocess_timeout_seconds": 30, "code_hashes_before": hashes_before,
              "code_hashes_after": code_hashes(code), "samples": results, "summary": summaries,
              "limitations": ["single local host and filesystem", "provisioning throughput only",
                              "no contention, scheduler, IPC or model-intelligence benchmark",
                              "batch is a different workload from individual transactions"]}
    result["source_unchanged"] = result["code_hashes_before"] == result["code_hashes_after"]
    data = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(data, encoding="utf-8")
    else:
        print(data, end="")
    if not result["source_unchanged"] or any(item["status"] != "PASS" for item in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
