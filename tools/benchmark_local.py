#!/usr/bin/env python3
"""Small reproducible SQLite worker-pool benchmark; no model or Codex comparison.

Each repetition uses a fresh controller process and database. Provisioning is
outside the measured interval. The measured interval includes pool startup,
execution, verification, and final correctness inspection.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import multiprocessing
from pathlib import Path
import platform
import queue
import statistics
import sys
import tempfile
import time


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RUNTIME_ROOT))
from universal.core import Runtime
from universal.worker import run_pool
from universal.broker import environment_identity

try:
    import resource
except ImportError:
    resource = None


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def source_version():
    files = {str(path.relative_to(RUNTIME_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted((RUNTIME_ROOT / "universal").rglob("*.py"))}
    return {"package_sha256": sha(canonical(files)), "files": files}


def scenarios():
    result = []
    for index in range(20):
        action = ("copy", "uppercase", "sha256")[index % 3]
        content = "fixture {:02d}\n".format(index) + ("alpha beta gamma 0123456789\n" * 160)
        expected = content if action == "copy" else content.upper() if action == "uppercase" else sha(content)
        result.append({"task": "task-{:02d}".format(index), "input": "input-{:02d}".format(index),
                       "output": "output-{:02d}".format(index), "action": action,
                       "content": content, "expected_sha256": sha(expected)})
    return result


def usage():
    if resource is None:
        return {"available": False, "reason": "Python resource module unavailable"}
    rss_unit = "KiB" if sys.platform.startswith("linux") else "bytes" if sys.platform == "darwin" else "platform-specific native unit"
    result = {"available": True, "ru_maxrss_unit": rss_unit}
    for label, who in (("parent", resource.RUSAGE_SELF), ("children", resource.RUSAGE_CHILDREN)):
        sample = resource.getrusage(who)
        result[label] = {"cpu_user_seconds": sample.ru_utime, "cpu_system_seconds": sample.ru_stime,
                         "ru_maxrss": sample.ru_maxrss}
    return result


def usage_measurement(before, after):
    result = {"before": before, "after": after,
              "cpu_scope": "Delta within measured interval. Parent is this controller; children are reaped bubblewrap wrappers. Isolated grandchildren are not fully accounted for: this is a partial CPU measurement.",
              "rss_scope": "Process-lifetime high-water marks, including untimed imports/provisioning. Child value describes reaped wrappers, not all isolated Python grandchildren. Neither value is aggregate pool memory."}
    if before["available"] and after["available"]:
        result["cpu_delta_seconds"] = {}
        for label in ("parent", "children"):
            result["cpu_delta_seconds"][label] = {
                name: after[label][name] - before[label][name]
                for name in ("cpu_user_seconds", "cpu_system_seconds")}
        result["cpu_delta_seconds"]["observed_partial_total"] = sum(
            value for sample in result["cpu_delta_seconds"].values() for value in sample.values())
    return result


def trial_entry(workers, repetition, result_queue):
    try:
        fixture = scenarios()
        with tempfile.TemporaryDirectory(prefix="universal-local-benchmark-") as directory:
            database = Path(directory) / "runtime.db"
            runtime = Runtime(database)
            try:
                trusted_environment = environment_identity()
                for task in fixture:
                    runtime.put_resource(task["input"], task["content"])
                    runtime.put_resource(task["output"], "")
                    runtime.add_task(task["task"], task["input"], task["output"], task["action"], task["expected_sha256"])
            finally:
                runtime.close()
            # All source data, tasks, and initial SQLite state are ready here.
            before_usage = usage()
            started = time.perf_counter()
            pool_result = run_pool(database, workers=workers, max_jobs=20, timeout=15)
            runtime = Runtime(database)
            try:
                task_states = [dict(row) for row in runtime.db.execute("SELECT id,status FROM tasks ORDER BY id")]
                effect_count = runtime.db.execute("SELECT count(*) FROM effects WHERE state='COMMITTED'").fetchone()[0]
                total_effect_count = runtime.db.execute("SELECT count(*) FROM effects").fetchone()[0]
                proofs = [dict(row) for row in runtime.db.execute("SELECT id,task,outcome FROM evidence ORDER BY task")]
                journal_valid = runtime.check_journal()
                current_proof_count = sum(runtime.proof_is_accepted_for_gate(proof["id"], trusted_environment) for proof in proofs)
                outputs = []
                for task in fixture:
                    output = runtime.resource(task["output"])
                    assert output["sha"] == task["expected_sha256"], "output contract mismatch"
                    assert output["version"] == 2, "unexpected number of output mutations"
                    outputs.append({"id": output["id"], "version": output["version"], "sha256": output["sha"]})
                assert len(task_states) == 20 and all(task["status"] == "VERIFIED" for task in task_states)
                assert effect_count == total_effect_count == 20
                assert len(proofs) == current_proof_count == 20 and all(proof["outcome"] == "PASS" for proof in proofs)
                assert journal_valid, "event journal integrity failed"
                assert len(pool_result) == workers and not any("error_type" in item for item in pool_result)
                returned_jobs = sum(len(item["results"]) for item in pool_result)
                assert returned_jobs == 20
                assert all(job.get("verification", {}).get("outcome") == "PASS"
                           and job.get("verification", {}).get("accepted_for_gate") is True
                           for item in pool_result for job in item["results"])
                event_count = runtime.db.execute("SELECT count(*) FROM events").fetchone()[0]
                journal_tail = runtime.db.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()[0]
            finally:
                runtime.close()
            elapsed = time.perf_counter() - started
            after_usage = usage()
            assert elapsed < 30, "per-repetition elapsed budget exceeded"
            result_queue.put({"status": "PASS", "workers": workers, "repetition": repetition,
                              "elapsed_seconds": elapsed, "resources": usage_measurement(before_usage, after_usage),
                              "checks": {"verified_tasks": 20, "committed_effects": effect_count,
                                         "accepted_pass_proofs": current_proof_count, "event_chain_valid": journal_valid,
                                         "returned_jobs": returned_jobs, "event_count": event_count,
                                         "journal_tail_sha256": journal_tail},
                              "worker_job_distribution": {item["worker"]: len(item["results"]) for item in pool_result},
                              "task_states": task_states, "outputs": outputs, "pool_result": pool_result})
    except BaseException as error:
        result_queue.put({"status": "FAIL", "workers": workers, "repetition": repetition,
                          "error": {"type": type(error).__name__, "message": str(error)}})


def run_trial(workers, repetition):
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    controller = context.Process(target=trial_entry, args=(workers, repetition, result_queue))
    controller.start()
    try:
        try:
            result = result_queue.get(timeout=25)
        except queue.Empty:
            return {"status": "FAIL", "workers": workers, "repetition": repetition,
                    "error": {"type": "Timeout", "message": "Isolated repetition exceeded 25-second outer deadline"}}
        controller.join(timeout=1)
        if controller.is_alive() or controller.exitcode != 0:
            return {"status": "FAIL", "workers": workers, "repetition": repetition,
                    "error": {"type": "ControllerExit", "message": "Controller did not terminate cleanly"}, "partial_result": result}
        return result
    finally:
        if controller.is_alive():
            controller.terminate()
            controller.join(timeout=1)
            if controller.is_alive():
                controller.kill()
                controller.join(timeout=1)
        result_queue.close()


def distribution(values):
    return {"samples": values, "n": len(values), "min": min(values), "median": statistics.median(values),
            "mean": statistics.mean(values), "max": max(values)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    version_before = source_version()
    fixture = scenarios()
    trials = []
    # Alternate order to reduce systematic warm-up bias, without claiming full control of host load.
    for repetition, order in enumerate(((1, 2), (2, 1), (1, 2)), start=1):
        for workers in order:
            trials.append(run_trial(workers, repetition))
    version_after = source_version()
    stable = version_before == version_after
    summary = {}
    for workers in (1, 2):
        selected = [trial for trial in trials if trial["workers"] == workers and trial["status"] == "PASS"]
        record = {"successful_repetitions": len(selected), "requested_repetitions": 3}
        if selected:
            record["elapsed_seconds"] = distribution([trial["elapsed_seconds"] for trial in selected])
            cpus = [trial["resources"]["cpu_delta_seconds"]["observed_partial_total"] for trial in selected
                    if "cpu_delta_seconds" in trial["resources"]]
            if cpus:
                record["partial_controller_plus_reaped_wrappers_cpu_seconds"] = distribution(cpus)
        summary[str(workers) + "_workers"] = record
    result = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if stable and len(trials) == 6 and all(trial["status"] == "PASS" for trial in trials) else "FAIL",
        "runtime_version": version_before, "runtime_sources_stable_during_run": stable,
        "runtime_version_after": version_after,
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scenarios_sha256": sha(canonical(fixture)),
        "fixture": {"tasks_per_repetition": 20, "repetitions_per_condition": 3,
                    "action_counts": {action: sum(task["action"] == action for task in fixture) for action in ("copy", "uppercase", "sha256")},
                    "input_bytes_per_repetition": sum(len(task["content"].encode("utf-8")) for task in fixture),
                    "same_inputs_and_contracts_in_all_repetitions": True},
        "environment": {"platform": platform.platform(), "python": platform.python_version(), "resource_module_available": resource is not None},
        "method": {"timed": "Pool process startup, all task reads/transforms/writes/verifications, and final correctness inspection.",
                   "untimed": "Isolated controller startup, fixture generation and initial SQLite resource/task provisioning.",
                   "budgets": {"pool_timeout_seconds": 15, "isolated_trial_outer_deadline_seconds": 25, "elapsed_assertion_seconds": 30},
                   "limitations": "Only six small synthetic local runs. Host load and filesystem cache are uncontrolled. Multiprocessing and SQLite overhead can dominate. No statistical generalization, model inference, Codex comparison, domain validation, or isolation claim."},
        "raw_trials": trials, "summary": summary,
    }
    if result["status"] == "PASS":
        result["summary"]["median_wall_ratio_1_worker_over_2_workers"] = (
            summary["1_workers"]["elapsed_seconds"]["median"] / summary["2_workers"]["elapsed_seconds"]["median"])
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "runtime_sources_stable": stable, "summary": summary}, ensure_ascii=False))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
