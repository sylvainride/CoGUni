import argparse
import json
import platform
from pathlib import Path
import sys

from .core import GuardError, Runtime, Intent
from .worker import run_pool
from .broker import environment_identity
from .isolation import IsolationUnavailable


def main():
    parser = argparse.ArgumentParser(description="Local control and bounded candidate verification; no LLM, shell or network tools")
    parser.add_argument("--db", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("status")
    commands.add_parser("recover")
    put = commands.add_parser("put")
    put.add_argument("resource")
    put.add_argument("--text", required=True)
    put.add_argument("--expected-version", type=int)
    task = commands.add_parser("task")
    task.add_argument("id")
    task.add_argument("--source", required=True)
    task.add_argument("--output", required=True)
    task.add_argument("--action", choices=sorted(Runtime.ACTIONS | {"candidate"}), required=True)
    task.add_argument("--expected-sha")
    task.add_argument("--validation-mode", choices=("DETERMINISTIC_EXACT_SHA","GENERATIVE_POLICY_VALIDATED"), default="DETERMINISTIC_EXACT_SHA")
    task.add_argument("--policy-id")
    task.add_argument("--after", action="append", default=[])
    task.add_argument("--input-mode", choices=("PINNED_VERSION", "VERIFIED_UPSTREAM_OUTPUT", "VERIFIED_UPSTREAM_POLICY_OUTPUT"), default="PINNED_VERSION")
    task.add_argument("--producer")
    task.add_argument("--source-expected-sha")
    task.add_argument("--source-policy-id")
    owner_source=commands.add_parser("source-snapshot")
    owner_source.add_argument("id");owner_source.add_argument("resource")
    owner_source.add_argument("--classification",choices=("owner_contract","untrusted"),default="untrusted")
    policy=commands.add_parser("policy")
    policy.add_argument("id");policy.add_argument("--file",required=True)
    candidate=commands.add_parser("candidate")
    candidate.add_argument("task");candidate.add_argument("--file",required=True)
    verify_candidate=commands.add_parser("verify-candidate")
    verify_candidate.add_argument("task");verify_candidate.add_argument("--run",required=True)
    run = commands.add_parser("run")
    run.add_argument("--workers", type=int, default=2)
    run.add_argument("--max-jobs", type=int, default=100)
    resume = commands.add_parser("resume")
    resume.add_argument("task")
    backup = commands.add_parser("backup")
    backup.add_argument("target")
    export = commands.add_parser("export")
    export.add_argument("target")
    args = parser.parse_args()
    runtime = Runtime(args.db)
    try:
        if args.command == "init":
            result = {"schema": runtime.db.execute("PRAGMA user_version").fetchone()[0], "python": platform.python_version(), "network_tools": False, "llm": None}
        elif args.command == "put":
            result = {"version": runtime.put_resource(args.resource, args.text, args.expected_version)}
        elif args.command == "task":
            runtime.add_task(args.id, args.source, args.output, args.action, args.expected_sha, args.after, input_mode=args.input_mode, producer=args.producer, source_expected_sha=args.source_expected_sha,validation_mode=args.validation_mode,policy_id=args.policy_id,source_policy_id=args.source_policy_id)
            result = runtime.task(args.id)
        elif args.command == "source-snapshot":
            runtime.source_snapshot(args.id,args.resource,args.classification)
            result={"source":args.id,"current":runtime.source_current(args.id),"classification":args.classification}
        elif args.command == "policy":
            from .generative import GenerativeValidator,strict_json
            p=Path(args.file)
            if p.stat().st_size>65_536:raise GuardError("policy file too large","BLOCK")
            result={"policy_id":args.id,"sha":GenerativeValidator(runtime).register_policy(args.id,strict_json(p.read_text()))}
        elif args.command == "candidate":
            from .generative import candidate_files
            p=Path(args.file)
            if p.stat().st_size>Runtime.MAX_CONTENT:raise GuardError("candidate file too large","BLOCK")
            content=p.read_text();candidate_files(content)
            claim=runtime.claim('candidate-owner',ttl=60,environment=environment_identity(),supported_actions=['candidate'],task_id=args.task)
            if not claim:raise GuardError("candidate task not claimable","BLOCK")
            intent=Intent(claim['run_id'],'artifact.write',claim['task']['output'],claim['output_version'],claim['run_id']+'.write',claim['fence'],{'content':content})
            try:
                receipt=runtime.execute(intent,claim['token'])
            except BaseException:
                runtime.abandon_run(claim['run_id'])
                raise
            result={"run_id":claim['run_id'],"receipt":receipt,"verification":"NOT_RUN"}
        elif args.command == "verify-candidate":
            from .generative import GenerativeValidator
            result=GenerativeValidator(runtime).verify(args.task,environment_identity(),expected_run_id=args.run)
            if not result['accepted_for_gate']:
                print(json.dumps(result,ensure_ascii=False,indent=2));return 2
        elif args.command == "run":
            runtime.close()
            runtime = None
            result = run_pool(args.db, args.workers, args.max_jobs)
            if any("error_type" in worker or any("decision" in job or job.get("verification", {}).get("outcome") == "FAIL" for job in worker.get("results", [])) for worker in result):
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 2
        elif args.command == "recover":
            result = {"suspect_runs": runtime.recover()}
        elif args.command == "resume":
            runtime.resume(args.task, environment=environment_identity())
            result = runtime.task(args.task)
        elif args.command == "backup":
            result = {"sha256": runtime.backup(args.target)}
        elif args.command == "export":
            target = Path(args.target)
            with target.open("x", encoding="utf-8") as stream:
                json.dump(runtime.snapshot(), stream, ensure_ascii=False, indent=2)
            result = {"exported": str(target), "chatgpt_sources_updated": False}
        else:
            result = runtime.snapshot()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    finally:
        if runtime is not None:
            runtime.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (GuardError, ValueError, OSError, TimeoutError, IsolationUnavailable) as error:
        print(json.dumps({"error_type": type(error).__name__, "reason": str(error)}, ensure_ascii=False), file=sys.stderr)
        sys.exit(2)
