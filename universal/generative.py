"""Owner policy verification of generated candidates, never a worker verdict.

Generated output SHA is measured after production. Immutable owner policies and
real confined checks replace the anticipated exact SHA only in the opt-in mode.
This bounded Python-function contract is not a general coding agent or release.
"""
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import shutil
import uuid

from .core import GuardError, canonical, digest

MODE = "GENERATIVE_POLICY_VALIDATED"
METHOD = "independent_generative_policy_v1"
CRITERIA = frozenset({"tests", "lint", "security", "licenses", "provenance", "environment"})


def strict_json(text):
    def pairs(items):
        result = {}
        for key,value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("nonfinite value")
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (TypeError, ValueError, RecursionError):
        raise GuardError("invalid candidate/policy JSON", "BLOCK") from None


def candidate_files(content):
    value = strict_json(content)
    if not isinstance(value,dict) or set(value) != {"files"} or not isinstance(value["files"],dict):
        raise GuardError("candidate requires exact files envelope", "BLOCK")
    from .policy_runner import git_tree_sha
    git_tree_sha(value["files"])  # Path/content limits and actual Git object tree.
    return value["files"]


def runner_identity():
    """Implementation helpers and actual environment, not inspect.getsource only."""
    from .broker import environment_identity
    git = shutil.which("git")
    if not git:
        raise GuardError("Git required for candidate provenance", "BLOCK")
    return digest(canonical({"runtime_environment":environment_identity(),
                             "git_binary_sha":hashlib.sha256(Path(git).read_bytes()).hexdigest()}))


def _signature(secret,body):
    return hmac.new(secret, canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()


def _task_contract(task):
    return {key:value for key,value in task.items() if key not in {"status", "revision"}}


def _active_policy(rt,policy_id):
    row = rt.db.execute("SELECT * FROM validation_policies WHERE id=?", (policy_id,)).fetchone()
    if not row or rt.db.execute("SELECT 1 FROM validation_policy_revocations WHERE id=?", (policy_id,)).fetchone():
        raise GuardError("owner policy absent or revoked", "BLOCK")
    if digest(row["body"]) != row["sha"]:
        raise GuardError("owner policy digest mismatch", "BLOCK")
    return row


def _source_origin(rt,task,run_id):
    source=rt.resource(task["input"])
    if task["input_mode"] == "PINNED_VERSION":
        row=rt.db.execute("SELECT * FROM sources WHERE resource=? AND classification='owner_contract' AND version=? AND sha=? ORDER BY id LIMIT 1", (source["id"],source["version"],source["sha"])).fetchone()
        if not row:
            raise GuardError("current owner source pin required", "BLOCK")
        return {"kind":"owner_pin","id":row["id"],"version":row["version"],"sha":row["sha"]}
    binding=rt.db.execute("SELECT * FROM run_input_bindings WHERE run=?", (run_id,)).fetchone()
    # The caller's core predicate checks full lineage iteratively. Re-entering
    # that predicate here would recurse through every generative ancestor.
    if not binding:
        raise GuardError("verified producer provenance required", "BLOCK")
    return {"kind":"verified_producer","binding":dict(binding)}


def _authorization(rt,task,run_id,*,expected_fence=None):
    """Check at the decision point after expensive I/O; never extends rights."""
    at=rt.clock()
    grants=rt.db.execute("SELECT resource,tool,expires,revoked FROM grants WHERE run=?", (run_id,)).fetchall()
    lease=rt.db.execute("SELECT * FROM leases WHERE resource=?", (task["output"],)).fetchone()
    if (len(grants)!=2 or {(g["resource"],g["tool"]) for g in grants} != {(task["input"],"artifact.read"),(task["output"],"artifact.write")}
            or any(g["revoked"] or g["expires"]<=at for g in grants)
            or not lease or lease["run"]!=run_id or lease["expires"]<=at
            or (expected_fence is not None and lease["fence"]!=expected_fence)):
        raise GuardError("candidate authorization expired, revoked or fenced", "BLOCK")
    return {"fence":lease["fence"],"expires":min(lease["expires"],*[g["expires"] for g in grants])},at


def generative_proof_accepted(rt,evidence,environment):
    """Transaction-owned acceptance used by core and producer-lineage checks."""
    from .broker import environment_identity
    from .policy_runner import git_tree_sha
    try:
        row = rt.db.execute("SELECT * FROM generative_evaluations WHERE evidence=?", (evidence["id"],)).fetchone()
        key = rt.db.execute("SELECT * FROM generative_keys ORDER BY epoch DESC LIMIT 1").fetchone()
        task = rt.task(evidence["task"])
        if not row or not key or task["validation_mode"] != MODE or row["policy"] != task["policy_id"]:
            return False
        policy = _active_policy(rt,row["policy"])
        body = strict_json(row["body"])
        context = body["context"]
        source,output = rt.resource(task["input"]),rt.resource(task["output"])
        files = candidate_files(output["content"])
        return bool(row["epoch"] == key["epoch"] == body["epoch"]
                    and hmac.compare_digest(row["signature"], _signature(key["secret"],body))
                    and body["schema"] == "owner-generative-evaluation-v1"
                    and body["evidence"] == evidence["id"] and body["outcome"] == "PASS"
                    and evidence["outcome"] == "PASS" and evidence["method"] == METHOD
                    and context["run_id"] == evidence["run"] and context["task_id"] == evidence["task"]
                    and context["environment"] == environment == evidence["environment"] == environment_identity()
                    and context["runner_sha"] == runner_identity()
                    and context["policy_id"] == task["policy_id"] and context["policy_sha"] == policy["sha"]
                    and context["task_contract_sha"] == digest(canonical(_task_contract(task)))
                    and task["revision"] == context["task_revision"] + 1
                    and context["source_id"] == source["id"] and context["source_version"] == source["version"] == evidence["input_version"]
                    and context["source_sha"] == source["sha"]
                    and context["source_origin"] == _source_origin(rt,task,evidence["run"])
                    and context["artifact_id"] == output["id"] and context["artifact_version"] == output["version"] == evidence["output_version"]
                    and context["artifact_sha"] == output["sha"] == evidence["output_sha"]
                    and context["tree_sha"] == body["checks"]["tree_sha"] == git_tree_sha(files)
                    and body["decision_at"] < context["authorization"]["expires"]
                    and body["checks"]["context_digest"] == digest(canonical(context))
                    and body["checks"]["policy_digest"] == policy["sha"]
                    and set(body["checks"]["criteria"]) == CRITERIA
                    and all(item["outcome"] == "PASS" for item in body["checks"]["criteria"].values()))
    except (GuardError, KeyError, TypeError, ValueError, OSError):
        return False


class GenerativeValidator:
    """Trusted owner facade, deliberately absent from worker IPC tool schema."""
    def __init__(self,runtime):
        self.runtime = runtime
        with runtime.transaction():
            if not runtime.db.execute("SELECT 1 FROM generative_keys LIMIT 1").fetchone():
                runtime.db.execute("INSERT INTO generative_keys VALUES(1,?,?)", (secrets.token_bytes(32),runtime.clock()))
                runtime._event("owner","generative.key","signer","INITIALIZED",{"epoch":1})

    def register_policy(self,policy_id,policy):
        from .policy_runner import validate_policy
        rt = self.runtime
        rt._id(policy_id)
        copied = strict_json(json.dumps(policy,ensure_ascii=False,allow_nan=False))
        validate_policy(copied)
        body = canonical(copied)
        if len(body.encode("utf-8")) > 65_536:
            raise GuardError("policy too large", "BLOCK")
        with rt.transaction():
            old = rt.db.execute("SELECT * FROM validation_policies WHERE id=?", (policy_id,)).fetchone()
            if old:
                if old["body"] != body:
                    raise GuardError("immutable owner policy collision", "BLOCK")
                _active_policy(rt,policy_id)
                return old["sha"]
            rt.db.execute("INSERT INTO validation_policies VALUES(?,?,?,?)", (policy_id,body,digest(body),rt.clock()))
            rt._event("owner","generative.policy",policy_id,"FROZEN",{"policy_sha":digest(body)})
            return digest(body)

    def revoke_policy(self,policy_id,reason="owner_withdrawal"):
        rt = self.runtime
        rt._id(policy_id);rt._id(reason)
        with rt.transaction():
            rt.db.execute("INSERT OR IGNORE INTO validation_policy_revocations VALUES(?,?,?)", (policy_id,rt.clock(),reason))
            affected = {row[0] for row in rt.db.execute("SELECT id FROM tasks WHERE policy_id=? OR source_policy_id=?", (policy_id,policy_id))}
            rt._invalidate_tasks(affected,{"policy":policy_id})
            rt._event("owner","generative.policy.revoke",policy_id,"REVOKED")

    def rotate_signing_key(self):
        rt = self.runtime
        with rt.transaction():
            epoch = rt.db.execute("SELECT max(epoch) FROM generative_keys").fetchone()[0] + 1
            rt.db.execute("INSERT INTO generative_keys VALUES(?,?,?)", (epoch,secrets.token_bytes(32),rt.clock()))
            affected = {row[0] for row in rt.db.execute("SELECT id FROM tasks WHERE validation_mode=?", (MODE,))}
            rt._invalidate_tasks(affected,{"signing_epoch":epoch})
            rt._event("owner","generative.key","signer","ROTATED",{"epoch":epoch})
            return epoch

    def _capture(self,task_id,run_id,environment):
        from .broker import environment_identity
        from .policy_runner import git_tree_sha
        rt = self.runtime
        if environment != environment_identity():
            raise GuardError("actual verification environment mismatch", "BLOCK")
        package = Path(__file__).parent.resolve()
        import sys
        database = rt.path.resolve()
        roots = [package,Path(sys.base_prefix).resolve(),*[Path(path).resolve() for path in ("/lib","/lib64","/usr/lib")]]
        if any(database.is_relative_to(root) for root in roots):
            raise GuardError("owner DB would be mounted in candidate sandbox", "BLOCK")
        task = rt.task(task_id)
        if task["validation_mode"] != MODE or task["status"] != "RESULT_READY":
            raise GuardError("no generative candidate awaiting verification", "BLOCK")
        run = rt.db.execute("SELECT * FROM runs WHERE id=? AND task=?", (run_id,task_id)).fetchone()
        source,output = rt.resource(task["input"]),rt.resource(task["output"])
        if (not run or run["state"] != "SUCCEEDED" or not rt._dependencies_current(run_id)
                or run["input_version"] != source["version"] or task["input_version"] != source["version"]
                or run["output_version"] != output["version"]):
            raise GuardError("candidate target or lineage stale", "BLOCK")
        authorization,_ = _authorization(rt,task,run_id)
        policy = _active_policy(rt,task["policy_id"])
        files = candidate_files(output["content"])
        context = {"task_id":task_id,"run_id":run_id,"task_revision":task["revision"],
                   "task_contract_sha":digest(canonical(_task_contract(task))),
                   "source_id":source["id"],"source_version":source["version"],"source_sha":source["sha"],
                   "source_origin":_source_origin(rt,task,run_id),"authorization":authorization,
                   "artifact_id":output["id"],"artifact_version":output["version"],"artifact_sha":output["sha"],
                   "tree_sha":git_tree_sha(files),"policy_id":policy["id"],"policy_sha":policy["sha"],
                   "environment":environment,"runner_sha":runner_identity()}
        return context,files,strict_json(policy["body"])

    def verify(self,task_id,environment,*,expected_run_id,timeout=10.0,crash_hook=None):
        from .policy_runner import run_policy_checks
        rt = self.runtime
        rt._id(task_id);rt._id(expected_run_id)
        with rt.transaction():
            # Recover an owner ACK loss after verification commit by observing
            # the one still-accepted proof. This does not execute checks, sign,
            # write an artifact, extend grants or reuse a worker credential.
            task=rt.task(task_id)
            if task["validation_mode"] == MODE and task["status"] == "VERIFIED":
                rows=rt.db.execute("SELECT * FROM evidence WHERE task=? AND run=? AND method=? AND outcome='PASS'", (task_id,expected_run_id,METHOD)).fetchall()
                accepted=[row for row in rows if rt._proof_is_accepted_for_gate(row,environment)]
                if len(accepted)!=1:
                    raise GuardError("no unique current owner verification receipt", "BLOCK")
                row=accepted[0]
                body=strict_json(rt.db.execute("SELECT body FROM generative_evaluations WHERE evidence=?",(row["id"],)).fetchone()[0])
                return {"evidence":row["id"],"outcome":"PASS","tree_sha":body["context"]["tree_sha"],"accepted_for_gate":True,"replayed":True}
            context,files,policy = self._capture(task_id,expected_run_id,environment)
            epoch = rt.db.execute("SELECT max(epoch) FROM generative_keys").fetchone()[0]
        checks = run_policy_checks(files,policy,context,timeout=timeout)
        if crash_hook is not None:
            crash_hook("after_checks_before_commit")  # owner/test hook only
        # Run and all content/contract/policy/environment bindings must still
        # describe the exact snapshot. No child can finalize or forge this step.
        with rt.transaction():
            current,_,_ = self._capture(task_id,expected_run_id,environment)
            key = rt.db.execute("SELECT * FROM generative_keys ORDER BY epoch DESC LIMIT 1").fetchone()
            if current != context or epoch != key["epoch"]:
                raise GuardError("candidate verification snapshot changed", "BLOCK")
            if (not isinstance(checks,dict) or checks.get("schema") != "generative-policy-checks-v1"
                    or checks.get("tree_sha") != context["tree_sha"] or checks.get("context_digest") != digest(canonical(context))
                    or checks.get("policy_digest") != context["policy_sha"] or not isinstance(checks.get("criteria"),dict)
                    or set(checks["criteria"]) != CRITERIA):
                raise GuardError("independent check result binding mismatch", "BLOCK")
            outcomes = [item.get("outcome") for item in checks["criteria"].values() if isinstance(item,dict)]
            if len(outcomes) != len(CRITERIA) or any(outcome not in {"PASS","FAIL","UNKNOWN","NOT_RUN","STALE"} for outcome in outcomes):
                raise GuardError("invalid independent check outcome", "BLOCK")
            # _capture performs Git/hash I/O. Re-read rights afterwards under
            # this owner lock at the authorization decision, just before signing.
            authorization,decision_at = _authorization(rt,rt.task(task_id),expected_run_id,expected_fence=context["authorization"]["fence"])
            if authorization != context["authorization"]:
                raise GuardError("candidate authorization changed", "BLOCK")
            outcome = "PASS" if all(x == "PASS" for x in outcomes) else "FAIL" if "FAIL" in outcomes else "UNKNOWN"
            evidence_id = str(uuid.uuid4())
            body = {"schema":"owner-generative-evaluation-v1","evidence":evidence_id,
                    "epoch":epoch,"context":context,"checks":checks,"outcome":outcome,"decision_at":decision_at}
            encoded = canonical(body)
            if len(encoded.encode("utf-8")) > 262_144:
                raise GuardError("check report too large", "BLOCK")
            rt.db.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?)", (evidence_id,task_id,expected_run_id,METHOD,outcome,context["source_version"],context["artifact_version"],context["artifact_sha"],environment,decision_at))
            rt.db.execute("INSERT INTO generative_evaluations VALUES(?,?,?,?,?)", (evidence_id,context["policy_id"],epoch,encoded,_signature(key["secret"],body)))
            if outcome in {"PASS","FAIL"}:
                rt.db.execute("UPDATE tasks SET status=?,revision=revision+1 WHERE id=?", ("VERIFIED" if outcome == "PASS" else "FAILED",task_id))
                rt.db.execute("UPDATE runs SET state=? WHERE id=?", ("VERIFIED" if outcome == "PASS" else "FAILED",expected_run_id))
                rt.db.execute("UPDATE leases SET expires=? WHERE run=?", (rt.clock(),expected_run_id))
            # UNKNOWN preserves the committed candidate for owner re-verification,
            # with original budgets/TTL. It does not start a replacement write.
            rt._event("verifier","generative.verify",task_id,outcome,{"evidence":evidence_id,"tree_sha":context["tree_sha"],"policy_sha":context["policy_sha"]})
            if crash_hook is not None:
                crash_hook("before_verification_commit")
        if crash_hook is not None:
            crash_hook("after_verification_commit")
        return {"evidence":evidence_id,"outcome":outcome,"tree_sha":context["tree_sha"],
                "accepted_for_gate":rt.proof_is_accepted_for_gate(evidence_id,environment),"replayed":False}
