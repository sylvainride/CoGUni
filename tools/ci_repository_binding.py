"""CI context preflight, not the runtime's future broker repository lock."""
from pathlib import Path
import json
import os
import re
import subprocess
import urllib.request

REPOSITORY = "sylvainride/CoGUni"
REPOSITORY_ID = "1418009675"
OWNER_ID = "265171248"
REPO_NODE_ID = "R_kgDOVIUcSw"  # Separately observed through the repository API.
STACKED_BASE = "work/mvp-mission-transport-20261015"
STACKED_BASE_SHA = "1fafa8248900934ebcb54bbc737557a43ecb5a5f"
PR_BASES = ("main", STACKED_BASE)


def _json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate provider field")
        value[key] = item
    return value


def read_event(context):
    # Only the workflow-injected file is an event source, never request JSON.
    with Path(context["GITHUB_EVENT_PATH"]).open("rb") as stream:
        data = stream.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("provider event exceeds bound")
    return json.loads(data, object_pairs_hook=_json_object)


def public_pr(number):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open("https://api.github.com/repos/" + REPOSITORY + "/pulls/" + str(number), timeout=20) as response:
        data = response.read(262145)
    if len(data) > 262144:
        raise ValueError("provider PR exceeds bound")
    return json.loads(data, object_pairs_hook=_json_object)


def bound_repository(repo):
    return (type(repo) is dict and repo.get("id") == int(REPOSITORY_ID)
            and repo.get("full_name") == REPOSITORY
            and repo.get("owner", {}).get("id") == int(OWNER_ID)
            and repo.get("owner", {}).get("login") == "sylvainride")


def _pr_identity(pr):
    return (pr["number"], pr["state"], pr["base"]["ref"], pr["base"]["sha"],
            pr["head"]["ref"], pr["head"]["sha"], pr["merge_commit_sha"])


def validate_pr(context, payload, observed, merge_parents):
    try:
        number = int(context["GITHUB_REF"].split("/")[2])
        pr = payload["pull_request"]
        if (context.get("GITHUB_ACTOR_ID") != OWNER_ID
                or payload["sender"]["id"] != int(OWNER_ID)
                or payload["number"] != number or not bound_repository(payload["repository"])):
            raise ValueError("pull request provider identity is not authorized")
        for item in (pr, observed):
            if (item["number"] != number or item["state"] != "open"
                    or not bound_repository(item["base"]["repo"])
                    or not bound_repository(item["head"]["repo"])
                    or item["user"]["id"] != int(OWNER_ID)
                    or item["base"]["ref"] != context["GITHUB_BASE_REF"]
                    or item["head"]["ref"] != context["GITHUB_HEAD_REF"]
                    or not re.fullmatch(r"(?:work|bootstrap)/[A-Za-z0-9._/-]+", item["head"]["ref"])
                    or any(not re.fullmatch(r"[0-9a-f]{40}", item[side]["sha"]) for side in ("base", "head"))
                    or item["merge_commit_sha"] != context["GITHUB_SHA"]):
                raise ValueError("pull request refs or repository are not qualified")
            if item["base"]["ref"] == STACKED_BASE and (
                    number != 14 or item["head"]["ref"] != "work/parallel-missions-20261015"
                    or item["base"]["sha"] != STACKED_BASE_SHA):
                raise ValueError("stacked pull request is outside the explicit approval")
        if (_pr_identity(pr) != _pr_identity(observed)
                or list(merge_parents) != [pr["base"]["sha"], pr["head"]["sha"]]):
            raise ValueError("pull request changed or virtual merge parents differ")
        return {"pr_number": number, "base_ref": pr["base"]["ref"], "base_sha": pr["base"]["sha"],
                "head_ref": pr["head"]["ref"], "head_sha": pr["head"]["sha"],
                "merge_parents": list(merge_parents)}
    except (KeyError, TypeError, AttributeError, IndexError) as error:
        raise ValueError("incomplete pull request provider evidence") from error


def validate_context(context, checkout_sha, *, payload=None, observed_pr=None, merge_parents=()):
    expected = {
        "GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_API_URL": "https://api.github.com", "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": REPOSITORY_ID, "GITHUB_REPOSITORY_OWNER": "sylvainride",
        "GITHUB_REPOSITORY_OWNER_ID": OWNER_ID,
    }
    for key, value in expected.items():
        if context.get(key) != value:
            raise ValueError("repository context mismatch: " + key)
    sha = context.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or sha != checkout_sha:
        raise ValueError("checkout does not match the event commit")
    event = context.get("GITHUB_EVENT_NAME")
    ref = context.get("GITHUB_REF", "")
    observation = {}
    if event == "pull_request":
        if context.get("GITHUB_BASE_REF") not in PR_BASES or not re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", ref):
            raise ValueError("pull request target or merge ref is not authorized")
        observation = validate_pr(context, payload, observed_pr, merge_parents)
    elif event in {"push", "workflow_dispatch"}:
        if not re.fullmatch(r"refs/heads/(main|(?:work|bootstrap)/[A-Za-z0-9._/-]+)", ref):
            raise ValueError("branch is not authorized for this CI workflow")
    else:
        raise ValueError("workflow event is not authorized")
    return {"repository": REPOSITORY, "repository_id": REPOSITORY_ID,
            "owner_id": OWNER_ID, "checkout_sha": sha, "event": event,
            "scope": "CI_CONTEXT_PREFLIGHT_ONLY", **observation}


def main():
    root = Path(__file__).resolve().parents[1]
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    try:
        evidence = {}
        if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
            ref = os.environ.get("GITHUB_REF", "")
            if not re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", ref):
                raise ValueError("invalid PR merge ref")
            payload = read_event(os.environ)
            parents = [line[7:] for line in subprocess.check_output(
                ["git", "cat-file", "-p", sha], cwd=root, text=True).split("\n\n", 1)[0].splitlines()
                if line.startswith("parent ")]
            evidence = dict(payload=payload, observed_pr=public_pr(int(ref.split("/")[2])), merge_parents=parents)
        observation = validate_context(os.environ, sha, **evidence)
        observation["checkout_tree"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip()
    except (ValueError, KeyError, OSError) as error:
        print(str(error))  # Field names only; never print values or the full environment.
        return 1
    print(json.dumps(observation, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
