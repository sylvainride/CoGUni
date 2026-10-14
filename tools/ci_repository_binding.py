"""CI context preflight, not the runtime's future broker repository lock."""
from pathlib import Path
import json
import os
import re
import subprocess

REPOSITORY = "sylvainride/CoGUni"
REPOSITORY_ID = "1418009675"
OWNER_ID = "265171248"
REPO_NODE_ID = "R_kgDOVIUcSw"  # Separately observed through the repository API.


def validate_context(context, checkout_sha):
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
    if event == "pull_request":
        if context.get("GITHUB_BASE_REF") != "main" or not re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", ref):
            raise ValueError("pull request target or merge ref is not authorized")
    elif event in {"push", "workflow_dispatch"}:
        if not re.fullmatch(r"refs/heads/(main|(?:work|bootstrap)/[A-Za-z0-9._/-]+)", ref):
            raise ValueError("branch is not authorized for this CI workflow")
    else:
        raise ValueError("workflow event is not authorized")
    return {"repository": REPOSITORY, "repository_id": REPOSITORY_ID,
            "owner_id": OWNER_ID, "checkout_sha": sha, "event": event,
            "scope": "CI_CONTEXT_PREFLIGHT_ONLY"}


def main():
    root = Path(__file__).resolve().parents[1]
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    try:
        observation = validate_context(os.environ, sha)
    except ValueError as error:
        print(str(error))  # Field names only; never print values or the full environment.
        return 1
    print(json.dumps(observation, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
