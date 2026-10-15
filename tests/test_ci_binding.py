"""CI refuses identity substitution, privileged events and checkout mismatch."""
import unittest
import copy
from tools.ci_repository_binding import validate_context, STACKED_BASE, STACKED_BASE_SHA


def context(event="push"):
    return {"GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com", "GITHUB_REPOSITORY": "sylvainride/CoGUni",
            "GITHUB_REPOSITORY_ID": "1418009675", "GITHUB_REPOSITORY_OWNER": "sylvainride",
            "GITHUB_REPOSITORY_OWNER_ID": "265171248", "GITHUB_SHA": "a" * 40,
            "GITHUB_EVENT_NAME": event, "GITHUB_REF": "refs/heads/main"}


def pr_evidence(base="main"):
    repo = {"id": 1418009675, "full_name": "sylvainride/CoGUni",
            "owner": {"id": 265171248, "login": "sylvainride"}}
    pr = {"number": 14, "state": "open", "user": {"id": 265171248},
          "base": {"ref": base, "sha": STACKED_BASE_SHA, "repo": copy.deepcopy(repo)},
          "head": {"ref": "work/parallel-missions-20261015", "sha": "b" * 40, "repo": copy.deepcopy(repo)},
          "merge_commit_sha": "a" * 40}
    value = context("pull_request")
    value.update(GITHUB_REF="refs/pull/14/merge", GITHUB_BASE_REF=base,
                 GITHUB_HEAD_REF=pr["head"]["ref"], GITHUB_ACTOR_ID="265171248")
    return value, dict(payload={"number": 14, "sender": {"id": 265171248}, "repository": repo,
                                "pull_request": pr}, observed_pr=copy.deepcopy(pr),
                       merge_parents=[STACKED_BASE_SHA, "b" * 40])


class TestCIBinding(unittest.TestCase):
    def test_exact_owner_repository_and_commit_are_accepted(self):
        self.assertEqual(validate_context(context(), "a" * 40)["scope"], "CI_CONTEXT_PREFLIGHT_ONLY")

    def test_same_name_with_other_immutable_id_is_refused(self):
        value = context()
        value["GITHUB_REPOSITORY_ID"] = "1418009676"
        with self.assertRaises(ValueError):
            validate_context(value, "a" * 40)

    def test_owner_transfer_and_fork_are_refused(self):
        for key, replacement in (("GITHUB_REPOSITORY_OWNER_ID", "1"),
                                 ("GITHUB_REPOSITORY_OWNER", "other"),
                                 ("GITHUB_REPOSITORY", "other/CoGUni")):
            with self.subTest(key=key):
                value = context()
                value[key] = replacement
                with self.assertRaises(ValueError):
                    validate_context(value, "a" * 40)

    def test_missing_context_and_other_servers_are_refused(self):
        for key in context():
            with self.subTest(key=key):
                value = context()
                value.pop(key)
                with self.assertRaises(ValueError):
                    validate_context(value, "a" * 40)
        value = context()
        value["GITHUB_SERVER_URL"] = "https://example.invalid"
        with self.assertRaises(ValueError):
            validate_context(value, "a" * 40)

    def test_sha_format_and_actual_checkout_must_match(self):
        for sha in ("b" * 40, "a" * 39, "G" * 40, ""):
            with self.subTest(sha=sha):
                value = context()
                value["GITHUB_SHA"] = sha
                with self.assertRaises(ValueError):
                    validate_context(value, "a" * 40)

    def test_main_and_exact_stacked_virtual_merges_are_bound(self):
        for base in ("main", STACKED_BASE):
            value, evidence = pr_evidence(base)
            result = validate_context(value, "a" * 40, **evidence)
            self.assertEqual(result["merge_parents"], [STACKED_BASE_SHA, "b" * 40])
        value, evidence = pr_evidence()
        for key, replacement in (("GITHUB_BASE_REF", "other"), ("GITHUB_REF", "refs/heads/main")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_context({**value, key: replacement}, "a" * 40, **evidence)

    def test_stacked_pr_requires_provider_evidence_and_refuses_forks_and_drift(self):
        def change(path, replacement):
            value, evidence = pr_evidence(STACKED_BASE)
            target = evidence
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = replacement
            return value, evidence
        cases = [
            (("payload", "sender", "id"), 1), (("payload", "number"), 15),
            (("payload", "repository", "id"), 1),
            (("payload", "pull_request", "head", "repo", "id"), 1),
            (("observed_pr", "head", "repo", "owner", "id"), 1),
            (("observed_pr", "head", "repo", "full_name"), "fork/CoGUni"),
            (("observed_pr", "head", "sha"), "c" * 40),
            (("observed_pr", "base", "sha"), "c" * 40),
            (("payload", "pull_request", "base", "sha"), "c" * 40),
            (("observed_pr", "base", "ref"), "main"),
            (("observed_pr", "head", "ref"), "work/other"),
            (("observed_pr", "user", "id"), 1), (("observed_pr", "state"), "closed"),
            (("observed_pr", "merge_commit_sha"), "d" * 40),
            (("merge_parents",), ["b" * 40, STACKED_BASE_SHA]),
            (("merge_parents",), [STACKED_BASE_SHA]),
            (("merge_parents",), [STACKED_BASE_SHA, "c" * 40]),
            (("payload",), None), (("observed_pr",), None),
        ]
        for path, replacement in cases:
            with self.subTest(path=path), self.assertRaises(ValueError):
                value, evidence = change(path, replacement)
                validate_context(value, "a" * 40, **evidence)
        for key, bad in (("GITHUB_ACTOR_ID", "1"), ("GITHUB_HEAD_REF", "work/other"),
                         ("GITHUB_BASE_REF", STACKED_BASE + "-copy"),
                         ("GITHUB_REF", "refs/pull/15/merge"), ("GITHUB_REF", "refs/pull/14/head"),
                         ("GITHUB_SHA", "b" * 40), ("GITHUB_EVENT_NAME", "pull_request_target"),
                         ("GITHUB_EVENT_NAME", "workflow_run")):
            value, evidence = pr_evidence(STACKED_BASE)
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                validate_context({**value, key: bad}, "a" * 40, **evidence)

    def test_stacked_allowance_does_not_extend_to_other_prs_or_heads(self):
        value, evidence = pr_evidence(STACKED_BASE)
        value["GITHUB_REF"] = "refs/pull/15/merge"
        evidence["payload"]["number"] = 15
        for pr in (evidence["payload"]["pull_request"], evidence["observed_pr"]):
            pr["number"] = 15
        with self.assertRaises(ValueError):
            validate_context(value, "a" * 40, **evidence)
        value, evidence = pr_evidence(STACKED_BASE)
        value["GITHUB_HEAD_REF"] = "work/other"
        for pr in (evidence["payload"]["pull_request"], evidence["observed_pr"]):
            pr["head"]["ref"] = "work/other"
        with self.assertRaises(ValueError):
            validate_context(value, "a" * 40, **evidence)

    def test_privileged_events_and_unapproved_branches_are_refused(self):
        for event in ("pull_request_target", "workflow_run", "release"):
            with self.subTest(event=event), self.assertRaises(ValueError):
                validate_context(context(event), "a" * 40)
        for ref in ("refs/tags/main", "refs/heads/other", "refs/heads/work/"):
            value = context()
            value["GITHUB_REF"] = ref
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                validate_context(value, "a" * 40)

    def test_work_and_bootstrap_branches_can_run_checks(self):
        for ref in ("refs/heads/work/v8-02", "refs/heads/bootstrap/p01-ci"):
            value = context("workflow_dispatch")
            value["GITHUB_REF"] = ref
            with self.subTest(ref=ref):
                self.assertEqual(validate_context(value, "a" * 40)["checkout_sha"], "a" * 40)
