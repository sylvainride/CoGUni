"""CI refuses identity substitution, privileged events and checkout mismatch."""
import unittest
from tools.ci_repository_binding import validate_context


def context(event="push"):
    return {"GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com", "GITHUB_REPOSITORY": "sylvainride/CoGUni",
            "GITHUB_REPOSITORY_ID": "1418009675", "GITHUB_REPOSITORY_OWNER": "sylvainride",
            "GITHUB_REPOSITORY_OWNER_ID": "265171248", "GITHUB_SHA": "a" * 40,
            "GITHUB_EVENT_NAME": event, "GITHUB_REF": "refs/heads/main"}


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

    def test_fork_merge_context_uses_bound_base_repository(self):
        value = context("pull_request")
        value.update(GITHUB_REF="refs/pull/7/merge", GITHUB_BASE_REF="main")
        self.assertEqual(validate_context(value, "a" * 40)["event"], "pull_request")
        for key, replacement in (("GITHUB_BASE_REF", "other"), ("GITHUB_REF", "refs/heads/main")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_context({**value, key: replacement}, "a" * 40)

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
