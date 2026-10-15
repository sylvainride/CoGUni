"""Exercise the real workflow's bounded concurrency expressions without dependencies."""
import ast
from pathlib import Path
import re
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"


def concurrency_scalars(text):
    """Read this YAML block's plain/quoted scalars; reject unsupported structure.

    The dependency-free reader accepts only the deliberately small YAML subset
    used by this block. When available, PyYAML independently checks the document.
    No fallback permits an unrecognised scalar or silently changes its type.
    """
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line == "concurrency:"]
    if len(starts) != 1:
        raise ValueError("expected one top-level concurrency mapping")
    result = {}
    for line in lines[starts[0] + 1:]:
        if line and not line[0].isspace():
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"  (group|cancel-in-progress): (.+)", line)
        if match is None or match[1] in result:
            raise ValueError("unsupported or duplicate concurrency entry")
        value = match[2]
        if value == "true":
            value = True
        elif value == "false":
            value = False
        elif not value.startswith("${{") or not value.endswith("}}") or ": " in value or " #" in value:
            raise ValueError("expected a YAML boolean or a complete plain expression scalar")
        result[match[1]] = value
    if set(result) != {"group", "cancel-in-progress"}:
        raise ValueError("missing concurrency entry")
    try:
        import yaml
    except ImportError:
        pass
    else:
        if yaml.safe_load(text)["concurrency"] != result:
            raise ValueError("targeted YAML reader differs from full YAML parser")
    return result


class Expression:
    """Interpret the committed expression's small syntax subset without eval.

    Python's AST supplies parsing only. Every accepted node and callable is
    explicitly bounded; unknown syntax fails instead of becoming executable.
    """
    def __init__(self, value, context):
        self.value = value
        self.context = context

    def node(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool)):
            return node.value
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "github":
            return self.context[node.attr]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not self.node(node.operand)
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            left, right = self.node(node.left), self.node(node.comparators[0])
            return left.casefold() == right.casefold() if isinstance(left, str) and isinstance(right, str) else left == right
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            value = self.node(node.values[0])
            for item in node.values[1:]:
                if (isinstance(node.op, ast.And) and not value) or (isinstance(node.op, ast.Or) and value):
                    break
                value = self.node(item)
            return value
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.keywords:
            args = [self.node(arg) for arg in node.args]
            if node.func.id == "startsWith" and len(args) == 2:
                # GitHub string comparison functions ignore case.
                return args[0].casefold().startswith(args[1].casefold())
            if node.func.id == "format" and args:
                return args[0].format(*args[1:])
        raise ValueError("unsupported expression syntax")

    def evaluate(self):
        if isinstance(self.value, bool):
            return self.value
        if not self.value.startswith("${{") or not self.value.endswith("}}"):
            raise ValueError("expression delimiters required")
        # Preserve quoted literals while translating operator spelling only.
        source = re.sub(r"'[^']*'|&&|\|\||!", lambda match: {
            "&&": " and ", "||": " or ", "!": " not "
        }.get(match[0], match[0]), self.value[3:-2]).strip()
        return self.node(ast.parse(source, mode="eval").body)


class ParallelWorkflowTests(unittest.TestCase):
    def policy(self, event="push", ref="refs/heads/work/mvp-mission-transport-A", run_id=101, run_attempt=1):
        values = concurrency_scalars(WORKFLOW.read_text())
        context = dict(event_name=event, ref=ref, run_id=run_id, run_attempt=run_attempt)
        return {name: Expression(value, context).evaluate() for name, value in values.items()}

    def test_mission_pending_runs_and_reruns_have_distinct_groups(self):
        # GitHub preserves only a bounded pending queue for shared groups. Each
        # run/attempt must therefore be isolated before any runner is available.
        rows = [self.policy(run_id=run_id, run_attempt=attempt)
                for run_id in range(101, 106) for attempt in (1, 2)]
        self.assertEqual(len({row["group"].casefold() for row in rows}), 10)
        self.assertTrue(all(row["cancel-in-progress"] is False for row in rows))

    def test_same_sha_pushes_are_distinct_and_new_push_cannot_cancel_old(self):
        first = self.policy(run_id=101)
        second = self.policy(run_id=102)
        self.assertNotEqual(first["group"], second["group"])
        self.assertIs(first["cancel-in-progress"], False)
        self.assertIs(second["cancel-in-progress"], False)

    def test_distinct_mission_branches_do_not_share_groups(self):
        first = self.policy(ref="refs/heads/work/mvp-mission-transport-A", run_id=101)
        second = self.policy(ref="refs/heads/work/mvp-mission-transport-B", run_id=102)
        self.assertNotEqual(first["group"], second["group"])

    def test_ordinary_ci_retains_ref_group_and_cancellation(self):
        for ref in ("refs/heads/main", "refs/heads/work/parallel", "refs/heads/bootstrap/review"):
            with self.subTest(ref=ref):
                first = self.policy(ref=ref, run_id=101)
                second = self.policy(ref=ref, run_id=102, run_attempt=2)
                self.assertEqual(first["group"], "coguni-checks-" + ref)
                self.assertEqual(first["group"], second["group"])
                self.assertIs(first["cancel-in-progress"], True)

    def test_mission_qualification_requires_push_and_full_branch_prefix(self):
        for event, ref in (
            ("workflow_dispatch", "refs/heads/work/mvp-mission-transport-A"),
            ("pull_request", "refs/pull/14/merge"),
            ("pull_request", "refs/heads/work/mvp-mission-transport-A"),
            ("push", "refs/tags/work/mvp-mission-transport-A"),
            ("push", "refs/heads/work/mvp-mission-transport"),
            ("push", "refs/heads/work/not-mvp-mission-transport-A"),
        ):
            with self.subTest(event=event, ref=ref):
                row = self.policy(event=event, ref=ref)
                self.assertEqual(row["group"], "coguni-checks-" + ref)
                self.assertIs(row["cancel-in-progress"], True)

    def test_stacked_pr_base_keeps_main_and_required_job_names(self):
        text = WORKFLOW.read_text()
        block = re.search(r"^  pull_request:\n    branches:\n(?P<branches>(?:    - [^\n]+\n)+)", text, re.MULTILINE)
        self.assertIsNotNone(block)
        branches = [line[6:] for line in block["branches"].splitlines()]
        self.assertEqual(branches, ["main", "work/mvp-mission-transport-20261015"])
        jobs = re.findall(r"^  ([a-z][a-z-]+):\n    name: ([a-z][a-z-]+)$", text, re.MULTILINE)
        self.assertEqual(jobs, [("owner-contracts", "owner-contracts"), ("sandbox-runtime", "sandbox-runtime")])
        self.assertRegex(text, r"(?m)^permissions: \{\}$")

    def test_yaml_scalar_reader_refuses_duplicate_or_non_scalar_config(self):
        for text in (
            "concurrency:\n  group: ${{ github.ref }}\n  group: ${{ github.ref }}\n  cancel-in-progress: true\n",
            "concurrency:\n  group:\n    key: value\n  cancel-in-progress: true\n",
            "concurrency:\n  group: ${{ github.ref }}\n  cancel-in-progress: [false]\n",
        ):
            with self.subTest(text=text):
                self.assertRaises(ValueError, concurrency_scalars, text)


if __name__ == "__main__":
    unittest.main()
