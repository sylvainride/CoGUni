"""Public synthetic resource/DAG admission and deterministic state-machine tests."""
from dataclasses import FrozenInstanceError, replace
import random
import unittest

from universal.parallel_policy import (Access, Work, HOLDING_STATES,
                                       conflicts, select_ready)

SHA = "a" * 40
OTHER_SHA = "b" * 40


def access(target="target", path="/artifact", *, mode="W", immutable=False, **changes):
    values = dict(provider="github", repo_id=1418009675, project_id="synthetic-P",
                  ref=SHA if immutable else "refs/heads/work/parallel-test",
                  path=path, mode=mode, expected_sha=SHA, physical_id=target,
                  immutable=immutable)
    values.update(changes)
    return Access(**values)


def work(task_id="A", target="target", path="/artifact", *, accesses=None, **changes):
    values = dict(task_id=task_id, depends_on=(), accesses=(access(target, path),),
                  authorized=True)
    if accesses is not None:
        values["accesses"] = accesses
    values.update(changes)
    return Work(**values)


def ready(tasks, **changes):
    values = dict(enabled=True, remaining_runs=128, remaining_seconds=128 * 300)
    values.update(changes)
    return select_ready(tasks, **values)


def footprint_collision(a, b):
    """Independent safety oracle: compare path component prefixes, not strings."""
    for left in a.accesses:
        for right in b.accesses:
            if left.physical_id != right.physical_id or (left.immutable and right.immutable):
                continue
            first = tuple(part for part in left.path.split("/") if part)
            second = tuple(part for part in right.path.split("/") if part)
            if first[:min(len(first), len(second))] == second[:min(len(first), len(second))]:
                return True
    return False


class ParallelPolicyTests(unittest.TestCase):
    def test_default_disabled_and_never_an_execution_grant(self):
        item = work()
        decision = select_ready([item])
        self.assertEqual(decision.selected, ())
        self.assertEqual(decision.blocked, (("A", "DISABLED"),))
        self.assertFalse(decision.execution_authorized)
        admitted = ready([item])
        self.assertEqual(admitted.selected, ("A",))
        self.assertFalse(admitted.execution_authorized)
        with self.assertRaises(FrozenInstanceError):
            admitted.execution_authorized = True
        with self.assertRaises(FrozenInstanceError):
            item.state = "ACCEPTED_APPLIED"

    def test_independent_ab_and_one_slot_sequential_compatibility(self):
        tasks = [work("B", "target-B"), work("A", "target-A")]
        self.assertEqual(ready(tasks).selected, ("A", "B"))
        self.assertEqual(ready(tasks, max_parallel=1).selected, ("A",))
        self.assertEqual(ready(tasks[::-1]).selected, ready(tasks).selected)

    def test_d_waits_for_owner_acceptance_and_applied_readback(self):
        dependent = work("D", "target-D", depends_on=("A",))
        for state in HOLDING_STATES | {"READY", "BLOCKED", "CANCELLED", "FAILED_CONFIRMED"}:
            decision = ready([work("A", "target-A", state=state), dependent])
            with self.subTest(state=state):
                self.assertNotIn("D", decision.selected)
                self.assertIn(("D", "DEPENDENCY_NOT_APPLIED"), decision.blocked)
        self.assertEqual(ready([work("A", state="ACCEPTED_APPLIED"), dependent]).selected, ("D",))
        with self.assertRaises(ValueError):
            work(state="COMPLETED")  # A worker's computation is not an owner state.

    def test_unknown_result_apply_suspect_and_handoff_keep_resources(self):
        for state in HOLDING_STATES:
            active = work("A", state=state, authorized=False)
            candidate = work("B")
            with self.subTest(state=state):
                decision = ready([active, candidate])
                self.assertEqual(decision.selected, ())
                self.assertEqual(decision.held, ("A",))
                self.assertIn(("B", "RESOURCE_HELD"), decision.blocked)
        independent = work("C", "independent")
        self.assertEqual(ready([work(state="UNKNOWN_EFFECT"), independent]).selected, ("C",))

    def test_lower_limit_or_permission_does_not_release_active_reservations(self):
        active = [work("A", "A", state="IN_FLIGHT", authorized=False),
                  work("B", "B", state="UNKNOWN_EFFECT", authorized=False)]
        decision = ready(active + [work("C", "C")], max_parallel=1)
        self.assertEqual(decision.selected, ())
        self.assertEqual(decision.held, ("A", "B"))
        self.assertEqual(ready([work(authorized=False)]).blocked,
                         (("A", "OWNER_PERMISSION_REQUIRED"),))

    def test_global_target_writes_conflict_even_across_branches(self):
        left = work("A", accesses=(access(ref="refs/heads/work/A"),))
        right = work("B", accesses=(access(ref="refs/heads/work/B"),))
        self.assertTrue(conflicts(left, right))
        self.assertEqual(ready([left, right]).selected, ("A",))
        self.assertEqual(ready([replace(left, state="IN_FLIGHT"), right]).selected, ())

    def test_read_profiles_and_stage_claims(self):
        pinned = work("A", accesses=(access(mode="R", immutable=True),), work_class="READ_SOURCE")
        second = replace(pinned, task_id="B")
        self.assertEqual(ready([pinned, second]).selected, ("A", "B"))
        older = replace(second, accesses=(access(mode="R", immutable=True,
                                                 ref=OTHER_SHA, expected_sha=OTHER_SHA),))
        self.assertEqual(ready([pinned, older]).selected, ("A", "B"))
        mutable = replace(second, accesses=(access(mode="R"),))
        self.assertEqual(ready([pinned, mutable]).selected, ("A",))
        self.assertTrue(conflicts(mutable, work("C")))
        for kind in ("READ_SOURCE", "COMPUTE_ONLY"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                work(work_class=kind)

    def test_prefix_root_and_disjoint_boundaries(self):
        for first, second in (("/", "/file"), ("/dir", "/dir/file"),
                              ("/dir/file", "/dir"), ("/dir", "/dir")):
            with self.subTest(paths=(first, second)):
                self.assertTrue(conflicts(work(path=first), work("B", path=second)))
        for first, second in (("/dir", "/directory"), ("/dir/a", "/dir/b")):
            with self.subTest(paths=(first, second)):
                self.assertEqual(ready([work(path=first), work("B", path=second)]).selected, ("A", "B"))

    def test_owner_alias_chain_and_case_policy_not_branch_spelling(self):
        tasks = [work("A", "canonical", "/Source"), work("B", "symlink-alias", "/source/file")]
        aliases = (("symlink-alias", "mount-alias"), ("mount-alias", "canonical"))
        self.assertEqual(ready(tasks, resource_aliases=aliases).selected, ("A", "B"))
        policy = dict(resource_aliases=aliases, case_insensitive_targets=("canonical",))
        self.assertEqual(ready(tasks, **policy).selected, ("A",))
        self.assertTrue(conflicts(tasks[0], tasks[1], **policy))
        # No filesystem claim: the authenticated owner supplies physical aliases.

    def test_changed_physical_domain_is_refused(self):
        for changes in ({"provider": "local"}, {"repo_id": 99}, {"project_id": "changed"}):
            tasks = [work("A"), work("B", accesses=(access(**changes),))]
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "identity changed"):
                ready(tasks)
        # Aliasing to a canonical target cannot bypass the domain binding.
        with self.assertRaises(ValueError):
            ready([work(), work("B", accesses=(access("alias", project_id="changed"),))],
                  resource_aliases=(("alias", "target"),))

    def test_budget_reservation_backpressure_and_fit(self):
        tasks = [work("A", "A", run_cost=2, duration_seconds=100),
                 work("B", "B", run_cost=1, duration_seconds=50)]
        for changes in ({"remaining_runs": 0}, {"remaining_seconds": 0}):
            with self.subTest(changes=changes):
                self.assertEqual(ready(tasks, **changes).selected, ())
        self.assertEqual(ready(tasks, remaining_runs=2).selected, ("A",))
        self.assertEqual(ready(tasks, remaining_seconds=100).selected, ("A",))
        self.assertEqual(ready(tasks, remaining_runs=1).selected, ("B",))
        self.assertEqual(ready(tasks, remaining_seconds=50).selected, ("B",))
        self.assertEqual(ready(tasks, remaining_runs=3, remaining_seconds=150).selected, ("A", "B"))

    def test_dag_and_duplicate_identity_refusal(self):
        for tasks in ([work(depends_on=("missing",))], [work(), work()],
                      [work("A", depends_on=("B",)), work("B", depends_on=("A",))]):
            with self.subTest(tasks=tasks), self.assertRaises(ValueError):
                ready(tasks)
        with self.assertRaises(ValueError):
            work(depends_on=("A",))
        with self.assertRaises(ValueError):
            work(depends_on=("B", "B"))
        # Iterative shared validator also handles the maximal bounded chain.
        chain = [work("T%03d" % n, str(n), depends_on=(() if n == 0 else ("T%03d" % (n - 1),)))
                 for n in range(256)]
        self.assertEqual(ready(chain, max_backlog=256).selected, ("T000",))

    def test_untyped_noncanonical_and_unbounded_inputs_refused(self):
        for changes in ({"repo_id": True}, {"repo_id": 0}, {"provider": []},
                        {"physical_id": "../target"}, {"project_id": ""},
                        {"mode": "OWNER_PASS"}, {"immutable": 1},
                        {"expected_sha": "a" * 39}, {"expected_sha": "A" * 40},
                        {"ref": "main"}, {"ref": "refs/heads/a..b"},
                        {"ref": "refs/heads/a/.hidden"}, {"ref": "refs/heads/a.lock"},
                        {"immutable": True}, {"mode": "R", "immutable": True,
                                               "ref": "refs/heads/work/mutable"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                access(**changes)
        for path in ("relative", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\\b", "/%2e%2e/b", "/é", "/" + "a" * 512):
            with self.subTest(path=path), self.assertRaises(ValueError):
                access(path=path)
        for changes in ({"depends_on": []}, {"accesses": []}, {"accesses": ()},
                        {"accesses": ({"mode": "W"},)}, {"accesses": (access(), access())},
                        {"accesses": tuple(access(str(i)) for i in range(33))},
                        {"run_cost": True}, {"run_cost": 0}, {"duration_seconds": 3601},
                        {"authorized": 1}, {"state": "WORKER_PASS"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                work(**changes)
        for changes in ({"enabled": 1}, {"max_parallel": True}, {"max_parallel": 0},
                        {"max_parallel": 9}, {"remaining_runs": -1},
                        {"remaining_seconds": float("nan")}, {"max_backlog": 257}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                ready([work()], **changes)
        for tasks in ({"A": work()}, [object()], [work(str(i)) for i in range(129)]):
            with self.subTest(tasks_type=type(tasks)), self.assertRaises(ValueError):
                ready(tasks)

    def test_invalid_owner_alias_and_case_inputs_refused(self):
        policies = [dict(resource_aliases={"a": "b"}),
                    dict(resource_aliases=(("a", "a"),)),
                    dict(resource_aliases=(("a", "b"), ("a", "c"))),
                    dict(resource_aliases=(("a", "b"), ("b", "a"))),
                    dict(resource_aliases=(("a",),)),
                    dict(case_insensitive_targets=["a"]),
                    dict(case_insensitive_targets=("a", "a"))]
        for policy in policies:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                ready([work()], **policy)
        with self.assertRaises(ValueError):
            conflicts(work(), object())

    def test_256_randomized_interleavings_never_duplicate_apply_or_start_d_early(self):
        rng = random.Random(15102026)
        observed_unknown = observed_reordered = 0
        for scenario in range(256):
            tasks = [work("A", "A"), work("B", "B"),
                     work("D", "D", depends_on=("A",))]
            applied, last_ready = set(), None
            for _ in range(80):
                decision = ready(tasks)
                self.assertFalse(decision.execution_authorized)
                active = [t for t in tasks if t.state in HOLDING_STATES]
                self.assertLessEqual(len(active) + len(decision.selected), 2)
                chosen = [t for t in tasks if t.task_id in decision.selected]
                for index, item in enumerate(chosen):
                    self.assertTrue(all(dep in applied for dep in item.depends_on))
                    self.assertFalse(any(footprint_collision(item, other) for other in active + chosen[:index]))
                tasks = [replace(t, state="IN_FLIGHT") if t.task_id in decision.selected else t for t in tasks]
                pending = [t for t in tasks if t.state in HOLDING_STATES]
                if not pending:
                    break
                item = rng.choice(pending)
                if item.state == "IN_FLIGHT":
                    new_state = rng.choice(("RESULT_READY", "UNKNOWN_EFFECT", "SUSPECT"))
                elif item.state in {"SUSPECT", "UNKNOWN_EFFECT"}:
                    observed_unknown += item.state == "UNKNOWN_EFFECT"
                    new_state = "RESULT_READY"  # Authenticated exact receipt reconciliation.
                elif item.state == "RESULT_READY":
                    new_state = "APPLY_PENDING"
                    observed_reordered += item.task_id == "B" and last_ready != "A"
                    last_ready = item.task_id
                else:
                    self.assertNotIn(item.task_id, applied)
                    self.assertTrue(all(dep in applied for dep in item.depends_on))
                    applied.add(item.task_id)
                    new_state = "ACCEPTED_APPLIED"  # Owner proof + CAS/readback, never worker event.
                tasks = [replace(t, state=new_state) if t.task_id == item.task_id else t for t in tasks]
                # A simulated crash/reload only permutes immutable owner rows.
                rng.shuffle(tasks)
            self.assertEqual(applied, {"A", "B", "D"}, scenario)
        self.assertGreater(observed_unknown, 0)
        self.assertGreater(observed_reordered, 0)

    def test_500_random_resource_sets_obey_external_footprint_oracle(self):
        rng = random.Random(29051982)
        for scenario in range(500):
            tasks = []
            for number in range(rng.randint(2, 12)):
                immutable = rng.choice((False, True))
                mode = "R" if immutable else rng.choice(("R", "W"))
                claim = access(rng.choice(("P", "Q", "R")),
                               rng.choice(("/", "/dir", "/dir/a", "/dir/b", "/other")),
                               mode=mode, immutable=immutable)
                tasks.append(work("T%02d" % number, accesses=(claim,),
                                  state=rng.choice(("READY", "READY", "IN_FLIGHT", "UNKNOWN_EFFECT"))))
            selected = ready(tasks).selected
            chosen = [t for t in tasks if t.task_id in selected]
            active = [t for t in tasks if t.state in HOLDING_STATES]
            self.assertLessEqual(len(chosen), max(0, 2 - len(active)), scenario)
            for index, item in enumerate(chosen):
                self.assertFalse(any(footprint_collision(item, other) for other in active + chosen[:index]), scenario)
            rng.shuffle(tasks)
            self.assertEqual(ready(tasks).selected, selected, scenario)


if __name__ == "__main__":
    unittest.main()
