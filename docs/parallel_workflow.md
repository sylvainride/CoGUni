# Synthetic mission concurrency

The existing workflow keeps the ordinary `coguni-checks-<ref>` cancellation
policy for code checks. Only a `push` to a branch whose full ref starts with
`refs/heads/work/mvp-mission-transport-` uses the mission policy. Such a run has
its own group, `coguni-mission-<run_id>-<run_attempt>`, and cannot cancel another
mission run through Actions concurrency. A rerun receives a distinct attempt
group. This is scheduling isolation, not permission to apply a target effect.

Setting only `cancel-in-progress: false` on one shared group would still leave
pending runs subject to the group's pending-queue behaviour. Unique run/attempt
groups avoid that collision without relying on an optional queue setting or
adding another workflow. GitHub runner availability, service limits, explicit
cancellation and failures can still delay or stop a job. This change guarantees
neither unlimited parallelism nor background continuation of a Chat session.

The owner scheduler remains responsible for bounded admission, dependency and
resource exclusion, budgets, immutable provider/source identity, and exact
proof/readback before application. A later result push may launch another
workflow; its distinct identity does not authorise repeating an earlier effect.
No token permission, worker command, mandatory isolation or required check is
changed here.

The pull-request trigger also names the exact existing transport development
branch `work/mvp-mission-transport-20261015`, so a PR stacked on that base gets
the same two checks on its virtual merge. `main` remains included. No wildcard
base, privileged pull-request event or protected-branch setting is introduced.

`python3 -B -m unittest tests.test_parallel_workflow -v` reads the committed YAML
and evaluates its actual concurrency expressions across mission, ordinary CI,
pending, rerun and wrong-event/ref contexts. The tests use only the standard
library; when PyYAML is installed it also checks the targeted YAML parsing
against a full parser. Provider qualification still requires actual runs.

Official reference:
https://docs.github.com/en/actions/concepts/workflows-and-actions/concurrency
