# ADR 012: bounded CI campaigns and repository identity

Status at prepublication review, 2026-10-13: implemented in the review snapshot;
remote workflow execution pending.

Preserve the existing runtime and its strict default SHA policy. Add two
separate CI jobs on standard GitHub-hosted Ubuntu runners with Python 3.12.
`owner-contracts` runs the explicit host-independent owner checks and the
existing continuity and local replay fixtures. `sandbox-runtime` must first
pass the real namespace, seccomp and CPU qualification probes, then run the
entire discovered test suite and the bounded generative fixtures.

The test gate refuses skipped, missing, duplicate or incomplete tests, and
tracked source changes. Test inventory, individual outcomes, checkout commit,
tree, per-file hashes and host versions are recorded. An owner-only passing
campaign never certifies the sandbox or the whole product. No checks are
omitted from the full campaign to accommodate an unqualified host.

The context preflight requires the canonical repository name, repository ID
1418009675, owner ID 265171248, GitHub server, permitted event and branch, and
the actual checkout SHA. The separately observed repository node ID is
R_kgDOVIUcSw. This assumes trusted GitHub context and workflow bootstrap; it
does not implement the future broker lock, perform live permission queries,
authorize remote effects or prevent an owner from changing repository rules.

Only push, pull_request and workflow_dispatch events are used. Each job first
checks the repository and owner IDs, public GitHub server and event SHA, then
fetches that exact commit over anonymous HTTPS from the literal bound remote.
Git and Python 3.12 come from the standard Ubuntu runner. The workflow uses no
external action, token permission, credential, secret, cache or artifact upload.
Whitelisted JSON summaries are emitted to the public job log; raw test logs
are not emitted. Jobs have ten- and fifteen-minute timeouts. There is no paid
model API, deployment, larger runner or self-hosted runner in this workflow.

Three official action releases were initially considered at verified SHAs.
Their lockfile audits reported high-severity dependency advisories. Their
source and build lockfiles do not establish exploitability of bundled action
code, but those dependencies are not part of the selected workflow. The
private review retains the audits and direct-license observations. The remote
policy still requires full-length action SHAs if actions are introduced later.

Bubblewrap comes from the runner's distribution repositories. No host security
policy is disabled and no sandbox argument is removed. If the runner cannot
meet the required isolation profile, qualification must fail and subsequent
sandbox campaigns remain unexecuted. Runner images, distribution packages and
Python patch versions can change; record the actual observed environment. JSON
evidence in workflow logs follows the repository's observed ninety-day log
retention policy; no separate artifact storage is requested.

The remote integrity ruleset targets main and blocks deletion and force pushes
without bypass actors. The repository currently has no branch. Required pull
requests and named CI checks must be configured after the approved initial
snapshot creates main and actual workflow check identities are observable.
No external approving reviewer is configured in this single-owner bootstrap.

Rollback: remove this CI preparation commit locally. Do not remove mandatory
runtime isolation or disable remote integrity rules to obtain passing checks.
First public source publication and licensing remain owner decisions.

Primary references:

- https://docs.github.com/en/actions/reference/workflows-and-actions/variables
- https://docs.github.com/en/actions/reference/security/secure-use
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
