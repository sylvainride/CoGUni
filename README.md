# CoGUni

Local Python control runtime, version 0.4.0. This is a review snapshot.

The owner defines immutable task contracts and controls permissions, leases,
versions and validation. Three deterministic operations use a predeclared SHA.
An explicit candidate mode supports bounded Python functions checked against
owner-defined policies and independent external oracles. Candidate submission
alone never means validation succeeded.

The runtime also includes a separate scheduling journal and a fake outbox using
two local SQLite databases. The journal does not execute tools or models.
The outbox provides fixtures for uncertain acknowledgements and reconciliation;
it does not connect to a remote service.

## Requirements and tests

Python 3.10+, Git and the Python standard library. Running untrusted children
requires Linux, functioning Bubblewrap user/network namespaces and seccomp.
The presence of a bwrap binary alone does not qualify the host. Isolation
failure must block execution.

CI separates owner checks from the full sandbox campaign. On a clean committed
checkout, host-independent checks are available with:

```bash
python -B -W error::ResourceWarning tools/run_ci_checks.py --mode owner --out evidence/owner
```

On a qualified host:

```bash
python -B -W error::ResourceWarning tools/run_ci_checks.py --mode isolation --out evidence/isolation
python -B -W error::ResourceWarning tools/run_ci_checks.py --mode full --out evidence/full
```

Host-independent owner checks can be examined separately; a passing subset
does not establish that the full sandbox suite passes on another host.
CLI entry point: `python -B -m universal --help`.

## Scope

No model inference, autonomous agent service, GitHub integration or general
Git workspace manager is implemented. The candidate runner executes a bounded
function in candidate.py; other text files are bound to its tree and inspected.
SPDX declarations and static markers do not prove licensing rights, security
or the absence of all secrets. Databases and backups may contain private keys
and must remain outside public source repositories.

## Prepublication review record: 2026-10-13

At review time, the snapshot has no approved project license or public commit. The owner must
establish publication rights and approve the exact files before publication.
CI is prepared in this snapshot but has not run on GitHub at review time. A separately
verified remote integrity ruleset targets main and blocks deletion and force
pushes; main does not yet exist. Pull request and required-check enforcement
are pending bootstrap. See docs/ADR_012_CI_BOOTSTRAP.md for the precise scope.

## Owner consent

The optional owner consent authority records expiring and revocable consent
for one exact local gate contract. It rejects worker approval flags and never
grants external publication or spending rights. See
[ADR 013](docs/ADR_013_OWNER_CONSENT.md) for the API, trust boundary and checks
that remain to implement.
