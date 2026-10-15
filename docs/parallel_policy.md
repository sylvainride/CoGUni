# Owner admission policy

`universal.parallel_policy` computes an inert, deterministic admission decision.
It has no database, executor, token, timer, network client, consent authority or
outbox. `Decision.execution_authorized` is always false for calculated decisions.
The persistent owner facade must read its authoritative journal, calculate and
reserve under the existing CAS/fence, recheck actual permissions and immutable
sources immediately before dispatch, then use the existing runtime. A worker
result cannot populate authoritative owner states or authorize target effects.

`Access` binds provider, numeric repository identity, project identity, source ref,
canonical absolute path, read/write mode, expected SHA and owner-defined physical
target. Physical targets override branch names: two branches targeting the same
resource conflict. Project/repository/provider changes for one physical identity
are rejected. Versions are lowercase 40- or 64-character hexadecimal values;
immutable reads additionally address that exact version in `ref`.

The host must resolve or reject symlinks and resource aliases before construction.
The pure function performs no filesystem resolution. Owner-only alias tuples
can map several mount/target names to one physical identity. Optional owner case
policy applies to canonical target identities. Parent/child paths, including the
resource root, overlap; adjacent names and disjoint children do not. No branch
spelling, payload or worker assertion can override that owner policy.

Only two pinned immutable reads may share an overlapping claim. Mutable reads
conservatively retain their claims, including against other mutable reads. An
immutable read and a live write also serialize. Distinct proposals can compute
in parallel when they claim independent output resources; later application to
a common physical integration target must use a separate serialized stage. A
`READ_SOURCE` or `COMPUTE_ONLY` stage cannot claim a write.

`select_ready` defaults to disabled, two slots and zero unreserved budget. Owner
opt-in permits one to eight slots; backlogs are bounded to 128 by default and 256
at most, with at most 32 dependencies and 32 accesses per task. The explicit
budgets count remaining unreserved runs and aggregate runner seconds, not elapsed
wall time. A task that does not fit is held; a later smaller independent task can
fit. The caller must durably decrement/reserve budgets when dispatch is claimed.

The shared iterative DAG validator rejects cycles, duplicates and dangling
dependencies. Only `ACCEPTED_APPLIED`, recorded after independent owner proof,
target CAS and readback, satisfies dependencies. `IN_FLIGHT`, `RESULT_READY`,
`APPLY_PENDING`, `UNKNOWN_EFFECT`, `SUSPECT` and `HANDOFF` retain resources and
slots. Reducing budgets, permissions or parallelism never releases these claims.
No automatic retry, cancellation or effect follows from a decision. Reconcile an
uncertain effect against its exact original outbox record before releasing it.

Tests cover both positive admission and refusals, including 256 randomized
completion/reconciliation/crash-reload interleavings and 500 randomized resource
sets checked against an independent component-prefix footprint oracle. These
tests establish policy invariants only, not provider authentication, physical
crash durability, remote execution overlap or native Chat connectivity.
