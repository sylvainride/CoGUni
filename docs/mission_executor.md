# Bounded synthetic mission executor

`DeterministicExecutor(runtime_path)` is a trusted owner facade over the existing
SQLite `Runtime`, mandatory Bubblewrap/seccomp broker, owner-pinned deterministic
SHA verifier and current-proof predicate. It adds no database, schema, signer,
worker opcode, external service, secret or model call.

`prepare(key, payload, action='uppercase')` atomically provisions a stable task
identifier derived from the complete key/payload/action tuple. Repetition reads
the same immutable contract without adding resources, events or tasks. A changed
tuple is a different contract: the transport must enforce its own immutable
mission-key binding before calling this owner API.

The payload is at most 256 ASCII characters: letters alone, or `synthetic:`
followed by letters, digits, `.`, `_`, `:`, or `-`. The only actions are
`uppercase` and `sha256`. Inputs are inert strings and never commands or code.

`run(task_id, timeout=30)` has a maximum 60-second budget. It calls the existing
broker with an exact task filter, one worker and one job. Both ordinary claims
and recovery verification honor that filter. Other READY/RESULT_READY tasks are
untouched. RUNNING work is observed without resetting or launching another job.
Committed local output can be verified after ACK loss without replaying its
write. Failed, abandoned, revoked and stale work is never silently reset.

`result(task_id)` re-reads the original owner store under one transaction and
rechecks the proof in the current source/environment identity. It returns task
and run identities, evidence identity, bounded content, output SHA/version,
environment, raw task status and `accepted_for_gate`. `status='COMPLETED'` is
reported only with a currently accepted owner proof. Worker PASS text and a
transport ACK cannot establish completion. No token or grant is exported.

Timeout and unavailable isolation propagate as failures; the owner store stays
available for reconciliation. A silence observation alone neither proves a
failure nor authorizes retry. Transport permission, project identity, expiry,
revocation, target version checks and external-effect reconciliation belong to
the durable mission controller. Accepted local computation does not authorize
applying a target-project change or publishing remotely.

Owner tests use explicit mocks only for failures/forged worker claims. Separate
isolation tests execute actual confined workers and verifiers, test exact task
selection, committed-write recovery, replay and concurrent single application.
The general runner and arbitrary software development remain out of scope.
