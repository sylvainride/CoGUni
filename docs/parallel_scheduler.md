# Bounded owner scheduling API

`OwnerScheduler` is a trusted host facade over the existing ContinuityJournal.
It adds no database schema, signer, outbox, remote receiver or worker opcode.
The constructor is disabled by default. The synthetic demonstration explicitly
opts in with max_parallel=2. Run count, aggregate reserved seconds, poll count,
backlog, code/source pins and finite observation leases are immutable owner
policy. Reopening with a different policy does not reset spent reservations.

The API is `submit`, `ready`, `reserve`, `observe`, `accept_applied`, `renew`,
`recover`, `reconcile`, `cancel_queued`, `status`, `handoff`. `ready` returns an
inert plan; it does not dispatch or grant permission. The host reserves under
SQLite BEGIN IMMEDIATE before calling its actual GitHub connector. Both resource
selection and queue insertion are atomic with existing receipts/events. Lost
submit ACK preserves the reservation: query the exact immutable commit/run,
never submit another workflow merely because a Chat response is absent.

The owner supplies reviewed `check_current(work, metadata)` and
`check_applied(work, metadata, provider, evidence)` functions. The first checks
current ACLs, immutable code/source, project/ref identity and expected versions.
The second independently checks the qualified provider artifact and actual host
CAS effect/readback. These are executable trusted host code, not JSON booleans
or worker assertions; never expose them to untrusted mission payloads. Timestamps,
lease/fence, TTL and sources are rechecked after callbacks. Host connector writes
still require their own fresh provider CAS: SQLite cannot lock a GitHub branch.

Jobs retain slots/resources in IN_FLIGHT, RESULT_READY, APPLY_PENDING, UNKNOWN_EFFECT,
SUSPECT or HANDOFF, even if lease expired or permissions later changed. Only
independently checked ACCEPTED_APPLIED releases a dependency. Result-ready or
provider green alone never does. A queued cancellation is distinct from killing
active work. Reconciliation only reads the original binding, or qualifies an
UNKNOWN_EFFECT through the same independent original-effect readback; neither
path dispatches or writes a target. Generic uncertain external writes continue
to use the existing Outbox and its exact backend contract.

Finite lease renewal cannot add attempts, restore spent budget or exceed the
original job deadline. After an expired lease the owner can explicitly recover
observation control with a new fence and the same provider binding, without
redispatching. The stale controller cannot accept/apply using its former fence.
Source drift of scheduler/policy/DAG/Continuity/core or a pinned job input blocks
continuation. A polling/retention/network failure requires UNKNOWN/SUSPECT or
handoff, never an inferred absent effect.

For a private host integration, open its existing owner journal and create
Access/Work records from reviewed project profiles. Resolve physical targets,
symlinks, aliases, case policy, current permissions and versions before using
this API. The pure policy cannot discover them. Two refs aiming at one physical
effect domain must share its physical_id. Git-only test branches may be explicitly
registered as distinct fixture domains; this is not proof that two branches of
a production application are independent physical targets.

The GitHub fixture adapter remains separate: public packet v2 INDEPENDENT allows
A/B on isolated branches; DEPENDENT keeps D on A's branch and reuses the strict
predecessor source/branch/run/code_ref/readback gate. No cross-branch dependency
protocol or arbitrary target application is installed. The host alone applies.

The runbook permits useful independent work C while provider jobs execute, then
bounded observations. It installs no timer, background Chat, model or permanent
service. At a real turn limit export handoff and ask “Écris reprise pour continuer”.
