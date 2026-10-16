# Public synthetic mission transport MVP

`python -B -m universal.mission_cli --state PRIVATE_STATE --targets PRIVATE_TARGETS --owner OWNER`
reads one bounded JSON request from stdin and emits one JSON response. The state
and target roots must be canonical directories owned by the current uid, mode
0700. A local owner process is the authority. This is not a remotely exposed
server or an authenticator for arbitrary JSON senders.

The methods are `mission.submit`, `mission.execute`, `mission.status`,
`mission.result`, `mission.ack`, `mission.cancel`, `mission.revoke`,
`mission.reconcile` (no effect replay), and `mission.handoff`. Every request has exactly
`schema_version: 1`, `method`, `params`. Submission parameters are `envelope`
(existing mission-contract v1), `payload`, `action` and `code_ref`. Other methods
use `project_id`, `mission_id`; ACK additionally requires `artifact_sha256`.

Only public synthetic projects A/B, allowlisted ASCII payloads and deterministic
uppercase/SHA256 are enabled. Project kind is metadata, never a grant. The
runtime does not receive target connector tokens. No model, network instruction,
worker-provided approval or arbitrary command is executed.

The existing ContinuityJournal stores immutable envelopes, source pins, finite
leases, attempts, CAS and operation receipts. The existing Runtime stores exact
input/output contracts and proofs. The optional broker `task_id` filter limits
both claims and pending verification to one task. Filesystem locks serialize
execute/ACK/cancel/revoke across processes; SQLite transactions preserve the
existing records. There is no new mission database schema or parallel outbox.

Execution produces a candidate in mandatory Bubblewrap/seccomp isolation. A
separate verifier and the current Runtime proof predicate qualify its content.
COMPLETED means computation was verified, not target acceptance. The host applies
the proposal itself. ACK re-reads the fixed project result file without following
symlinks and computes an independent expected value. Only then does the owner
close the scheduling task as completed. A subsequent read rechecks proof and
current target; changing either invalidates current acceptance. Revocation has a
durable journal receipt even after closure and invalidates existing evidence.

A duplicate submit returns the same scheduling task; conflicting content fails.
Lost execute ACK attaches to the existing run, never resets it. Reconciliation can finish only the existing confined verifier for an already committed RESULT_READY output; it never reclaims a READY/RUNNING task. An expired lease
alone gives SUSPECT, not a new worker. Safe cancel is allowed before dispatch.
Revoke removes authority without pretending a process has been killed. Generic
uncertain external writes remain the existing Outbox reconciliation contract;
this CLI performs no such write and offers no blind retry operation.

While running, the controller identity binds Linux boot identity, PID and start
ticks. Status checks that identity independently of stdout and the finite lease.
This observes the local controller; it is not proof of every descendant or a
service health SLA. The GitHub caller separately observes provider run/jobs.
Silence alone never causes cancellation. Reads are finite; a final handoff gives
exact IDs and requests “Écris reprise”. No prompt keeps an inactive Chat alive.

## GitHub adapter

The reviewed CI workflow has an optional step only for owner pushes to branches
`work/mvp-mission-transport-*`. Permissions remain `{}`. There are no secrets,
write tokens, external deployments or privileged triggers. The adapter processes
only `tests/fixtures_mvp_transport/request.json`, rejecting any executable source
change relative to the pinned `code_ref` in a request commit. Repository ID,
owner, actor, ref, event and checked-out source must match trusted provider
context. Local environment variables alone do not authenticate a remote sender.

The request commits and public job log receipts form the exchange. Result
receipts bind provider run/attempt, actual commit, request fingerprint, runtime
run/evidence and artifact digest. The host must inspect provider job success and
fetch the actual receipt; a title or worker PASS is insufficient. Mission B
requires the successful exact A provider run and independent readback of A's
synthetic target bytes. The adapter never writes a target.

GitHub runners and SQLite files are ephemeral. This adapter does not promise a
shared database, exactly-once computation across workflow reruns or permanent
log retention. Repeating a workflow can repeat a harmless deterministic
calculation; it never applies a target effect. Durable cross-process local
sessions use the CLI's original private stores. Request/target Git commits are
durable provider records while their refs are retained.

The invoking Codex host can use these tools in an active session. This does not
prove installation or invocation from a separate native ChatGPT Project. That
last calibration must be performed in that Chat with its available GitHub tools.
No MCP app or persistent scheduler is installed by this code.
