# Passive persistent foundation (P4)

This package is a **passive owner-host API**, not an installed agent. It adds no
daemon, cron, background worker, OAuth, LLM, GitHub writer or remote receiver.
It must not be used as a production authorization boundary without an
independently authenticated owner integration.

## Components and responsibilities

- `persistent_provider_observation.ProviderObservation` strictly validates a
  bounded readback and compares it with the **current OwnerScheduler** journal
  binding. Constructing the type or setting a field is **not** evidence that a
  provider or human has been authenticated. Only a trusted owner host may inject
  `provider_reader`; never pass worker, user-uploaded or public-PR JSON as the
  reader.
- `persistent_supervisor.PassiveSupervisor` consumes a finite explicit set of
  task IDs. It reuses `OwnerScheduler.status/ready/observe`,
  `mission_liveness.classify`, and `mission_polling.plan_read`. Each qualified
  observation is committed through the **original** ContinuityJournal CAS/event
  receipt. Stable owner read IDs permit same-store lost-ACK lookup without
  another durable poll. No dispatch, lease recovery, acceptance, application,
  cancellation or write retry is exposed.
- `persistent_resume.export_resume/validate_resume` produces canonical bounded
  **NONE-authority** references, with a non-secret integrity digest. It refuses
  stale source/contract/revision/fence/provider states and foreign journal IDs.
  The original journal protects its SQLite locator and UUID; copied SQLite
  files do not become a new owner of an old mission.

`HealthReadback` is an independently sourced observation provided by the owner
host, **not** proof of a live lease. Healthy silence only classifies as
`SILENT_RUNNING` when both provider and supervisor readbacks match an active
owner reservation. Missing evidence remains `SUSPECT_RECOVERY` or `UNKNOWN`.
Provider success alone remains `UNKNOWN` without the owner-verifiable artifact
and target readback; `RESULT_READY` never implies `ACCEPTED_APPLIED`.

## Sketch for a future qualified host (not a deployed integration)

A trusted owner host must reopen the **same** canonical
`ContinuityJournal(path)`, instantiate `OwnerScheduler` with its unchanged
owner-verified policy and read-only checkers, and construct
`PassiveSupervisor(scheduler)`. It may call
`tick(("task-id",), provider_reader=trusted_reader, now_unix=owner_now,
max_observations=1, max_duration_ms=1000)`. The host is responsible for
verifying provider identity, trusted callback provenance, ACL, ref and source
pins at the real provider boundary; a Python callback is not that boundary.

For a stop/restart, `export_resume(scheduler, ("task-id",))` returns a hint that
another process can pass to `validate_resume` only after reopening that same
SQLite journal and reconstructing the same owner policy. An invalid hint must
not trigger submission or replay. Persist the hint privately; do not place
owner journal bytes, database paths, real receipts or credentials in GitHub.

## Safety and test scope

Only local synthetic stores and readbacks are exercised. The P4 modules do not
create a second task store, scheduler, outbox, authority or permissions layer.
Resource collision and budget accounting remain exclusively in
`parallel_policy` and `OwnerScheduler`; ambiguous effects remain
`UNKNOWN_EFFECT`, with same-store receipt reconciliation by the authorized
existing runtime. A timed tick bounds **admission to reads and subsequent
actions**, but cannot interrupt a blocked externally injected synchronous
reader; deployers must enforce actual per-request deadlines outside this
module. A silent provider and a closed Chat conversation do not authorize
cancellation. CI runners and local tests are not a deployed persistent host,
and provide no autonomous AI inference or Chat wakeup guarantee.

These new tests are discoverable by the full `test_*.py` suite. Existing
owner-contracts subsets may not include them. Any stacked PR preflight failure
caused by a branch-specific CI policy remains a separate Passe 3 blocker; do
not relax .github workflows, rulesets, or isolation.
