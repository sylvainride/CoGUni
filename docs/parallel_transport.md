# Parallel public synthetic mission transport

The public adapter continues to use `MissionClient`, its existing owner journal,
runtime, isolated computation and independent verifier. No worker, credential,
target writer, paid API, service or network permission is added. Provider identity,
the fixed workflow step, immutable source/code pin, ordinary fixture files and
the bounded public payload rules remain mandatory.

Version 1 is unchanged: project A has no predecessor; project B requires the
verified A predecessor. Version 2 is an explicit transport routing opt-in:

```json
{"schema_version":2,"request":{},"predecessor":null,"mode":"INDEPENDENT"}
```

`request` must be a complete existing synthetic request, not the empty example.
These are the exact four outer fields. `INDEPENDENT` accepts synthetic A or B
with no predecessor. The owner submits each independent mission on its own
`work/mvp-mission-transport-*` branch, pinned to the same reviewed executable
source if shared. The existing `request.json` path is a single slot on each
branch; pushing competing requests to the same branch is not parallel dispatch.
The owner scheduler must check resources, budgets, ACLs and current versions
before dispatch. A routing flag alone does not prove independence or confer a
permission.

For a dependent mission D, use `mode: "DEPENDENT"`, project `synthetic-B`, and the
existing predecessor tuple `request_commit`, `provider_run_id`,
`artifact_sha256`. D remains sequential on A's branch. The adapter requires A's
exact successful push run, repository/actor identity, reviewed code pin and
qualified sandbox step on that **same branch**, then verifies A's changed base
and actual target bytes independently at D's checkout. A cross-branch provider
run, stale source, missing CI step or unapplied A result refuses before execution.
Cross-branch dependency promotion is not implemented. B's independent branch
does not grant D a right to read or apply B's result.

A v2 receipt includes `schema_version: 2` and `mode`; its existing request hash
covers all four fields. `RESULT_READY` attests a verified computation, not an
applied target or a connected Chat session. The authorized Chat/owner must
independently verify the result, use its existing CAS path to apply the benign
target change, and read the exact target back. Provider log retention remains
finite, and no background Chat wake-up mechanism is installed.

`tests/test_parallel_transport.py` covers v1 preservation, strict v2 routing,
independent A/B admission, dependent D's readback gate, missing steps and
branch/source/identity spoof refusals. Its MissionClient mocks isolate transport
routing; they are not confinement or live GitHub evidence. Existing runtime and
isolation tests and exact-source CI must still pass; real provider/Chat recipe
evidence is recorded separately.

## Push admission and retained packets

The presence of `request.json` alone no longer admits a mission. The adapter
binds the injected GitHub push event's repository, sender, ref and `before/after`
to the provider source and actual checkout. It inspects every Git transition in
a forward linear range of at most 64 commits, fetching immutable history from
the fixed public repository without credentials. Event file lists are not used.
Only the existing three inert fixture paths may change in that range.

An introduced or changed request enters the existing strict client, including
TTL, source, target base, isolation and dependency validation. Any request edit
within a multi-commit push counts, even if later reverted or deleted/restored.
Writing identical bytes with the same ordinary file mode has no Git change.
New malformed or stale requests fail; a simultaneous target edit cannot turn
them into a skip. A retained packet still has its bounded ordinary Git blob,
checkout bytes, packet shape and cumulative executable code pin checked, then
returns `SKIPPED_UNCHANGED_REQUEST` with `business_executed: false`. This receipt
has no business result, predecessor acceptance or new application authority. It
does not assert that an older execution succeeded or that an effect occurred.

Absence/deletion returns `NOT_SUBMITTED` after provenance/range checks. Branch
creation without a packet is also neutral; copying a branch with an existing
packet is ambiguous and refused. Submit a new request in a subsequent ordinary
commit. Forced/nonancestor pushes, merge commits, missing history, overlong
ranges and incomplete events fail closed. Required CI jobs still run and the
mission concurrency policy is unchanged. No cross-run exactly-once store is
introduced: explicit reruns of the original request run can recompute; target
effects remain owner-controlled CAS with original-effect reconciliation on an
unknown ACK. `tests/test_public_mission_admission.py` exercises real local Git
trees and real owner admission, with worker execution mocked; provider and
isolation evidence must be qualified separately.
