# Mission transport remains disconnected

The pure CI metadata contract is a narrow parser of owner PR observations. It
pins repository/owner identity, actor, PR merge ref, head/base/merge/tree and run.
The caller must obtain these observations from the trusted provider. The parser
does not authenticate their origin. Public titles, bodies, arbitrary payloads,
keys and claimed signatures are not accepted. An inert CI receipt carries
observations only; PASS and a digest grant no dispatch or publication authority.

The existing offline hash mission remains a synthetic function. ConsentAuthority
is the sole existing owner consent path and is scoped to local_validation_only;
it does not authenticate a Chat human. No mock HMAC, second nonce database,
production event receiver or privileged workflow is introduced.

A future mission receiver requires authenticated provider delivery, a durable
nonce/idempotency record bound to the immutable owner contract, TTL, explicit
action scope and revocation/fencing. Use existing continuity receipts for owner
scheduling and existing outbox reconciliation for uncertain effects; do not
infer a remote grant from either. On lost ACK read the known run/ref receipt
first; mismatch or incomplete evidence remains BLOCKED/UNKNOWN. Never emit a
second effect merely because a Chat reply is absent.
