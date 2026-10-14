# Coordinated cold restore scope

The harness owns temporary owner/fake/continuity databases. With all writers
quiescent, SQLite backup creates standalone images. It refuses an incomplete
set before replacing any copies, restores original locators, then checks journal
chains, durable identities and an uncertain fake receipt. Expired/revoked rights
cannot reemit the effect; observation reconciles it in the original store.

RPO is the selected cold snapshot: a later local-only tail is intentionally
lost. RTO is measured by the private validation harness, not a service SLA.
Relocating an identical fake UUID changes its locator binding; continuity also
refuses implicit relocation. Missing/new fake UUID cannot reconcile an old effect.

This is not a production backup API. There is no global transaction across
stores, live-write coordinator, new-host credential restoration or encryption.
Never restore an owner snapshot against a later or missing external store and
infer absence as permission to repeat an effect. Preserve UNKNOWN and require
owner reconciliation. Physical fsync/disk/power faults remain unqualified.
