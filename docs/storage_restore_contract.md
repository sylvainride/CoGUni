# Restore must preserve each store identity and uncertainty

Owner Runtime, ContinuityJournal and fake-effect stores have different roles.
Their independent transactions do not form a distributed atomic snapshot.
Freeze dispatch before backup, record each store's UUID/locator and known receipt
keys, then verify integrity and journal chains on private copies. A SQLite backup
alone cannot prove that all separately committed effects are included.

Reopen each store at its authorized locator. Fake and continuity stores reject
silent relocation; an owner runtime backup does not grant rebinding a pending
outbox intent to another fake store. Reconcile uncertain attempts against their
original UUID/locator before any retry. A missing acknowledged effect, wrong
store, stale fence, expired grant or revoked run blocks emission.

The SIGKILL recovery and store-mismatch tests qualify bounded local behavior.
They do not demonstrate a coordinated multistore restore, physical fsync
durability, encryption, a new host deployment or production RPO/RTO. Such a
restore requires a separately executed protocol and current owner authorization.
