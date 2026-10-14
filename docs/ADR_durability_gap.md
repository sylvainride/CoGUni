# Extend failure tests, preserve the existing owner stores

Runtime, ContinuityJournal and FakeAdapter each own a SQLite transaction path;
Outbox coordinates separate owner and fake-effect commits. Existing receipt,
fencing, revocation, store-identity and crash tests are retained. No second
controller, journal or outbox is added.

SQLite may automatically abort a transaction on SQLITE_FULL/IOERR. A subsequent
unconditional ROLLBACK masks the original storage error. The three transaction
helpers now roll back only while their connection is still in a transaction.
They still propagate the failure, never convert it to a successful result.

Capacity probes use actual max_page_count on disposable stores. Commit IO failure
is injected at a controlled boundary; it is not a physical fsync or power-loss
test. Separate processes exercise WAL lock timeout and fenced claims. Coordinated
SIGKILL tests cover an uncommitted owner write and a fake effect committed before
ACK. These are trusted owner processes, not new untrusted worker execution paths.

The fake store is an isolated local simulation. Unknown effects require matching
store identity and reconciliation. A revoked run cannot emit again, and an
observed fake receipt never certifies an artifact or a remote provider effect.
Physical disk failure, multistore consistent backup, long endurance and measured
RPO/RTO remain separate qualifications.
