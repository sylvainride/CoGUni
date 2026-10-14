# Owner-side defensive checks

LocalWorkspace.advance rechecks the actual candidate diff and text modes before
its local CAS, even when a trusted caller constructs Candidate directly. This
adds defense against owner API misuse; it does not authorize remote publication
or protect a private Git database from an attacker with the same OS identity.

If rollback itself fails, transaction helpers preserve the original exception,
attach a sanitized cleanup note, and close the poisoned connection. The caller
must reopen and reconcile state before further work. Synthetic rollback faults
are distinct from physical disk or fsync qualification.
