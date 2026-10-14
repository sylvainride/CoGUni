# Owner consent for one local gate

`ConsentAuthority` replaces the synthetic consent fixture when the trusted
controller explicitly selects `owner-consent-v1` for a new gate contract.
Existing contracts and synthetic verifiers keep their original identities.

The controller first verifies the artifact and defines the six-criterion gate
using the actual `environment_identity()`. It then grants consent for that
specific contract with an explicit expiry, at most 24 hours later:

```python
authority = ConsentAuthority(gate)
required_verifiers["consent"] = "owner-consent-v1"
contract_id = gate.define_contract(task_id, run_id, evidence_id,
                                   environment_identity(), required_verifiers)
consent_id = authority.grant(contract_id, expires_at=owner_selected_expiry)
result = gate.run_check(contract_id, "consent", {
    "executed": True,
    "artifact_sha": gate.contract_context(contract_id)["artifact_sha"],
    "consent_id": consent_id,
})
```

This is a controller API, not a worker tool. The record authenticates the
controller's decision, not the identity or presence of a human. Authenticating
the human and collecting consent through a UI remain integration work.
`approved=True`, a worker verdict, another contract with identical bytes, and
publication or spending scopes cannot replace this record. This consent never
authorizes an external effect: its only scope is `local_validation_only`.

Each immutable record contains the complete gate contract's digest, signer
epoch, implementation identity and finite timestamps. The contract binds task,
run, source and artifact versions, bytes, environment and required verifiers.
Module and gate helpers are pinned as well as the checker entry point.

The bounded consent lookup and attestation signing run in one SQLite write
transaction. A revocation before the transaction is observed by the lookup;
a revocation after signing invalidates the signed attestation. Expiry and clock
rollback also block evaluation. Expiry does not renew a lease or extend any
worker permission.

`authority.revoke(consent_id)` persists revocation and invalidates all existing
consent attestations for that contract atomically. This conservative choice
requires a fresh check if another valid receipt remains. Backup and restart
preserve grants, revocations and signing records; creating new attestations
requires reloading the authority. Old contracts cannot adopt changed verifier
code or execution mode under the same registered identity.

The new `transactional=True` verifier option is reserved for bounded trusted
controller database checks. It must never run project code, subprocesses,
network requests or arbitrary plugin checkers under the owner lock. Existing
verifiers continue to run outside that transaction. Their registration hashes
are unchanged.

The consent tests exercise actual SQLite, signatures, independent connections,
revocation/signing interleavings, expiry, backup and IPC rejection. Other gate
criteria in those fixtures remain explicitly synthetic. This lot does not
qualify real project builds, general license or secret scanners, remote
publication, Git workspaces or OS confinement. V8-02 remains incomplete.
