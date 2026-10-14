# Local Git object workspaces

LocalWorkspace is a disconnected owner-only preparation API. The caller first
verifies GitHub repository/node/owner identity, canonical remote, main base/tree,
and permissions. RepositoryBinding rejects other identities. The module checks
the trusted source checkout's remote and HEAD and copies only the pinned commit
into a private bare Git database. It does not fetch a remote, execute candidate
code, read worker files or alter the source checkout/main.

Patches are bounded text data in an exact path allowlist. Git hash-object and
an isolated index construct real blob/tree OIDs. No patch is written through a
filesystem path, so symlink swaps in a worker checkout cannot redirect a write.
Symlink/executable allowlisted base entries and binary replacements are refused.
Renames are explicit allowlisted deletion/addition pairs. Unlisted paths remain
in the tree unchanged. A finite owner lease is checked before preparation and
before atomic update-ref with the expected parent. A conflicting writer gets
an explicit error; it cannot overwrite the winner.

The supplied validated tree is an owner observation, not an authenticated
attestation. No worker API, production broker integration, durable remote lease,
GitHub ref update or publication authority is added. Before PR publication the
owner must re-resolve live repository/base/permissions, bind actual signed gate
evidence, and test the merged tree. Rebase/merge/revert requires another proof.
The private database must not be writable by an untrusted process; this API
does not claim to isolate hostile same-UID processes or a hostile source Git DB.
