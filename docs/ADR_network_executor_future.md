# Future network boundary, not activated

Keep the deterministic Bubblewrap child unchanged: no network, credentials,
browser, owner database or external connector enters that child. A future
network executor must be a separate reviewed owner-broker service with explicit
provider/domain/operation scopes, finite leases, revocation/fencing, payload and
rate limits, redacted observations and bounded process/session cleanup.

Read-only smoke tests precede any separately authorized mutation. Unknown or
lost acknowledgements require source-bound receipts and reconciliation; they
never justify blind retries. Browser authentication and API grants are distinct
authorities. Do not extract page credentials, reuse cookies across domains, or
infer necessity from a planner's availability flag. Browser use needs a measured
reason and a dedicated isolation profile; closing or failing must release it.

No executor, OAuth flow, remote service, browser dependency or network allowance
is installed by the current module or this design document.
