# Pure routing, separate authority

The router retains deterministic offline/API/CLI/browser-last planning. It is
OFF by default and an explicit flag enables only a decision. WRITE, secret data,
malformed booleans, missing permission and exhausted simulated call budgets are
refused. Every Decision has execution_authorized=False.

The immutable simulated budget can only decrease. It neither reads nor modifies
Runtime grants, leases, fences, revocations or continuity attempt budgets. An
enabled plan cannot extend any of them. Fake API faults consume one simulated
call, return bounded typed errors and perform no automatic retry; 503/504 remain
uncertain. No HTTP, provider key, cookie or browser is used.

The simulated browser reservation is released on CLOSED and FAILED. These states
prove fixture cleanup only, not cleanup of a real browser or network session.
Forty existing fixed oracle decisions are retained within one unittest method.
