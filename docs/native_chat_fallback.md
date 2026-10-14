# Read-only fallback and actual capability scope

A connected GitHub tool may create an authorized reviewed code PR and read its
CI results. This proves only that code-review CI path in the current session.
It does not connect the offline mission fixture to a live broker, authenticate
a human mission, or promise work after the Chat session ends.

If native workflow dispatch or a mission receiver is absent, record BLOCKED_TOOL
for mission execution. For manual observation:

1. Open the known CoGUni PR and record its head and current base SHA.
2. Read the associated run, event/ref and required owner-contracts/sandbox-runtime
   jobs. Pending, skipped, missing or failed jobs do not qualify the change.
3. Read the bounded JSON summaries in job logs. Bind their source commit/tree
   to the tested PR merge tree, rather than assuming the displayed head was run.
4. After an authorized merge, read main and its independent push run. Compare
   the final tree and rerun required checks if it differs.

This observation procedure adds no dispatch authority, credentials, paid API,
permanent service, owner consent or automatic retry. The CLI and provider UI
remain human-operated alternatives under the same repository protections.
