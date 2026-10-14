# Developer instructions

Inspect the current source and existing changes before editing. Keep strict
SHA validation and explicit opt-in policies. Preserve scopes, leases, fences,
proof freshness and mandatory isolation. A worker verdict is not evidence.

Use existing tests appropriate to the change. Record the source version,
commands, environment, failures and unexecuted checks. Do not claim a passing
subset validates the whole runtime. Never weaken isolation to make tests pass.

Before external operations, resolve the authorized repository, immutable ID,
remote, branch, base SHA and actual permissions. These instructions are not a
server-side repository lock. Such a lock is still a runtime implementation task.

Keep private archives, state, credentials and logs out of commits. Obtain the
owner's approval for the concrete public snapshot and license. Do not copy an
old private Git history into the public repository without a separate audit.
