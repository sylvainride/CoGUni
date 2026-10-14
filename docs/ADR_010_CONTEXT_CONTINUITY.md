# Local scheduling journal

ContinuityJournal uses a separate owner-controlled SQLite database. Contracts
and structured checkpoints preserve constraints, decisions, sources, criteria
and permitted actions. Leases, fencing, compare-and-swap and receipts bound
retries and local budget consumption.

The journal launches no tool, shell, model, service or background activity.
OWNER_COMPLETED records scheduling completion and never validates an artifact.
Hard quota remains blocked until explicit capacity or a preauthorized alternate
tool is declared by the owner. It does not change a platform quota.

Source hashes are observations, not filesystem locks. UUID and canonical path
bind the journal to its original location. Administrator rollback, relocation,
storage failure, encrypted backup and remote effects require separate controls.

The test module and continuity simulator contain local scheduling fixtures,
including real process crashes around database commits. They are control tests
and provide no model-quality benchmark.
