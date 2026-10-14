# Current policy scope

The six existing runner criteria are tests, lint, security, licenses,
provenance and environment. Tests compare computed JSON against owner cases;
lint compiles Python AST; security checks configured literals and a bounded AST
policy; licenses check the actual LICENSE file for one allowed SPDX identifier.
These scans are limited checks, not complete secret detection or proof of legal
rights. Provenance requires actual tree/nonce/context binding; environment
requires qualified confinement. FAIL, UNKNOWN and NOT_RUN never satisfy required
criteria.

Permission is checked separately by the owner runtime: current grants, output
lease, fence, policy and source pin. GateEngine owner consent remains a distinct
contract-scoped, expiring authority. A fixture result or an SPDX string does not
authorize publication or an external effect.

The normalization profile in tests is explicitly opt-in and synthetic. It
supports the existing single-function entrypoint only. Candidate-controlled
unittest files remain unexecuted; the owner unittest suite drives independent
cases through the confined runner.
