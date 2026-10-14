# Security boundaries

The owner process, interpreter, operating system and controlled bootstrap are
trusted. Workers receive only bounded IPC tasks. Untrusted children require
the mandatory Linux isolation profile; there is no unconfined fallback.

Keep secrets, production databases, backups, logs and historical archives
outside this source tree. Do not run untrusted forks with write tokens or
secrets. A local HMAC or passing fixture does not certify a complete product.

The CI context preflight checks one repository identity and checkout SHA. It
does not implement runtime broker binding, remote effects, web sessions or a
release approval gate. Branch protection must be checked on the real remote
repository. Its configuration is separate from this document.

Report suspected vulnerabilities privately to the repository owner once a
private reporting channel is available. No reporting address is configured
in this unpublished review snapshot.
