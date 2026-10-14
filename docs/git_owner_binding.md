# Owner Git binding and promotion boundary

GitOwnerBroker resolves the fixed repository and authenticated current actor
from three read-only GitHub endpoints. It pins ID/node/owner/main/tree and checks
pull/push permissions, refusing renamed/transferred repositories or base drift.
No worker opcode exposes the provider or lets the worker select a destination.
No token is discovered, created, returned, or passed into candidate sandboxes.

An inert promotion plan additionally requires existing owner-signed generative
evidence covering every changed path of a bounded project projection. Blob modes,
content, candidate parent/tree and proof freshness are rechecked. Unrelated base
files are outside that project proof. The plan has execution_authorized=false.

There is no remote write executor, remote atomic CAS, automatic PR manager or
authenticated human receiver. An observed push permission and local-validation
consent do not grant remote execution. A future executor must enforce its own
bounded grant/revoke/fence, negotiated remote expected-head update, current base,
required CI/virtual merge and actual post-main proof. Do not emulate CAS with an
unconditional REST update-ref or enable force-push. Session development PRs are
ordinary owner operations, separate from a deployed autonomous runtime broker.
