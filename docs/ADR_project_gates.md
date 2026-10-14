# Bounded project fixtures reuse the V8 policy runner

The normalization fixtures exercise the existing owner-side policy runner and
GenerativeValidator. Their source is projected from `worker.py` to the required
`candidate.py` entrypoint without changing behavior. Owner unittest cases freeze
the expected values. Candidate test files are inert artifact data and cannot
replace the oracle. Function execution requires Bubblewrap, fresh child nonce,
actual Git tree, context digest, and the existing hard limits.

The owner validator rechecks source/output versions, policy, grants, lease,
fence and signing epoch after execution and final Git I/O. A passing unsigned
runner result is not authority. Output mutation, including equal-byte new
versions, invalidates the signed proof and downstream lineage.

This is a bounded Python-function profile. Arbitrary project unittest discovery,
build commands, third-party dependencies and release certification require a
separate reviewed profile. There is no unconfined project subprocess fallback,
second signing authority, extra dependency, or change to the strict default.
