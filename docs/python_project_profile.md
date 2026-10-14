# Flat Python mini-project profile

Owner policies explicitly select `python-project-v1`. Legacy function policies
and deterministic SHA mode keep their contracts. Up to eight flat `project_*`
modules (48 KB total profile input) can import one another. Owner unittest cases
declare module/function/arguments and keep expected values in the parent. Every
case gets a fresh bwrap child with the existing namespaces/seccomp/hard limits.
There is no unconfined fallback. Candidate `test_worker.py` is inert tree data.

The existing GenerativeValidator registers immutable policies, binds the exact
tree/source/run/environment, rechecks grants/fences after checks, and signs only
the resulting criteria. No second signer or worker authority is introduced.

Compile/AST, configured literal marker and SPDX identifier checks are bounded;
SPDX is not legal license certification. No dependency installation, package
build, shell, network, arbitrary unittest discovery, or general repository
runner is supported. Unsupported paths are refused, not silently executed.
The profile is opt-in and does not connect an LLM or authenticated Chat receiver.
