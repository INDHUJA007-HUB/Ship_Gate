# Governance policies

The installed policy source is `agent/policies/remediation.cedar`; keeping it
inside the Python package includes it in wheels. Never load policy files from
the repository being scanned. Cedar has deny-overrides-permit semantics and
default deny. A separate review authorization distinguishes a missing approval
from an outright denial. Evaluation errors always deny.

This phase prepares proposals and authorizes a future PR operation. It does not
implement GitHub writes, deployment, or hosted identity verification. The local
operator supplies trusted tenant/environment facts; a future API must derive
these from authenticated server state, never request-body claims.
