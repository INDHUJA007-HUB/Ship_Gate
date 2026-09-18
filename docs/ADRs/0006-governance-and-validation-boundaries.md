# ADR 0006: conservative remediation and separate validation evidence

Status: Accepted. Date: 2026-09-11.

Use cedarpy 4.8.7 to execute the real Cedar engine locally. It is a third-party
binding to Cedar; pin it and verify the native wheel on each CI OS/Python pair.
Policies ship inside the application package and are hashed into decisions and
approvals. Never use a policy from the scanned repository.

All IAM PR operations require explicit approval, static validation, a proof of
no access expansion, and runtime validation of the actual candidate. Unknown
environments, cross-tenant requests, stale input, Cedar errors, and unknown
actions deny. Direct commits, merges, and deployment deny in this phase.

The first implemented remediation format is a standalone JSON identity policy.
Exact action/resource pairs are supplied as reviewed evidence. Generation is
labelled static, not derived from activity history. Conditional policies,
resource policies, explicit Deny, NotAction and NotResource require further
analysis and return inconclusive. No automatic relaxation of this boundary.

Static validation parses Python without importing it and checks patch hashes
and policy containment without writing the submitted tree. It does not prove
AWS IAM or application behavior. A packaged SAM harness can test the local
runtime installation, but its result never authorizes a user's proposal.

The proposal and approval objects are local trusted-operator inputs. They are
not signed attestations or hosted tenant authentication. A future API must
obtain identity, approval, and validation facts from protected server state.

References: https://github.com/k9securityio/cedar-py and
https://docs.cedarpolicy.com/auth/authorization.html
