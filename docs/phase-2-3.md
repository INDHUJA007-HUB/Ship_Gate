# Governance and remediation: implementation and limits

This follows the phase numbering in the accepted conversation plan: Phase 2 is
governance; Phase 3 is remediation plus local validation. These differ from the
older 14-phase source reference's numbering.

## Run the reviewed IAM example

From the repository root, after `pip install -e ".[dev]"`:

```powershell
first-commit propose-iam fixtures/iam-remediation policy.json --operations fixtures/iam-remediation/operations.json --tenant local --environment development --output proposal.json
first-commit validate-proposal fixtures/iam-remediation proposal.json --tenant local --environment development
first-commit validate-runtime
```

The first command writes a NEW proposal artifact outside the submitted source,
including its diff, source hash, exact file hash, policy version, tenant, and
environment. It refuses to overwrite an existing artifact. The submitted
policy stays unchanged. The second command rechecks every condition, producing
`static_validated` or `unvalidated`. It cannot mark an app fixed or deployed.

The PR gate remains denied because runtime validation of the actual candidate
is not implemented. Unit tests separately exercise permit after trusted runtime
evidence and valid approval, needs-human-approval, and deny. The packaged SAM
smoke test is only a toolchain test; it must never count as candidate validation.

## Approval and policy behavior

Approval binds proposal ID, source hash, Cedar policy version, tenant,
environment, reviewer, and expiry. Changing any binding invalidates approval.
An approval JSON is accepted only as trusted local operator input; there is no
hosted authentication or tamper-proof approval store in this phase.

The policy defaults to deny and explicit forbid overrides permit. A malformed
policy or evaluation error denies. All IAM changes require review. This first
policy intentionally does not auto-approve uncertain auth/validation findings.

## Remediation coverage

Implemented: standalone JSON identity policies with Allow/Action/Resource;
exact reviewed operations; conservative containment over action/resource pairs;
stale/tampered proposal rejection; Python syntax parsing without execution.

Not yet implemented: automatic SAM/CloudFormation YAML patching, automatic
secret removal/rotation, framework-specific auth fixes, Access Analyzer activity
generation and CheckNoNewAccess, candidate execution in an isolated sandbox,
DynamoDB Local/MinIO replay, GitHub PR creation, or cloud deployment. None of
these are represented as passing checks.

## Failure scenario coverage

| User-supplied scenario | Current treatment |
| --- | --- |
| Source changes after approval | Source and proposal hashes rechecked; rejected |
| Wrong tenant/environment | Cedar denial plus proposal validation rejection |
| Approval expires/policy changes | Binding validation prevents reuse |
| Fix expands IAM access | Static subset proof blocks proposal |
| IAM Condition/NotAction/NotResource/Deny | Inconclusive; no guessed fix |
| No AWS activity history | Only reviewed static evidence; method explicitly labelled |
| Invalid Python/JSON | Unvalidated, with no source snippets in error output |
| Huge/deep/directory-only tree | Bounded preflight traversal, size/count/depth limits |
| Binary-only content changes | Included in source hash, invalidating proposals |
| Symlink/junction escape | Rejected during preflight and target resolution |
| Detector throws an unexpected exception | Partial results survive; exception text redacted |
| Docker/SAM missing | Runtime result blocked with specific dependency names |
| Docker/SAM fails or times out | Failed/timed_out, never passed |
| Local pass differs from AWS | Separate static/runtime/AWS evidence fields |
| Arbitrary source execution | No submitted code/import/build/test command is run |
| Zip bombs, Git URL ingestion, cancellation | Not exposed/implemented yet |
| AWS quotas, rollback, accounts, tracing, budgets | Cloud phases; not provisioned or claimed here |
| Hosted tenant isolation/authentication | Not implemented; local checks aren't an API security boundary |

## Remaining phase exit criteria

Phase 2's local Cedar decision engine is implemented and exercised against the
real native library. Phase 3's safe proposal/static-validation path is
implemented; the full phase is incomplete until candidate sandbox replay with
SAM, DynamoDB Local and MinIO runs and the supported patch formats are expanded.
The runtime machine must have Docker and SAM. Broader framework coverage and
AWS semantics cannot be guaranteed by a static subset proof.
