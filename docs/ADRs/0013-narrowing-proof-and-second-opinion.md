# ADR 0013: a candidate is offered only when its narrowing is proved

**Status:** Accepted

A remediation engine that says "here is a safer policy" is making a security claim. The claim has
two halves: the candidate grants nothing the original did not (containment), and it grants less
than the original (strictness). Either half alone is not enough — a policy that grants nothing is
contained but useless, and a policy that removes one action while adding another is smaller on
paper and wider in practice.

**Decision.** The local subset proof is the authority for the containment claim, and strictness is
required in the same evaluation:

1. `check_no_expansion(original, candidate)` must conclude `safe`, not merely "not obviously
   wider". `inconclusive` (for example an original statement that carries a `Condition`, or
   `NotAction`/`NotResource`) is reported as `inconclusive`, and the candidate is offered only as
   `needs_review`.
2. At least one action or resource the original allowed must be gone. Otherwise the verdict is
   `not_narrower` and nothing is offered — an already least-privilege policy never produces a
   "fix" that changes nothing.
3. AWS `CheckNoNewAccess` is a second opinion, requested explicitly (`--verify aws`). It can only
   strengthen the result: when it reports new access, the candidate is rejected. When it says
   `PASS`, the report says which rule established containment, so a local proof is never described
   as an AWS one.

**Placeholders.** With resource placeholders enabled, Access Analyzer may return
`arn:aws:s3:::${BucketName}` instead of a concrete ARN. The proof substitutes the widest value
(`*`) for any placeholder, so an unknown scope can never pass as a contained one, and the report
counts the placeholders and asks for them to be resolved before applying.

**Consequences.** A candidate is never offered as "recommended" unless it is provably narrower,
and every rejection carries a bounded reason code (`candidate_expands_access`,
`candidate_not_narrower`, `local_subset_proof_inconclusive`, `aws_check_reports_new_access`,
`generated_policy_outside_target_scope`). Nothing in this phase writes a file, a role, or a
deployed policy.
