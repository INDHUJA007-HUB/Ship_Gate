# ADR 0012: activity-generated and estimated policies are labelled, never blended

**Status:** Accepted

IAM Access Analyzer generates a policy from *observed* access activity, and a role with no
history has nothing to generate from. The alternative — deriving a policy from the calls the
source makes — is an estimate, not evidence. Both are useful; presenting them as the same thing
would be a lie of omission, because a reader cannot tell whether a policy reflects traffic that
happened or code that might run.

**Decision.** Every candidate carries a provenance record with a method, a label, a confidence
level, and the facts behind it:

| Method | Confidence | Label shown to the user |
| --- | --- | --- |
| `access_analyzer_activity` | `observed_activity` | Generated from real access activity (IAM Access Analyzer + CloudTrail) |
| `static_estimate` | `static_estimate` | Estimated from static analysis of the source (no activity history used) |

The label and confidence live in one table in `agent/least_privilege.py`, so no surface can
invent its own wording. An unavailable attempt keeps its own method and label too: when the
activity path cannot run, the report says *which* activity attempt failed and why, instead of
omitting it and showing only the estimate.

**Cold start is a state, not an error.** A generation job that succeeds with no statements means
"no activity yet", not "failure". The engine reports `no_activity_history`, tells the operator to
run the application a few times and re-run, and falls back to the clearly labelled estimate when
the caller asked for `auto`. `--method activity` fails closed instead of substituting an estimate.

**Consequences.** A policy generated from activity is reported with its CloudTrail window and job
identifier, so a reader can judge how much traffic it represents. A generated profile that
includes access the replaced policy never granted (a role with other policies) is restricted to
the policy being replaced, and everything dropped is reported rather than silently discarded.
An estimate is never described as evidence that traffic happened.
