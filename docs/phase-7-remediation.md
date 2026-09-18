# Phase 7 — least-privilege remediation engine

Phase 7 turns an over-broad identity policy into a strictly narrower, reviewable one. The
interesting part is not calling IAM Access Analyzer; it is that Access Analyzer can only generate
a policy from *observed* access activity, and a freshly scanned or freshly deployed role has none
yet. Phase 7 therefore has two methods, and every surface says which one produced the candidate it
is showing.

| Method | Confidence | What it means |
| --- | --- | --- |
| `access_analyzer_activity` | `observed_activity` | IAM Access Analyzer generated the policy from CloudTrail activity for this principal. Evidence about the past: code paths that never ran are missing. |
| `static_estimate` | `static_estimate` | The candidate is derived from the literal boto3 calls in the scanned source (Phase 3's parse). An estimate with no traffic behind it. |

The labels and confidence values live in one table in `agent/least_privilege.py`, so no caller can
describe an estimate as observed activity by re-using the wrong words.

## Flow

```text
first-commit remediate-iam SOURCE TARGET --role ROLE
  -> read the target identity policy (standalone JSON or SAM YAML)
  -> method: activity
       StartPolicyGeneration(principalArn, optional CloudTrail window)
       -> poll to a terminal state
       -> SUCCEEDED with statements   : candidate
          SUCCEEDED with nothing      : no_activity_history -> guidance, not an error
          FAILED                      : closed job-error reason code
       -> restrict the profile to what the replaced policy already granted
  -> method: static
       literal boto3 client calls -> actions -> narrow only the wildcard statements
  -> prove it: containment (nothing new) + strictness (something removed)
  -> optional second opinion: CheckNoNewAccess when --verify aws
  -> before/after diff + provenance + coverage + reason codes
```

## Cold start

A generation job that succeeds with no statements is the cold-start case, and it is reported as
one:

```powershell
first-commit remediate-iam fixtures/least-privilege-repo infra/template.yaml `
  --tenant demo --environment development --role arn:aws:iam::123456789012:role/UploadFunctionRole
```

```text
== method: access_analyzer_activity ==
confidence: observed_activity
status: unavailable
reasons: no_activity_history
note: Analyzing recent activity — run your app a few times first, then re-run this command.
note: For a policy now, re-run with --method static to get a clearly labelled estimate instead.
```

`auto` (the default) then offers the estimate, labelled as an estimate. `--method activity` fails
closed instead of quietly substituting one, so a caller that requires evidence never receives a
guess.

## What "strictly narrower" means here

A candidate is offered as *recommended* only when both halves hold:

1. **Containment.** `check_no_expansion(original, candidate)` concludes `safe`. `inconclusive`
   (an original statement with a `Condition`, `NotAction` or `NotResource`) downgrades the attempt
   to `needs_review` rather than claiming a proof that was not obtained.
2. **Strictness.** At least one action or resource the original allowed is gone. An already
   least-privilege policy produces `candidate_not_narrower` and no recommendation at all.

AWS `CheckNoNewAccess` (`--verify aws`) can only make the result stricter: a `FAIL` rejects the
candidate. Resource placeholders such as `arn:aws:s3:::${BucketName}` are treated as unknown scope
in the proof, counted in the report, and flagged for review.

## Coverage is stated, not implied

The estimate is an estimate, and the report shows its shape: the actions the source calls, files
where boto3 usage could not be resolved (`boto3.resource`, dynamic service names), actions the
current policy never granted, and — for activity profiles — actions the code calls that have not
been exercised yet. Dropping access a role was *observed* using is reported as
`actions_outside_replaced_policy`, because it means the profile came from the role's other
policies rather than the one being replaced.

## Commands

```powershell
# Estimate from the source, no AWS access needed
first-commit remediate-iam fixtures/least-privilege-repo infra/template.yaml `
  --tenant demo --environment development --method static

# Real activity, with an explicit CloudTrail window and CheckNoNewAccess as a second opinion
first-commit remediate-iam . infra/template.yaml --tenant demo --environment production `
  --role arn:aws:iam::123456789012:role/UploadFunctionRole `
  --trail-arn arn:aws:cloudtrail:us-east-1:123456789012:trail/management `
  --access-role arn:aws:iam::123456789012:role/AccessAnalyzerTrailRole `
  --start-time 2026-09-01T00:00:00Z --regions us-east-1 --verify aws --json
```

Exit code 0 means a candidate was offered (possibly `needs_review`); 2 means nothing was offered
and the report says why.

## Completion boundary

The engine, the analyzer boundary, the two provenance paths, the CLI and the tests are complete,
and the AWS request shapes are pinned by tests over a scripted client. What is *not* here, by
intent:

- **No deployed call.** No AWS account was touched; `CheckNoNewAccess` and policy generation are
  verified against their documented request and response shapes, not against live responses.
- **No hosted route yet.** There is no Lambda, API route or IAM permission for this engine. A
  hosted caller needs `access-analyzer:StartPolicyGeneration`, `GetGeneratedPolicy` and
  `CheckNoNewAccess`, plus a CloudTrail read role, and granting those before a caller exists would
  add unused access to a tool whose whole purpose is removing it. The route belongs with the
  deployment phase, alongside the change-set flow.
- **No automatic application.** A recommendation is a diff and a provenance record. Applying it
  stays a reviewed pull request (ADR 0003), and validating the patched function locally is
  Phase 8.
