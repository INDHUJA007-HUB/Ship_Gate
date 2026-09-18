# Phase 6 verification — 2026-09-13

Environment: Windows 11, Python 3.13 virtual environment, Strands Agents 1.55.1, cedarpy
4.8.7, and SAM CLI 1.166.1. No AWS resource was created or called.

## Acceptance evidence

- The exact deployed ASL file validates in the local restricted interpreter and in SAM, including
  `sam validate --lint`.
- A deliberately crashed `route-safety` detector produced a `partial` result. The successful
  environment finding remained visible, missing auth/validation coverage was named, Cedar
  decisions remained deny/closed, and one human-review record was written.
- Resuming that run without the fault reused the successful detector checkpoint, ran the missing
  detector work, completed generation 1, and marked the old review record resolved without
  deleting it.
- A `transient_after_write` fault produced exactly one retry, one physical detector execution,
  one normalized finding, and one stored Finding entity. The retry read the write-once checkpoint.
- Invalid source input failed with a safe rejection code, was not retried, was not resumable, and
  produced no misleading review item.
- Two runs over identical content reused the entire completed result with zero second detector or
  model work. Re-submitting the same run ID returned the existing final outcome.
- A real local pipeline invocation ran all five applicable checks. Gitleaks, Semgrep, Checkov,
  missing-environment and route-safety all completed; the golden repository produced four
  findings, Cedar returned four review decisions, and explanations used zero model calls.
- That live pass first exposed a relative-workspace integration bug: Semgrep failed and Gitleaks
  could inspect the wrong directory because scanner subprocesses use a trusted scratch cwd. The
  snapshot adapter now returns an absolute verified tree, and the full real-tool run passes.
- A Strands direct tool request was tenant-bound and used zero model calls. Guard tests pin the
  one-model-call ceiling, duplicate-call suppression, and one-state-change ceiling.

## Verification commands

```powershell
python -m pytest agent/tests/test_orchestration_pipeline.py `
  agent/tests/test_orchestration_agent.py -q --basetemp .pytest-tmp/phase6-focused
python -m ruff check .
sam validate --lint --template-file infra/template.yaml --region us-east-1
```

Focused result at implementation time: **15 passed**. Full suite: **224 passed, 7 skipped** before
the absolute-workspace regression assertion was added; the final full-suite result is recorded in
the project status report. The four opt-in real-scanner integration tests also pass. Ruff and SAM
validation are clean.

## Not verified

- A deployed Step Functions execution, Lambda retry, EventBridge failure event, DynamoDB/S3
  conditional race, or SQS delivery in a real AWS account.
- Packaging Gitleaks, Semgrep, and Checkov into the hosted detect Lambda.
- A live ambiguous Strands turn through Claude/Bedrock. Direct deterministic Strands tool
  invocation is verified; mocked provider shapes remain covered by Phase 5 tests.
