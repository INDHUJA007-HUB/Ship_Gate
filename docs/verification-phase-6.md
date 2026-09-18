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

## Container build (2026-09-14)

The build verification that this phase had left open is now complete, and it found a real
packaging bug on the way.

- The host has Python 3.13 only, so a native `sam build` installs dependencies for the wrong
  interpreter *and* the wrong platform. The local virtual environment holds
  `_internal.cp313-win_amd64.pyd`, a Windows cp313 extension module that a `python3.12` x86_64
  Lambda cannot import. Rather than loosen the runtime pin, every function now declares
  `Metadata: {BuildMethod: python3.12}`, so its build method is pinned to `Globals.Function.Runtime`
  and a guard test fails if the two ever disagree.
- `sam build --use-container` with SAM CLI 1.166.1 resolved the official image
  `public.ecr.aws/sam/build-python3.12:latest-x86_64` and finished with **Build Succeeded** for all
  nine functions sharing one `CodeUri`.
- The artifact is Python 3.12 Linux only: 72 shared objects, 0 `.pyd` files, 0 cp313 artefacts,
  and `cedarpy/_internal.cpython-312-x86_64-linux-gnu.so` in place of the host's `.pyd`.
- The artifact imports on the real runtime image `public.ecr.aws/lambda/python:3.12`
  (Python 3.12.14): `api.handlers`, `agent.orchestration.pipeline`, `agent.orchestration.steps`,
  `agent.orchestration.claude_model`, `agent.reasoning.providers`, `agent.least_privilege`,
  `cedarpy` and `strands`.
- That import test is what exposed the bug: `requirements.txt` declared PyYAML, cedarpy and
  anthropic, but **not** `strands-agents`, which `pyproject.toml` declares as a runtime dependency
  and `agent/orchestration/agent.py` imports. The artifact built, installed and imported before
  the gap was visible, so only running the packaged code found it. `requirements.txt` is fixed and
  `agent/tests/test_packaging_manifest.py` now fails if the Lambda manifest and `pyproject.toml`
  drift apart again.
- Building in place is not usable: SAM copies the whole `CodeUri` tree into the container, so a
  working copy with `.venv/` and `.tools/` present copies tens of thousands of files and exceeded
  ten minutes twice without finishing. The verification above was run from a clean tree (a copy of
  the tracked plus uncommitted-not-ignored files), which is what a deployment from a checkout looks
  like. `.aws-sam/` is ignored for the same reason, and the procedure is recorded in
  [the Phase 6 guide](phase-6-orchestration.md#building-the-deployable-artifact).

## Verification commands

```powershell
python -m pytest agent/tests/test_orchestration_pipeline.py `
  agent/tests/test_orchestration_agent.py -q --basetemp .pytest-tmp/phase6-focused
python -m ruff check .
sam validate --lint --template-file infra/template.yaml --region us-east-1
```

Focused result at implementation time: **15 passed**. Full suite at that point: **224 passed,
7 skipped**; after the Phase 7 work recorded separately, the same suite is **257 passed, 7 skipped**.
The four opt-in real-scanner integration tests also pass. Ruff and SAM validation are clean.

## Not verified

- A deployed Step Functions execution, Lambda retry, EventBridge failure event, DynamoDB/S3
  conditional race, or SQS delivery in a real AWS account.
- Packaging Gitleaks, Semgrep, and Checkov into the hosted detect Lambda: the container build
  proves the Python dependencies and the handler imports, not that the scanner executables are
  present on the Lambda filesystem.
- A live ambiguous Strands turn through Claude/Bedrock. Direct deterministic Strands tool
  invocation is verified; mocked provider shapes remain covered by Phase 5 tests.
