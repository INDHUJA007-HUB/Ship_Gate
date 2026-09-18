# Phase 6 — resilient orchestration

Phase 6 connects the deterministic scanner, Cedar policy engine, and explanation service into
one resumable workflow. The pipeline is durable; the model is not the workflow engine and never
becomes the security authority.

## End-to-end flow

```text
CLI / authenticated HTTP API / Strands tool
  -> create deterministic run record + named execution
  -> Prepare
       validate request -> ingest -> hostile-input preflight -> immutable snapshot
       -> reuse a completed identical result OR plan applicable detectors
  -> Detect Map (independent, bounded parallelism)
       success -> write-once detector checkpoint
       transient -> bounded backoff retry
       defect / timeout exhausted / missing tool -> review item + incomplete check
  -> Merge
       load valid checkpoints -> deduplicate content-derived findings
       -> persist Scan/Finding entities -> embedded Cedar evaluation
  -> Explain
       Phase 5 cache/budget/validation pipeline; template fallback on failure
  -> Finalize
       completed | partial | failed + exact coverage + compact run status
```

AWS runs this definition in Step Functions Standard. Local mode runs the same
`agent/orchestration/scan-pipeline.asl.json` through the deliberately restricted interpreter in
`agent/orchestration/asl.py`. Unsupported state-machine fields fail validation instead of being
silently approximated.

## What is durable and idempotent

| Record | Local | AWS | Idempotency key |
| --- | --- | --- | --- |
| Run/status | SQLite | DynamoDB | tenant + run ID + generation |
| Source snapshot | Files | S3 | tenant hash + content hash |
| Detector result | SQLite checkpoint | S3 JSON checkpoint | content hash + detector + detector fingerprint |
| Findings/scan | SQLite | DynamoDB | tenant + deterministic scan/finding ID |
| Cedar decision | SQLite | DynamoDB | canonical facts + policy version + tenant context |
| Explanation | SQLite | DynamoDB | sanitized evidence + prompt/provider/version context |
| Review item | SQLite | DynamoDB + FIFO SQS notification | run + generation + failed step |

The Step Functions execution name is the run ID plus its resume generation. Retrying `POST
/scans` with the same idempotency key cannot create a second logical run. A retry after a task
already wrote its checkpoint reads the first result and does no second detector or model job.

## Failure contract

| Failure | Action | Final meaning |
| --- | --- | --- |
| Throttling, network/storage transient | bounded retry with backoff and jitter | succeeds or becomes explicit retry-exhausted review |
| Detector timeout | one state-machine retry | incomplete check if still timed out |
| Detector crash/malformed or unknown output | no blind retry; durable review item | partial when another check succeeded |
| Scanner not packaged/configured | operator-action review item | partial, never clean |
| Invalid URL/archive, size/depth/link limit | reject without retry | failed, not resumable |
| Cedar engine error | one retry; never cached | partial/failed closed |
| Explanation/provider error | bounded retry, then vetted template | scan decision remains valid; prose is degraded |
| Finalizer/execution abnormal end | retry, then EventBridge reconciliation | failed and resumable; never stuck `running` |

Every public reason is a bounded reason code. Raw exception text, scanner output, source snippets,
and secrets are excluded from workflow history and logs.

## The Strands boundary

There is one tenant-bound `OrchestratorAgent` with six tools: start, status, resume, explain,
question, and review items. Clear structured or natural-language requests use a deterministic
planner and make zero orchestration-model calls. Only ambiguous phrasing reaches the configured
small Claude model. Hooks enforce one model call, at most three distinct tool calls, no duplicate
tool call, and no more than one state-changing tool per user request.

Tenant and user identifiers are captured when the toolbox is constructed; they are not tool
arguments the model can invent. Tool output contains compact stored facts, never repository
source. Cedar remains final: the agent cannot approve, downgrade, commit, merge, or deploy.

## Commands

```powershell
# Local durable pipeline, template-only explanations, first-party checks only
first-commit run fixtures/golden-repo --tenant demo --user demo --provider none --no-external

# Deliberate detector defect: should finish partial and create a review item
first-commit run fixtures/golden-repo --tenant demo --user demo --provider none --no-external `
  --fault route-safety=crash --trace

# Resume after removing the injected fault
first-commit resume RUN_ID --tenant demo --user demo --provider none --no-external

# Zero-model deterministic agent request
first-commit orchestrate "scan fixtures/golden-repo" --tenant demo --user demo --model none `
  --no-external
```

Fault injection is an operator-only test facility. AWS reads fault specifications only when the
deployment parameter explicitly enables it; a scan request cannot supply faults.

## Building the deployable artifact

The template pins `Runtime: python3.12`, and every function pins the same value as its
`Metadata: {BuildMethod: python3.12}`. A native `sam build` installs dependencies with the host
interpreter, which on a newer Python produces extension modules the runtime cannot import, so the
artifact is built in SAM's official runtime image instead:

```powershell
# From a clean tree: a working copy also contains .venv/, .tools/ and .aws-sam/, and SAM copies
# the whole CodeUri tree into the container.
git ls-files -z | xargs -0 -I{} cp --parents {} C:/tmp/first-commit-build
cd C:/tmp/first-commit-build
sam build --use-container --template-file infra/template.yaml
```

The verified result on this host: `public.ecr.aws/sam/build-python3.12:latest-x86_64`, all nine
functions built, 72 `cpython-312-x86_64-linux-gnu` extension modules and no Windows or cp313
binaries, importing cleanly under `public.ecr.aws/lambda/python:3.12`.

`requirements.txt` is the Lambda dependency manifest and must stay aligned with `pyproject.toml`,
which the stable SAM builder does not read. A guard test compares the two, because a missing entry
still builds and only fails when the packaged code imports it.

## Completion boundary

The code, local acceptance tests, Strands dependency, SAM state machine, per-step IAM roles,
authenticated asynchronous endpoints, and abnormal-execution reconciliation are implemented.
AWS deployment is intentionally a separate proof: `sam validate --lint` proves template shape,
not that an account has accepted the roles or that external scanner binaries are packaged in the
detect Lambda. Those live checks remain unverified until a stack is deployed.

Lambda Python dependencies are declared separately in `requirements.txt`, because the stable SAM
builder does not consume the project package's `pyproject.toml` by default; a guard test keeps the
two manifests aligned. The durable workspace always materializes an absolute scanner target;
scanner subprocesses deliberately use a separate trusted working directory and must never resolve
the target relative to it.
