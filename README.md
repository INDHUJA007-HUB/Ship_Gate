# First Commit

First Commit is an evidence-first safety companion for AI-generated code.
Deterministic scanners and embedded Cedar policies decide first; a validated,
tiered AI layer then explains those decisions without being able to change them.
It never executes scanned code, and it never commits, merges or deploys a fix.

## What works today

Phases follow the [master technical reference](first-commit-master-technical-reference.md).

| Phase | Capability | Commands |
| --- | --- | --- |
| 0–1. Product and scan engine | Repository contract, threat model, CI, seeded fixtures, deterministic versioned findings and content-hash cache | `scan` |
| 2–3. Intake and candidate validation | Directory, bounded `.zip` or hardened HTTPS Git URL; Gitleaks, Semgrep, Checkov and first-party checks; reviewed IAM proposals and sandboxed local candidate validation | `scan`, `propose-iam`, `validate-candidate` |
| 4. Policy engine and control plane | Embedded Cedar triage plus policy-version audit; local SQLite and DynamoDB adapters for scans, findings, decisions, and deployment attempts; SAM API/workflow foundation | `policy` |
| 5. AI reasoning layer | Evidence-first explanations and question answering: deterministic/small/large routing; schema and grounding validation; one retry then human review; tenant content-hash cache; budgets and circuit breaker; Claude API, Bedrock, or loopback-only Ollama open models | `explain`, `ask` |
| 6. Resilient orchestration | One tenant-bound Strands agent plus one local/AWS Step Functions definition; write-once checkpoints, bounded retries, partial results, review queue, generation-based resume and abnormal-run reconciliation | `run`, `resume`, `runs`, `reviews`, `orchestrate` |
| 7. Least-privilege remediation | A scoped policy in place of a wildcard one, from IAM Access Analyzer activity or a clearly labelled static estimate; before/after diff, containment and strictness proof, `CheckNoNewAccess` as a second opinion | `remediate-iam` |

Not built yet: browser dashboard implementation, real AWS deployment and runtime tracing
integrations, and with them a live IAM Access Analyzer call. See
[the architecture](docs/architecture.md), [the Phase 3 guide](docs/phase-3.md),
[the Phase 4 guide](docs/phase-4-policy.md), [the Phase 5 guide](docs/phase-5-reasoning.md),
[the Phase 6 guide](docs/phase-6-orchestration.md), and
[the Phase 7 guide](docs/phase-7-remediation.md).

## Quick start

Prerequisites: Python 3.12+, and Gitleaks, Semgrep and Checkov either on `PATH`
or installed under `.tools/<name>`. Runtime validation also needs Docker, the
SAM CLI and the three images pinned in `agent/candidate_runtime.py`.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev,aws,ai]"
first-commit doctor
first-commit scan fixtures/golden-repo
pytest
ruff check .
```

Explanations default to vetted templates with no model calls. Set
`FIRST_COMMIT_MODEL_PROVIDER` to `anthropic`, `bedrock` or `ollama` (or pass
`--provider`). Ollama defaults to local Qwen3 4B/8B and never downloads models
or accepts cloud tags. Install the optional `ai` extra only for Claude/Bedrock;
see [the Phase 5 guide](docs/phase-5-reasoning.md).

A wildcard policy can be narrowed from the source alone, with the result labelled as an estimate:

```powershell
first-commit remediate-iam fixtures/least-privilege-repo infra/template.yaml `
  --tenant demo --environment development --method static
```

The durable local workflow defaults to template-only explanations, so it does not need model
credentials:

```powershell
first-commit run fixtures/golden-repo --tenant demo --user demo --provider none
first-commit orchestrate "scan fixtures/golden-repo" --tenant demo --user demo --model none
```

Tests that drive the real scanners and Docker are opt-in:

```powershell
$env:FIRST_COMMIT_INTEGRATION = "1"
pytest agent/tests/test_scanner_integration.py agent/tests/test_candidate_runtime.py
```

## Safety contract

- Scanning reads input as data; nothing is imported, built or executed.
- A scanned repository cannot configure or suppress the scanners.
- Files outside the submitted root are never traversed; links, path escapes
  and zip bombs are rejected.
- A missing, crashed or unmapped detector makes a scan partial, never clean.
- Candidate code runs only inside the container sandbox of
  [ADR 0007](docs/ADRs/0007-candidate-sandbox-and-untrusted-scanner-config.md),
  driven by trusted operator manifests.
- Fixes are proposals. A PR requires static and runtime evidence plus a bound
  human approval.
- Models see bounded, sanitized facts, never source or secret values. Their
  output is validated before use, and they cannot change a policy decision
  ([ADR 0009](docs/ADRs/0009-tiered-validated-model-explanations.md)).

See [docs/threat-model.md](docs/threat-model.md), [CONTRIBUTING.md](CONTRIBUTING.md),
and [the ADRs](docs/ADRs/) for the project contract.
