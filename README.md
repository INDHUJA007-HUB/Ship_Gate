# First Commit

First Commit is an evidence-first safety companion for AI-generated code.
Deterministic scanners and embedded Cedar policies decide first; an AI
explanation layer comes in a later phase. It never executes scanned code, and it
never commits, merges or deploys a fix.

## What works today

Phases follow the [master technical reference](first-commit-master-technical-reference.md).

| Phase | Capability | Commands |
| --- | --- | --- |
| 0–1. Product and scan engine | Repository contract, threat model, CI, seeded fixtures, deterministic versioned findings and content-hash cache | `scan` |
| 2–3. Intake and candidate validation | Directory, bounded `.zip` or hardened HTTPS Git URL; Gitleaks, Semgrep, Checkov and first-party checks; reviewed IAM proposals and sandboxed local candidate validation | `scan`, `propose-iam`, `validate-candidate` |
| 4. Policy engine and control plane | Embedded Cedar triage plus policy-version audit; local SQLite and DynamoDB adapters for scans, findings, decisions, and deployment attempts; SAM API/workflow foundation | `policy` |
Not built yet: browser dashboard implementation, Bedrock explanations, IAM
Access Analyzer proof, real AWS deployment and tracing integrations. See
[the architecture](docs/architecture.md), [the Phase 3 guide](docs/phase-3.md)
and [the Phase 4 guide](docs/phase-4-policy.md).

## Quick start

Prerequisites: Python 3.12+, and Gitleaks, Semgrep and Checkov either on `PATH`
or installed under `.tools/<name>`. Runtime validation also needs Docker, the
SAM CLI and the three images pinned in `agent/candidate_runtime.py`.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
first-commit doctor
first-commit scan fixtures/golden-repo
pytest
ruff check .
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

See [docs/threat-model.md](docs/threat-model.md), [CONTRIBUTING.md](CONTRIBUTING.md),
and [the ADRs](docs/ADRs/) for the project contract.
