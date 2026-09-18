# Phase 3 completion guide

## Which "Phase 3"

This repository used two numbering schemes. The master reference calls Phase 3
*Ingestion and Static Analysis*. The earlier conversation plan
([phase-2-3.md](phase-2-3.md)) called remediation plus local validation
"Phase 3"; the master reference numbers that work Phases 7 and 8. Both were
incomplete, and both are completed here. Later documents use master numbering.

## Ingestion and static analysis (master Phase 3)

```powershell
first-commit scan fixtures/golden-repo
first-commit scan upload.zip
first-commit scan https://github.com/owner/repo.git
```

Every source converges on one bounded directory before preflight. The report adds
`ingestion.kind`, `label` and, for Git, the cloned commit `revision`.

| Exit criterion | Evidence |
| --- | --- |
| Golden fixture returns exactly the planted findings | `test_golden_fixture_returns_exactly_the_planted_findings` (real tools) |
| Hostile input fails cleanly without executing | preflight and `test_ingest.py` limits; `test_scan_never_executes_repository_code` |
| Git URL and zip converge on one tree | `agent/ingest.py`; zip scan hash equals directory scan hash |
| Scanners cannot be silenced by the repository | `test_scanned_repository_cannot_blind_the_scanners` (real tools) |
| Narrowest scan-worker network/IAM | Local: trusted cwd, packaged config, telemetry off. Cloud isolation is Phase 12. |

Defects found and fixed while completing it:

- Checkov never ran on Windows: its `.cmd` shim broke JSON output. It now runs
  through its virtual environment's interpreter. Every real scan had been partial,
  so Phase 4 denied everything.
- Semgrep prefixes local rule IDs with a machine-specific path, so no ID matched,
  every result was labelled `missing_input_validation`, and finding IDs differed
  per machine. IDs are normalized; unknown rules make the scan partial.
- A repository `.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore` or
  `.checkov.yaml` silenced the scanners (ADR 0007).
- Gitleaks' default rules allowlist AWS's public `AKIA...EXAMPLE` key, so the
  golden fixture's secret was never detected. The integration test generates a
  synthetic key at runtime instead of committing a detectable one.
- Checkov raises three overlapping checks per wildcard role, which alone tripped
  Phase 4's compound-risk threshold. It now yields one finding per IAM resource.
- Relative detector paths were resolved against the process directory.

## Remediation and local validation (master Phases 7 and 8)

```powershell
first-commit propose-iam fixtures/runtime-repo template.yaml --operations fixtures/runtime-operations.json --tenant local --environment development --output proposal.json
first-commit validate-proposal fixtures/runtime-repo proposal.json --tenant local --environment development
first-commit validate-candidate fixtures/runtime-repo proposal.json --manifest fixtures/runtime-validation.json --tenant local --environment development
```

Add `--approval approval.json` to `validate-candidate` to evaluate the PR gate
with a bound approval.

| Exit criterion | Evidence |
| --- | --- |
| A fix that works passes and is queued | `runtime_validated`, PR gate `needs_human_approval` (real Docker test) |
| A fix that breaks the app is blocked | Dropped code action rejected at proposal; failing smoke gives `failed` and `deny` |
| Static and activity-based results are distinguishable | `method: static_reviewed_operations_not_activity_history`; code estimate labelled |
| Local pass is not treated as AWS proof | `aws_iam_status: not_verified` on every result |

Defects found and fixed in the in-progress runtime:

- Docker does not publish ports from `--internal` networks, so the host smoke
  request could never succeed. A trusted invoker now calls from inside the network.
- The validation manifest was read from the untrusted repository.
- Scanner replay required zero findings, so any repository with an unrelated
  finding could never validate. It now requires no new findings and a resolved
  IAM finding on the patched file.
- Seeding hard-coded the fixture's table and bucket; the manifest declares it.
- The patch was written in text mode, which translates newlines on Windows.
- `sam validate` ran with the repository as working directory (`samconfig.toml`).

## Limits, not claimed

- YAML with CloudFormation intrinsic tags (`!Ref`, `!Sub`, `!GetAtt`) is
  rejected, and most real templates use them.
- Only `AWS::IAM::Role` inline policies are patched, not SAM function `Policies`.
- Python 3.12 zip Lambdas without dependency builds only.
- Local emulators do not enforce IAM; Access Analyzer and `CheckNoNewAccess`
  are not integrated.
- The code-action estimate covers literal boto3 clients only; other usage is
  reported as a partial estimate.
