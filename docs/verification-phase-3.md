# Phase 3 verification — 2026-09-11

Environment: Windows 11, Python 3.13.14 virtual environment, cedarpy 4.8.7,
Gitleaks 8.30.0, Semgrep 1.177.0, Checkov 3.3.17, SAM CLI 1.166.1, Docker 29.7.2
(linux/x86_64) and git 2.53.0. No AWS resources were provisioned.

## Results

- Unit suite: 74 passed, 6 skipped (5 opt-in real-tool tests, 1 Windows symlink
  privilege). Ruff: all checks passed.
- Real scanners (`FIRST_COMMIT_INTEGRATION=1`): golden fixture returns exactly the
  planted findings; repository config and inline suppressions do not silence
  Gitleaks, Semgrep or Checkov; no repository code executes with or without the
  external tools.
- Real Docker candidate runtime: 2 passed in 77 s. The patched Lambda reached
  `runtime_validated` with PR gate `needs_human_approval`; a failing smoke
  response was `failed` with PR gate `deny`.
- CLI end to end: `scan fixtures/golden-repo` was complete with 4 findings
  (Checkov IAM, missing environment variable, missing auth, missing validation).
  `policy` ran 8 Cedar requests and 0 model calls; all 4 decisions were
  `needs_human_approval`. A PowerShell `Compress-Archive` zip of the same fixture
  scanned complete with an identical content hash.
- Real git clone over a test-only `file` transport: revision returned, `.git`
  removed, a committed symlink checked out as a plain file. The default https-only
  allowlist refused the same transport.
- The built wheel contains the new rules, harness scripts, Cedar policy and modules.

The golden fixture's committed `AKIA...EXAMPLE` value is not reported: Gitleaks
allowlists AWS's public example. Secret detection is proven with a synthetic key
generated at test time.

## Baseline before the fixes, same machine

- `doctor`: Checkov unavailable, so every real scan was partial.
- Gitleaks reported 0 secrets in the golden fixture; Semgrep produced IDs with a
  machine-specific prefix that matched no mapping.
- Repository-supplied scanner config reduced findings to zero: Gitleaks 1 to 0,
  Semgrep 2 to 0, Checkov 3 to 0.
- A host request to a Lambda on an `--internal` network failed: no port published.

## Not verified

GitHub CI, an https clone of a public remote, AWS IAM enforcement, deployment,
and Docker on Linux or macOS hosts.
