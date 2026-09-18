# First Commit

Phase 4 finding-policy evaluation is available through `first-commit policy`.
See [the Cedar policy guide](docs/phase-4-policy.md) for context, cache, limits,
decision semantics and the Phase 5 handoff.

Governance and IAM proposal commands are now available. See
[the Phase 2–3 guide](docs/phase-2-3.md) for commands, tested failure handling,
and explicit remaining runtime-validation work.

First Commit is an evidence-first safety companion for AI-generated code. It
uses deterministic scanners to find concrete shipping risks before invoking an
AI explanation layer in a later phase. It never executes scanned code and it
never directly commits, merges, or deploys a remediation.

## What works today

Phase 0 and Phase 1 provide a local Python CLI that:

- enforces file-count, file-size, total-size, nesting-depth, and scan-time limits;
- invokes Gitleaks, Semgrep, and Checkov when installed;
- runs first-party static checks for missing required environment variables,
  missing route authorization, and missing request validation;
- converts all detector output into one versioned `Finding` schema;
- fingerprints findings and scan inputs deterministically for later caching.

The external tools are intentionally not reimplemented. If one is unavailable,
the CLI records a clear partial-scan error and exits non-zero; it never claims a
clean result. First-party checks cover product-specific patterns that are not
well represented by an off-the-shelf rule alone.

## Quick start

Prerequisites: Python 3.12+, plus [Gitleaks](https://github.com/gitleaks/gitleaks),
[Semgrep](https://github.com/semgrep/semgrep), and
[Checkov](https://github.com/bridgecrewio/checkov) on `PATH`.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
first-commit scan fixtures/golden-repo
pytest
ruff check .
```

Use `first-commit scan fixtures/hostile-repo` to verify safe rejection of a
hostile input. Run `first-commit scan --help` for machine-readable JSON output
options and limits.

## Safety contract

- Scanned code is read as data only; it is never imported, built, or executed.
- Files outside the submitted root are never traversed.
- Binary files are skipped and reported; detector commands receive only the
  target directory and run under a hard timeout.
- A missing detector is a partial/failed scan, not a passing scan.
- Findings are evidence, not automatic fixes. Future remediation is PR-only.

See [docs/threat-model.md](docs/threat-model.md), [CONTRIBUTING.md](CONTRIBUTING.md),
and [the ADRs](docs/ADRs/) for the project contract.
