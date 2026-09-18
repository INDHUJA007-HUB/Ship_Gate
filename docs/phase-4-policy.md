# Phase 4 — finding policy evaluation

Phase numbering here follows the master reference and the latest user request:
Phase 4 is Cedar, Phase 5 is AI reasoning. The remediation/runtime work once
called "Phase 3" is now complete; see [the Phase 3 guide](phase-3.md). Finding
triage here never opens its PR gate.

## Implemented workflow

`normalized ScanReport + explicit PolicyContext -> hard cap -> canonical facts
-> tenant/user-scoped decision cache -> embedded Cedar batch -> audited decisions`

Run `first-commit policy scan.json --tenant demo --user alice --owner demo
--environment development --current-hash HASH`. Replace HASH with the current
source hash obtained from preflight, not a stale previously supplied report.
Repeat `--environment` to provide multiple tags. Omit it to verify missing
environment denial. `--cache-db PATH` chooses the local SQLite cache/audit file.

Input is the JSON emitted by `first-commit scan`. Detector failures must stay
in `detector_errors`; a partial scan cannot authorize processing. CLI inputs
are trusted local operator data. A hosted API must derive tenant, owner,
current source hash, and rule facts server-side from authenticated state.

## Decisions and authority

`permit` means eligible for deterministic finding processing; it is NOT
permission to apply a patch, open a PR, merge, or deploy. Those operations still
use the separate remediation governance gate. `needs_human_approval` is a
triage escalation, not proof of runtime validation. `deny` covers absent or
invalid context, stale source, partial scans, and evaluation errors.

Eleven versioned Cedar files in `agent/policies/findings/` handle categories,
missing context, conflicting environments, aggregate risk, volume and examples.
`unsafe_command_execution` (Semgrep `shell=True` and subprocess rules) always
requires review.
Cedar default deny and forbid-overrides-permit are the only precedence rules.
There is no custom most-specific-wins mode. Each decision records source hash,
policy hash, matched human-readable rule IDs, effective environment/severity,
evidence class, and resource count.

There is no hand-assigned numerical confidence gate. Required-environment
detection is marked `deterministic_fact`; route heuristics and external detector
results are `detector_or_heuristic` and need review. Every IAM or non-example
secret finding requires review, as do authentication findings. This prevents a
number from being mistaken for a calibrated probability.

Multiple environment tags conservatively resolve to production. Unknown tags
still deny. Three findings sharing a resource escalate. Without a correlated
resource ID, grouping falls back to file path; this deliberately favors review.
Known examples are downgraded only when the Gitleaks adapter confirms the exact
public example value AND the path has a test/tests/fixtures/docs directory
component. Gitleaks' default rules already allowlist that public example, so with
the packaged configuration this path is unreachable; it remains as a guarded rule
for custom Gitleaks rules. Raw secret values are not included in the decision or cache.

## Cost and concurrency

Embedded cedarpy 4.8.7 is the only backend; no AVP request is made. Policies parse
once per engine instance. A single native batch evaluates two actions per
finding (processing and review), at most 1,000 Cedar requests for the default
500-finding cap. These are local computations, not paid managed-service calls.

Python enforces the hard cap before constructing requests. More than 500
findings returns `capped` with zero Cedar calls and no partial list presented as
complete. At 100 findings Cedar escalates triage to `batch_summary`; Python
computes counts. Cedar is not used as a stateful quota manager.

The cache key includes tenant, user, owner, source, complete scan state, sorted
normalized facts, deduplicated/sorted environment tags, policy hash, engine
version, and limits. It excludes timestamps, file-system root, result ordering,
untrusted prose and request IDs. A transaction prevents concurrent identical
misses from evaluating more than once, across local processes. Cache errors
fail closed; engine errors are never cached. Stored results retain policy
version and matched rule IDs with creation time for subsequent audit.

The SQLite file is trusted application state, outside the submitted repository.
`LocalScanStore` supplies that developer experience. `DynamoScanStore` uses the
same store interface and conditional writes for Scan, Finding, PolicyDecision,
and DeploymentAttempt records; the API/control-plane can use it when
`FIRST_COMMIT_MODE=aws`. The CLI retains `--cache-db` for an explicit local,
portable policy-audit file.

## Phase 5 handoff

The handoff requirements are implemented in the [Phase 5 guide](phase-5-reasoning.md):
- Models explain and may escalate, but never lower a decision or supply a
  probability.
- Facts are bounded and grouped; model attempts are budgeted; concurrent
  requests are deduplicated.
- The cache is keyed on policy, evidence, model and prompt versions.
- Throttling and budget stops are reported separately, with per-tier routing
  and usage.
- Truncated evidence is flagged.

The policy engine itself still makes no model calls; its reports keep
`model_calls: 0`.
