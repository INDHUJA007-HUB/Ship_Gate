# Phase 4 — finding policy evaluation

Phase numbering here follows the master reference and the latest user request:
Phase 4 is Cedar, Phase 5 is AI reasoning. The earlier conversation's Phase 3
remediation/runtime implementation remains on hold. This work does not open its
PR gate or resume its runtime implementation.

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

Ten versioned Cedar files in `agent/policies/findings/` handle categories,
missing context, conflicting environments, aggregate risk, volume and examples.
Cedar default deny and forbid-overrides-permit are the only precedence rules.
There is no custom most-specific-wins mode. Each decision records source hash,
policy hash, matched human-readable rule IDs, effective environment/severity,
upstream integer confidence, and resource count.

Unknown rules receive confidence 50; existing auth/input regex heuristics 70;
required-environment detection 90; the recognized Gitleaks rule 95. These values
express versioned detector certainty and aren't model-generated probabilities.
The tests pin the threshold at 89/90/91. Every IAM or non-example secret finding
requires review; auth findings require review even at high confidence.

Multiple environment tags conservatively resolve to production. Unknown tags
still deny. Three findings sharing a resource escalate. Without a correlated
resource ID, grouping falls back to file path; this deliberately favors review.
Known examples are downgraded only when the Gitleaks adapter confirms the exact
public example value AND the path has a test/tests/fixtures/docs directory
component. Raw secret values are not included in the decision or cache.

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
It is suitable for this local phase, not shared Lambda durable storage; a cloud
adapter will need conditional writes/leases and authenticated audit access.

## Phase 5 handoff, not implemented in this phase

AI explanations must never mutate Cedar decisions or supply confidence. The
model interface must accept bounded structured facts only, group by category,
enforce a fixed total-attempt/model-call budget, deduplicate concurrent requests,
cache on stable policy/evidence/model/prompt versions, and separately report
throttling versus an intentional quota break. Classification and synthesis
tiers need separate routing and measured usage; token budgets require explicit
truncation flags. These are Phase 5 requirements, not working features today.

No Bedrock/local-model inference is invoked by this phase; reports expose
`model_calls: 0` and actual Cedar request/cache-hit counters.
