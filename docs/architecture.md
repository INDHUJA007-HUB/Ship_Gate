# Architecture

The built system has a local deterministic core plus an AWS SAM control-plane
template. The template is not evidence that resources have been deployed; see
the verification reports for the boundary between mocked, local and live tests.

Phase numbers below follow the master reference. The earlier "Phase 2
governance / Phase 3 remediation" labels map to master Phases 4, 7 and 8.

## Ingestion and static analysis (master Phase 3)

```text
directory | .zip upload | https Git URL
  -> ingest: bounded extraction / hardened shallow clone, .git removed
  -> preflight: file count, size, depth, links, binaries, timeout, content hash
  -> detectors in parallel (static only)
       Gitleaks, Semgrep, Checkov  (packaged config, trusted cwd, repo suppressions ignored)
       first-party: missing env var, route auth, request validation
  -> normalized Finding schema -> JSON report + ingestion kind/label/revision
```

A missing, crashed or unmapped detector result makes the scan partial; a partial
scan never authorizes later processing. Checkov's overlapping IAM checks become
one finding per IAM resource.

## Finding policy (master Phase 4)

```text
report + trusted context -> hard cap -> canonical facts -> tenant-scoped cache
  -> embedded Cedar (11 policy files) -> permit | needs_human_approval | deny
```

## AI reasoning (master Phase 5)

```text
scan report + policy result -> evidence packet (grouped, sanitized, redacted, injection-flagged)
  -> route each group and the synthesis: template | small model | large model
  -> tenant content-hash cache + all-or-none leases -> budget reservation
  -> one evidence-first prompt -> forced tool or Ollama JSON schema -> schema + grounding validation
  -> accept | escalate | one corrective retry | human review with vetted template
questions -> sanitize, redact, resolve, score -> blocked | clarify | deterministic | knowledge
  | reuse explanations | synthesis | model answer (validated the same way)
```

Details: [Phase 5 guide](phase-5-reasoning.md),
[ADR 0009](ADRs/0009-tiered-validated-model-explanations.md) and
[ADR 0010](ADRs/0010-local-open-models-through-ollama.md).

## Resilient orchestration (master Phase 6)

```text
tenant-bound Strands agent | CLI | authenticated HTTP API
  -> deterministic run ID / named execution
  -> Prepare -> independent detector Map -> Merge + Cedar -> Explain -> Finalize
                 | defect / exhausted retry                |
                 +-> review item + labeled partial result  +-> vetted template fallback
  -> resume generation reuses successful content checkpoints
```

AWS uses Step Functions Standard with dedicated least-privilege Lambda roles, DynamoDB run/review
records, S3 snapshots/checkpoints, and a FIFO SQS review queue. EventBridge reconciles an execution
that fails outside the normal finalizer. Local mode interprets the exact same ASL definition and
uses SQLite/files. Details: [Phase 6 guide](phase-6-orchestration.md) and
[ADR 0011](ADRs/0011-durable-standard-workflow-and-resume.md).

## Least-privilege remediation (master Phase 7)

```text
over-broad identity policy (standalone JSON or SAM/CloudFormation YAML)
  -> activity path: StartPolicyGeneration -> poll -> GetGeneratedPolicy
       -> restrict the profile to access the replaced policy already granted
  -> estimate path: literal boto3 calls -> actions narrowed inside the original resource scope
  -> proof: local subset containment + strict narrowing (CheckNoNewAccess when reachable)
  -> before/after diff + provenance (observed_activity | static_estimate) + coverage gaps
```

Both paths are offered side by side and labelled, because a policy generated from observed
activity and one estimated from source code are not the same evidence. A cold-start principal
with no activity history is reported as such, with guidance, instead of being given a policy
dressed up as evidence. Details: [Phase 7 guide](phase-7-remediation.md),
[ADR 0012](ADRs/0012-activity-and-estimate-provenance.md) and
[ADR 0013](ADRs/0013-narrowing-proof-and-second-opinion.md).

## Reviewed proposals and local validation (master Phase 8)

```text
reviewed operations -> IAM proposal (JSON or SAM/CloudFormation YAML, never written to source)
  -> static validation: integrity, source hash, subset proof, ast syntax, code-action coverage
  -> candidate runtime (Docker --internal network):
       scanner replay (no new findings) -> sam validate
       -> DynamoDB Local + MinIO seeded from the operator manifest
       -> Lambda runtime + in-network trusted invoker -> expected response
  -> remediation Cedar gate: openPR needs static + runtime evidence + bound approval
```

## Trust boundaries

| Input | Trust | Handling |
| --- | --- | --- |
| Scanned repository, archive, Git remote | Untrusted | Never executed while scanning; its scanner config is ignored |
| Candidate code | Untrusted | Executed only in the ADR 0007 container sandbox |
| Operations, manifest, approval | Trusted operator input | Must live outside the source tree |
| Activity profile from IAM Access Analyzer | Untrusted advice | Scoped to the policy being replaced, proved narrower, reported with its CloudTrail window, never applied automatically |
| Static estimate from source calls | Untrusted | Labelled an estimate everywhere, confined to the original resource scope, never presented as observed activity |
| Packaged rules and Cedar policies | Trusted | Hashed into decisions and approvals |
| Packaged prompts, playbooks and glossary | Trusted | Versioned into every explanation cache key |
| User questions | Untrusted | Sanitized, redacted, screened for overrides; rewritten before any model sees them |
| Model output | Untrusted | Validated against schema and evidence; never alters a decision |

Decisions are recorded in [the ADRs](ADRs/).
