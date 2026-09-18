# Architecture

The built system is a local, deterministic core. The AWS layers in the master
reference (API Gateway, Step Functions, DynamoDB, S3, Cognito, Bedrock) are not
provisioned yet; `infra/template.yaml` only declares the findings table.

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

## Remediation and local validation (master Phases 7-8)

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
| Packaged rules and Cedar policies | Trusted | Hashed into decisions and approvals |

Decisions are recorded in [the ADRs](ADRs/).
