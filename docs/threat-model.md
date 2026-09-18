# Threat model

## Assets

Repository contents, uploaded archives, scan results, service credentials, and
future GitHub/AWS authorization tokens are protected assets.

## Trust boundaries

The submitted repository, archive or Git remote is untrusted, and so is candidate
code. Scanner processes, future API callers, external scanner binaries, GitHub,
and AWS are separate trust boundaries. Operations, validation manifests and
approvals are trusted local operator input and must live outside the source.

## Primary threats and controls

| Threat | Control |
| --- | --- |
| Malicious code executes during scan | No import/build/run path; scanners receive paths only; Git hooks, filters and submodules disabled. |
| Scanned repository blinds the scanners | Packaged scanner config, trusted working directory; repository ignore files and inline suppressions are not honored (ADR 0007). |
| Archive exhaustion or escape | Entry count, per-file and total size, compression ratio, depth, traversal, links, duplicate paths and encryption checked before writing. |
| Git URL abuse | https only; no credentials, ports or queries; non-public addresses rejected; redirects and credential helpers disabled. |
| Repository resource exhaustion | File count, individual/total size, depth, binary, and wall-clock limits. |
| Symlink escape | Links rejected by preflight, zip extraction and remediation targets; Git checks links out as plain files. |
| A missing detector looks clean | Missing, crashed or unmapped detectors create an explicit partial scan and non-zero exit. |
| Secret disclosure in logs | Findings retain locations and rule IDs; raw secrets and runtime logs are not emitted. |
| Candidate execution escapes | Digest-pinned images, internal network, dropped capabilities, read-only mounts, resource limits, forced cleanup. |
| Over-narrow fix passes locally | Emulators ignore IAM, so proposals must cover estimated code actions; results report `aws_iam_status: not_verified`. |
| Unsafe remediation | Proposals never write source; the PR gate needs runtime evidence and a bound approval; commit, merge and deploy are denied. |
| A "fix" widens access instead of narrowing it | A candidate must pass the local subset proof *and* remove at least one action or resource; `CheckNoNewAccess` is a second opinion when reachable; an inconclusive proof is reported as `needs_review` and never as recommended; AWS resource placeholders count as unknown scope. |
| An estimate is mistaken for evidence | Every recommendation names its method and confidence (`observed_activity` or `static_estimate`); a cold start is reported as `no_activity_history` with guidance, never as a policy. |
| Prompt injection through repository text | Paths, resources and messages are sanitized, flagged and sent only as JSON evidence; flagged groups go to the large model; output that echoes instructions is rejected. |
| Prompt injection or overrides in questions | Override, secret-disclosure and rule-change requests are blocked before any model call; questions are rewritten into canonical forms. |
| Model changes or undermines a decision | Decisions are copied from Cedar, never from the model; claims such as "false positive" or "safe to deploy" fail validation; the report asserts decisions are unchanged. |
| Hallucinated or malformed output | Forced tools, full local schema and grounding validation, one corrective retry, then human review with the vetted template. |
| Secrets reach or leave a model | Secret values never enter evidence; question secrets are redacted; credential-like output is rejected. |
| Cost exhaustion or retry storms | Worst-case budget reservation, bounded attempts, circuit breaker, content-hash cache and concurrency leases. |
| Local-model traffic leaves the host | Ollama accepts only loopback HTTP, disables proxies and redirects, and rejects every `:cloud` model tag. |
| Local model cannot hold the evidence | `/api/show` context preflight includes prompt, schema, output allowance and margin; overflow degrades before inference rather than truncating silently. |
| Unreviewed model download or disk exhaustion | First Commit never pulls weights; installation and license review remain explicit operator actions. |
| Cross-tenant explanation reuse | Tenant is part of every cache key and the DynamoDB partition key. |
| Duplicate work from at-least-once delivery | Named executions, content-derived IDs, conditional writes, detector fingerprints and write-once checkpoints. |
| One detector failure hides valid results | Independent Map catches create incomplete checks; merge keeps successful checkpoints and names missing coverage. |
| Retry storm multiplies scanner/model cost | Error-class-specific bounded retries; checkpoint/cache reads after writes; one-call Strands guard. |
| Stale review work after recovery | A successful resumed check resolves only its older review records; records remain auditable. |
| Workflow dies before final status | EventBridge reconciles failed/timed-out/aborted Standard executions; missing event input is recovered with scoped `DescribeExecution`. |
| Agent crosses tenant or changes a decision | Tenant/user are bound outside tool arguments; compact tool results contain no source; Cedar results are immutable to Strands. |

## Residual risks and out of scope

- Git re-resolves DNS after URL validation; hosted mode needs an egress proxy.
- Docker Desktop is a development sandbox, not a multi-tenant boundary.
- `--x-ignore-semgrepignore-files` is an internal Semgrep flag, guarded by the
  opt-in hijack integration test.
- Cognito/JWT authentication, per-tenant storage keys, workflow roles, and tracing are represented
  in the SAM template but are not proven controls until the stack is deployed. The GitHub App,
  real AWS deployment, egress proxy, and runtime trace ingestion remain later phases.
