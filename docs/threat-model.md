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

## Residual risks and out of scope

- Git re-resolves DNS after URL validation; hosted mode needs an egress proxy.
- Docker Desktop is a development sandbox, not a multi-tenant boundary.
- `--x-ignore-semgrepignore-files` is an internal Semgrep flag, guarded by the
  opt-in hijack integration test.
- Authentication, hosted tenant isolation, the GitHub App, real AWS deployment
  and runtime tracing are later phases. They must not be represented as
  implemented security controls.
