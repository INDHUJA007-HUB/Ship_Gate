# Threat model

## Assets

Repository contents, uploaded archives, scan results, service credentials, and
future GitHub/AWS authorization tokens are protected assets.

## Trust boundaries

The submitted repository is untrusted. Scanner processes, future API callers,
external scanner binaries, GitHub, and AWS are separate trust boundaries.

## Primary threats and controls

| Threat | Control in this phase |
| --- | --- |
| Malicious code executes during scan | No source import/build/run path; scanners receive paths only. |
| Archive/repository resource exhaustion | File count, individual/total size, depth, binary, and wall-clock limits. |
| Symlink escape | Symlinks are not followed. |
| A missing detector looks clean | Missing/failing detectors create an explicit partial scan and non-zero exit. |
| Secret disclosure in logs | Findings retain locations and detector rule IDs; raw file contents are not logged. |
| Unsafe remediation | No remediation execution exists; future changes are PR-only by ADR. |

## Out of scope for Phase 1

Authentication, tenant isolation, GitHub OAuth/App installation, archive upload
handling, sandbox/container isolation, real AWS deployment, and runtime tracing
are later phases. They must not be represented as implemented security controls.

