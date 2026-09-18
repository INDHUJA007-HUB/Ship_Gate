# ADR 0007: candidate execution sandbox and untrusted scanner configuration

Status: Accepted. Date: 2026-09-11.

## Context

ADR 0006 requires runtime validation of the actual candidate before a PR can be
proposed. That means executing submitted code, which the scan path never does.

Separately, verification against the real tools showed that a scanned repository
could silence every wrapped scanner: a repository `.gitleaks.toml`,
`.gitleaksignore`, `.semgrepignore` and `.checkov.yaml` reduced Gitleaks, Semgrep
and Checkov to zero findings on a repository with a live-looking key, a
`shell=True` call and a wildcard IAM role.

## Decision

1. Scanning never executes input. Candidate code executes only in
   `validate-candidate`, inside containers from digest-pinned images on a Docker
   `--internal` network: all capabilities dropped, `no-new-privileges`, CPU,
   memory and PID limits, read-only root and code mount, non-root Lambda user,
   bounded logs and forced cleanup. A trusted invoker sends the smoke request from
   inside the network; no port is published to the host.
2. The validation manifest (event, expected response, seed data) is trusted
   operator input and must live outside the submitted tree. Dependency builds
   (`requirements.txt`, `pyproject.toml`, ...) and repository `samconfig.toml`
   are not honored.
3. Local emulators do not enforce IAM. A proposal must also grant every action
   estimated from literal boto3 client calls, and results always report
   `aws_iam_status: not_verified`.
4. Scanners run from a trusted scratch directory with packaged configuration:
   Gitleaks `--config`, an empty `--gitleaks-ignore-path` and
   `--ignore-gitleaks-allow`; Semgrep `--disable-nosem`,
   `--x-ignore-semgrepignore-files` and `--no-git-ignore`; Checkov with explicit
   `-f` targets (directory mode loads repository config) and without `--quiet`,
   so inline-skipped IAM checks are still reported.
5. Git URLs are shallow-cloned over https only, with hooks, symlinks,
   submodules, LFS, credential helpers and redirects disabled; `.git` is removed
   before scanning. Zip uploads are extracted by Python with path, link,
   duplicate, encryption, ratio and size checks before any byte is written.

## Consequences

- Runtime validation needs Docker and the three pinned images; they are never
  pulled implicitly.
- `--x-ignore-semgrepignore-files` is an internal Semgrep flag. The opt-in
  hijack integration test fails if an upgrade changes its behavior.
- Legitimate inline suppressions also resurface, as findings for human review.
- Docker Desktop is a development sandbox, not a multi-tenant boundary. Hosted
  mode needs a stronger isolation layer (for example gVisor or Firecracker) and
  an egress proxy, since Git re-resolves DNS after URL validation.
