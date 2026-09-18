# Local verification — 2026-09-11

Environment: Windows, Python 3.13.14, isolated `.venv`, cedarpy 4.8.7 native
Windows wheel. No AWS resources were provisioned.

- `python -m pytest --basetemp .test-temp/phase23 -q`: 24 passed, 1 skipped.
- `python -m ruff check .`: all checks passed.
- Real Cedar evaluations cover permit, approval required, deny overrides,
  malformed policy, stale source, cross-tenant context, wrong environment,
  expired approval, and policy/proposal binding changes.
- Real subprocess CLI test creates a new proposal, validates it, confirms the
  PR gate denies without runtime evidence, and refuses output overwrite.
- IAM tests cover narrowing, expansion, cross-statement action/resource mixing,
  unsupported conditional/negative/principal constructs, and invalid evidence.
- Tests verify read-only validation, proposal tampering, changed source,
  source-code non-execution, binary hash invalidation, and bounded directories.
- Existing scan tests still pass; unexpected detector errors preserve partial
  findings without exposing exception text.
- Wheel build succeeded; Cedar source, trusted SAM template, event, and handler
  are present in the installable archive.
- Actual `validate-runtime`: blocked, `missing_dependency:sam` and
  `missing_dependency:docker`. Timeout behavior is tested with fault injection.

Skipped: creating a symlink requires a privilege unavailable in this Windows
session. CI includes Linux and Windows, Python 3.12/3.13, but CI has not run on
GitHub and its results are not claimed here.

Not verified: candidate runtime replay, DynamoDB Local/MinIO behavior, SAM
execution, AWS IAM, cloud deployment, and upstream scanner executable integration.
Those remain explicit phase/environment gaps, not successful checks.
