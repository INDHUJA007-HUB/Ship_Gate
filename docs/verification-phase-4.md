# Phase 4 verification

Verified locally on Windows with the isolated Python 3.13 environment and real
cedarpy 4.8.7 native engine.

- Full suite: **44 passed, 1 skipped**.
- Ruff lint: all checks passed.
- CLI subprocess integration: saved scan -> policy report -> repeat cache hit.
- SQLite audit integration: one stored record for retry, explicit tenant/user,
  creation time and versioned finding decisions; no evidence prose persisted.
- Native Cedar tests: default deny; explicit missing-environment forbid;
  cross-tenant and stale-source denial; conservative production resolution;
  compound-risk and volume escalation; 89/90/91 confidence boundaries; high
  severity override; known-example/path conjunction; unknown confidence ignored.
- Cost tests: reversed finding ordering and changed filesystem root preserve
  cache hits; changed tenant/user/policy and partial-scan state invalidate;
  four simultaneous identical requests evaluate once; hard cap issues zero
  Cedar requests; model calls remain zero.
- Failure tests: malformed policy fails closed and is not cached; an empty
  partial scan cannot pass by vacuous success.
- Built wheel includes all ten finding policy files and the Python implementation.

The single skip is the existing symlink creation test: Windows lacks the needed
privilege. No GitHub CI run, AVP request, or Bedrock call is claimed. Cloud
durable storage, API authentication and Phase 5 inference remain future work.
Phase 3 remains on hold.
