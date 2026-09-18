# Architecture

Phase 1 is a local, deterministic scan pipeline:

```text
repository path -> preflight limits -> independent detectors -> normalizer -> JSON report
```

External detector adapters invoke Gitleaks, Semgrep, and Checkov. Product
specific Python checks identify missing environment declarations, route auth,
and request validation. All adapters emit `Finding` objects from the same
versioned schema. A stable adapter boundary reserves `local` and `aws` modes
without making AWS a Phase 1 requirement.

