# Phase 7 verification — 2026-09-14

Environment: Windows 11, Python 3.13 virtual environment, cedarpy 4.8.7, SAM CLI 1.166.1,
Docker 29.7.2. **No AWS resource was created, read or called.** IAM Access Analyzer is exercised
through a scripted client that speaks the same protocol, exactly as the hosted Step Functions
tests use a stand-in client.

## Acceptance evidence

The phase exit criteria are *"the tool correctly distinguishes generated-from-real-activity from
estimated-from-static-analysis, and both paths produce a policy strictly narrower than the
original"*. Each half is pinned by a test:

| Exit criterion | Evidence |
| --- | --- |
| Activity and estimate results are distinguishable | `test_methods_are_labelled_and_never_presented_as_the_same_thing`: different `method`, different `label`, different `confidence`, and both labels present in the rendered report |
| Both are visible at once, neither hidden | Same test plus `test_cli_prints_the_method_and_the_before_after_diff`: an unavailable activity attempt keeps its own method and reason (`role_required_for_activity`, `access_analyzer_not_configured`) instead of disappearing behind the estimate |
| Activity path is strictly narrower | `test_activity_generated_policy_is_strictly_narrower_with_a_before_after_diff`: `s3:*` and `dynamodb:*` removed, candidate is `s3:GetObject`/`s3:PutObject` on the observed resource ARN, both the focused policy diff and the document patch contain the change |
| Estimate path is strictly narrower | `test_static_estimate_narrows_actions_and_keeps_exact_statements`: wildcard statements narrowed or dropped, already-exact statement untouched, `retained_resource_wildcards == 1` reported rather than hidden |
| Cold start handled, not faked | `test_no_activity_history_yields_guidance_and_a_labelled_estimate` (a succeeded-but-empty job becomes `no_activity_history` + "run your app a few times first", and the fallback is labelled an estimate) and `test_activity_only_mode_fails_closed_without_history` |
| Nothing is claimed that was not proved | `test_a_condition_makes_the_local_proof_inconclusive_rather_than_confident`, `test_an_already_narrow_policy_is_never_presented_as_a_narrowing`, `test_aws_check_blocks_a_candidate_that_allows_new_access`, `test_aws_verification_failure_becomes_a_reason_code` |
| A generated profile is scoped to the policy it replaces | `test_generated_actions_outside_the_replaced_policy_are_dropped_and_reported` (the role's other-policy access is dropped and reported as `actions_outside_replaced_policy`, and the attempt is downgraded to `needs_review`) |
| Coverage gaps are stated | `test_estimate_reports_unresolved_and_ungranted_code` (`boto3.resource` file listed as unresolved, `sqs:SendMessage` reported as never granted by the current policy) |
| Read-only, deterministic | `test_recommendation_is_read_only_and_deterministic`: the target file is byte-identical after two runs and the recommendation ID is stable |
| Governance still gates it | `test_unknown_environment_or_tenant_is_denied` (Cedar denies an unknown environment) |

The live CLI run against the fixture produces the same result the tests assert:

```text
status: recommended
== method: static_estimate ==
provenance: Estimated from static analysis of the source (no activity history used)
narrowing: strictly_narrower (static_identity_policy_subset)
removed: dynamodb:*, s3:*
kept: s3:GetObject, s3:PutObject, sqs:SendMessage
retained resource wildcards: 1
```

## Verification commands

```powershell
python -m pytest agent/tests/test_access_analyzer.py agent/tests/test_least_privilege.py `
  agent/tests/test_packaging_manifest.py -q --basetemp .pytest-tmp/phase7
python -m ruff check .
first-commit remediate-iam fixtures/least-privilege-repo infra/template.yaml `
  --tenant demo --environment development --method static
```

Focused result: **32 passed** (12 analyzer-boundary, 15 engine, 5 packaging guards). Full suite:
**257 passed, 7 skipped**. Ruff is clean, including `ruff format --check`.

## Not verified

- A live `StartPolicyGeneration` / `GetGeneratedPolicy` / `CheckNoNewAccess` call, a real
  CloudTrail window, or a generated policy returned by AWS. Request and response shapes are pinned
  by tests against the documented API, and every AWS failure path is mapped to a bounded reason
  code, but no live response has been seen.
- Behaviour on a role whose *managed* policies also grant access: the engine compares the policy
  document it is replacing, and reports access observed outside that scope, but it does not yet
  assemble a role's full effective policy set.
- A hosted route for this engine. None was added, deliberately: unused
  `access-analyzer:*` permissions in a least-privilege tool would contradict the phase's own goal.

## Phase 6 closure carried in this change

The container build that Phase 6 left open is now done, and it paid for itself by finding a real
packaging bug. Details and raw evidence are in
[the Phase 6 verification record](verification-phase-6.md#container-build-2026-09-14).
