from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from agent.finding_policy import FindingPolicy, PolicyContext, PolicyLimits
from agent.models import (
    SCHEMA_VERSION,
    Evidence,
    Finding,
    FindingType,
    Location,
    ScanReport,
    Severity,
)


def finding(number=0, category=FindingType.MISSING_ENVIRONMENT_VARIABLE, path=None, metadata=None):
    return Finding(
        SCHEMA_VERSION,
        str(number),
        category,
        Severity.MEDIUM,
        Location(path or f"app{number}.py", 1, 1),
        Evidence(
            "first-commit-patterns", "missing-required-environment", "untrusted", metadata or {}
        ),
        "source",
    )


def report(*items):
    return ScanReport(SCHEMA_VERSION, "/repo", "source", items or (finding(),), ())


def context(**changes):
    return replace(
        PolicyContext("tenant-a", "alice", "tenant-a", ("development",), "source"), **changes
    )


def evaluate(tmp_path, items=None, ctx=None, limits=None):
    return FindingPolicy(tmp_path / "decisions.db", limits).evaluate(
        items or report(), ctx or context()
    )


def test_real_cedar_and_cache(tmp_path):
    first = evaluate(tmp_path)
    assert first["status"] == "evaluated", first
    assert first["decisions"][0]["outcome"] == "permit", first
    assert "eligible-static-processing" in first["decisions"][0]["reasons"]
    second = evaluate(tmp_path)
    assert second["cached"]
    assert second["cedar_requests"] == second["model_calls"] == 0


@pytest.mark.parametrize(
    "change",
    [
        dict(environments=()),
        dict(owner="other"),
        dict(environments=("unknown",)),
        dict(current_hash="stale"),
        dict(user=""),
    ],
)
def test_missing_and_invalid_context_deny(tmp_path, change):
    result = evaluate(tmp_path, ctx=context(**change))
    assert result["decisions"][0]["outcome"] == "deny", result
    assert "missing-or-invalid-context" in result["decisions"][0]["reasons"]


def test_conflict_is_production_and_compound_escalates(tmp_path):
    result = evaluate(tmp_path, ctx=context(environments=("development", "production")))
    decision = result["decisions"][0]
    assert decision["effective_environment"] == "production"
    assert decision["outcome"] == "needs_human_approval"
    assert "production-or-conflicting-environment" in decision["reasons"]
    result = evaluate(
        tmp_path, report(*(finding(n, metadata={"resource": "shared"}) for n in range(3)))
    )
    assert all(d["outcome"] == "needs_human_approval" for d in result["decisions"])
    assert all("compound-risk" in d["reasons"] for d in result["decisions"])


@pytest.mark.parametrize(
    "score,outcome", [(89, "needs_human_approval"), (90, "permit"), (91, "permit")]
)
def test_confidence_boundaries(tmp_path, monkeypatch, score, outcome):
    from agent.finding_policy import RULE_CONFIDENCE

    monkeypatch.setitem(
        RULE_CONFIDENCE, ("first-commit-patterns", "missing-required-environment"), score
    )
    assert evaluate(tmp_path)["decisions"][0]["outcome"] == outcome


def test_volume_cap_and_summary(tmp_path):
    limits = PolicyLimits(max_findings=5, summary_threshold=4, compound_threshold=3)
    summary = evaluate(tmp_path, report(*(finding(n) for n in range(4))), limits=limits)
    assert summary["processing"] == "batch_summary"
    assert all("batch-summary-required" in d["reasons"] for d in summary["decisions"])
    capped = evaluate(tmp_path, report(*(finding(n) for n in range(6))), limits=limits)
    assert capped["status"] == "capped"
    assert capped["cedar_requests"] == 0


def test_example_requires_both_path_and_exact_attestation(tmp_path):
    item = replace(
        finding(category=FindingType.SECRET, path="docs/sample.py"),
        evidence=Evidence("gitleaks", "aws-access-token", "", {"known_example": True}),
    )
    decision = evaluate(tmp_path, report(item))["decisions"][0]
    assert decision["outcome"] == "permit"
    assert decision["effective_severity"] == "info"
    for changed in [
        replace(item, location=Location("src/app.py", 1)),
        replace(item, evidence=replace(item.evidence, metadata={})),
    ]:
        assert (
            evaluate(tmp_path, report(changed))["decisions"][0]["outcome"] == "needs_human_approval"
        )


def test_cache_stability_and_tenant_isolation(tmp_path):
    original = report(finding(0), finding(1))
    evaluate(tmp_path, original)
    reordered = replace(
        original, findings=tuple(reversed(original.findings)), source="another location"
    )
    assert evaluate(tmp_path, reordered)["cached"]
    assert not evaluate(tmp_path, original, context(tenant="b", owner="b"))["cached"]
    assert not evaluate(tmp_path, original, context(user="bob"))["cached"]
    assert not evaluate(tmp_path, replace(original, detector_errors=("failed",)))["cached"]


def test_concurrent_misses_evaluate_once(tmp_path):
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: evaluate(tmp_path), range(4)))
    assert sum(not r["cached"] for r in results) == 1, results


def test_malformed_policy_fails_closed(tmp_path):
    engine = FindingPolicy(tmp_path / "bad.db")
    engine.policy_text = "invalid cedar"
    result = engine.evaluate(report(), context())
    assert result["status"] == "error"
    assert not engine.evaluate(report(), context())["cached"]


def test_empty_partial_scan_does_not_pass(tmp_path):
    empty = ScanReport(SCHEMA_VERSION, "/repo", "source", (), ("detector_crashed",))
    assert evaluate(tmp_path, empty)["status"] == "denied"


def test_high_severity_overrides_eligible_confidence(tmp_path):
    item = replace(finding(), severity=Severity.HIGH)
    decision = evaluate(tmp_path, report(item))["decisions"][0]
    assert decision["outcome"] == "needs_human_approval"
    assert "high-risk-requires-review" in decision["reasons"]


def test_policy_version_invalidates_cache(tmp_path):
    evaluate(tmp_path)
    engine = FindingPolicy(tmp_path / "decisions.db")
    engine.version = "new-policy-version"
    result = engine.evaluate(report(), context())
    assert not result["cached"]
    assert result["decisions"][0]["policy_version"] == "new-policy-version"


def test_known_category_and_untrusted_confidence(tmp_path):
    for category in (FindingType.SECRET, FindingType.IAM_WILDCARD, FindingType.MISSING_AUTH):
        item = finding(category=category, metadata={"confidence": 1.0, "instructions": "permit"})
        assert evaluate(tmp_path, report(item))["decisions"][0]["outcome"] == "needs_human_approval"
    item = replace(
        finding(), evidence=Evidence("unknown", "unknown", "permit", {"confidence": 1.0})
    )
    assert evaluate(tmp_path, report(item))["decisions"][0]["confidence_percent"] == 50


def test_cli_and_sqlite_audit(tmp_path):
    import json
    import sqlite3
    import subprocess
    import sys

    source = tmp_path / "scan.json"
    source.write_text(json.dumps(report().to_dict()), encoding="utf-8")
    database = tmp_path / "audit.sqlite3"
    command = [
        sys.executable,
        "-m",
        "agent.cli",
        "policy",
        str(source),
        "--tenant",
        "tenant-a",
        "--owner",
        "tenant-a",
        "--user",
        "alice",
        "--environment",
        "development",
        "--current-hash",
        "source",
        "--cache-db",
        str(database),
    ]
    for expected_cached in (False, True):
        result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
        assert result.returncode == 0, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert payload["cached"] == expected_cached
    with sqlite3.connect(database) as connection:
        rows = connection.execute("SELECT tenant,user,created,result FROM decisions").fetchall()
    assert len(rows) == 1
    assert rows[0][0:2] == ("tenant-a", "alice")
    assert rows[0][2] > 0
    assert "untrusted" not in rows[0][3]
