import json
import sqlite3

import pytest

from agent.adapters import load_adapters
from agent.domain import DeploymentAttempt, DeploymentStatus, ScanStatus
from agent.finding_policy import FindingPolicy, PolicyContext
from agent.models import (
    SCHEMA_VERSION,
    Evidence,
    Finding,
    FindingType,
    Location,
    ScanReport,
    Severity,
)
from agent.store import ConflictError, LocalScanStore
from agent.workflow import record_scan_report, start_scan


def finding():
    return Finding(
        SCHEMA_VERSION,
        "finding",
        FindingType.MISSING_ENVIRONMENT_VARIABLE,
        Severity.MEDIUM,
        Location("app.py", 2),
        Evidence("test", "rule", "safe"),
        "content",
    )


def test_local_and_aws_adapter_selection(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert load_adapters("local").mode == "local"
    monkeypatch.delenv("FIRST_COMMIT_TABLE_NAME", raising=False)
    with pytest.raises(ValueError):
        load_adapters("aws")
    monkeypatch.setenv("FIRST_COMMIT_TABLE_NAME", "table")
    assert load_adapters("aws").mode == "aws"
    with pytest.raises(ValueError):
        load_adapters("unknown")


def test_local_store_migrates_pre_content_hash_schema(tmp_path):
    path = tmp_path / "state.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE scans (tenant TEXT, scan_id TEXT, body TEXT, "
            "PRIMARY KEY (tenant, scan_id))"
        )
    LocalScanStore(path)
    with sqlite3.connect(path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(scans)")}
    assert "content_hash" in columns


def test_content_idempotency_tenant_isolation_and_status(tmp_path):
    store = LocalScanStore(tmp_path / "state.sqlite3")
    first = start_scan(store, tenant_id="a", content_hash="content", source_ref="repo", now=1)
    again = start_scan(store, tenant_id="a", content_hash="content", source_ref="repo", now=2)
    other = start_scan(store, tenant_id="b", content_hash="content", source_ref="repo", now=3)
    assert first.created and not again.created and other.created
    assert first.scan.scan_id == again.scan.scan_id
    assert store.get_scan("b", first.scan.scan_id) is None
    report = ScanReport(SCHEMA_VERSION, "repo", "content", (finding(),), ())
    assert record_scan_report(store, "a", first.scan.scan_id, report, now=4) == ScanStatus.COMPLETED
    assert len(store.get_findings("a", first.scan.scan_id)) == 1
    assert store.get_findings("b", first.scan.scan_id) == []
    assert store.put_findings("a", first.scan.scan_id, (finding(),)) == 0
    with pytest.raises(ConflictError):
        store.put_findings("b", first.scan.scan_id, (finding(),))


def test_partial_scan_and_deployment_attempts(tmp_path):
    store = LocalScanStore(tmp_path / "state.sqlite3")
    started = start_scan(store, tenant_id="a", content_hash="content", source_ref="repo", now=1)
    report = ScanReport(SCHEMA_VERSION, "repo", "content", (), ("gitleaks: unavailable",))
    assert record_scan_report(store, "a", started.scan.scan_id, report, now=2) == ScanStatus.PARTIAL
    attempt = DeploymentAttempt(
        "a",
        "deploy",
        started.scan.scan_id,
        "proposal",
        "development",
        DeploymentStatus.AWAITING_APPROVAL,
        3,
        3,
    )
    assert store.create_deployment(attempt)
    assert not store.create_deployment(attempt)
    assert store.get_deployment("a", "deploy").status == DeploymentStatus.AWAITING_APPROVAL
    assert store.get_deployment("b", "deploy") is None


def test_policy_decisions_share_the_store_boundary(tmp_path):
    store = LocalScanStore(tmp_path / "state.sqlite3")
    report = ScanReport(SCHEMA_VERSION, "repo", "content", (finding(),), ())
    context = PolicyContext("tenant", "user", "tenant", ("development",), "content")
    policy = FindingPolicy(store=store)
    first = policy.evaluate(report, context)
    second = policy.evaluate(report, context)
    assert first["policy_version"]
    assert not first["cached"] and second["cached"]


def test_api_async_contract(monkeypatch, tmp_path):
    import api.handlers as handlers

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FIRST_COMMIT_MODE", "local")
    event = {
        "body": json.dumps({"source_ref": "https://github.com/example/repo"}),
        "headers": {"x-first-commit-tenant": "tenant"},
        "requestContext": {"http": {"method": "POST", "path": "/scans"}},
    }
    result = handlers.router_handler(event, None)
    body = json.loads(result["body"])
    assert result["statusCode"] == 202
    assert body["status"] == "queued" and body["execution_id"].startswith("local-")
    event["requestContext"]["http"] = {"method": "GET", "path": f"/scans/{body['scan_id']}"}
    event["pathParameters"] = {"scan_id": body["scan_id"]}
    assert handlers.router_handler(event, None)["statusCode"] == 200
