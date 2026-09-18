"""Tenant-bound persistence adapters: SQLite locally and DynamoDB in AWS."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Protocol

from agent.domain import DeploymentAttempt, DeploymentStatus, Scan, ScanStatus
from agent.models import Finding


class ConflictError(RuntimeError):
    pass


class ScanStore(Protocol):
    def create_scan(self, scan: Scan) -> bool: ...
    def get_scan(self, tenant_id: str, scan_id: str) -> Scan | None: ...
    def set_scan_status(
        self, tenant_id: str, scan_id: str, status: ScanStatus, updated_at: int
    ) -> bool: ...
    def put_findings(self, tenant_id: str, scan_id: str, findings: tuple[Finding, ...]) -> int: ...
    def get_findings(self, tenant_id: str, scan_id: str) -> list[dict]: ...
    def create_deployment(self, attempt: DeploymentAttempt) -> bool: ...
    def get_deployment(self, tenant_id: str, deployment_id: str) -> DeploymentAttempt | None: ...
    def get_policy_decision(self, tenant_id: str, user_id: str, key: str) -> dict | None: ...
    def put_policy_decision(self, tenant_id: str, user_id: str, key: str, result: dict) -> bool: ...


class LocalScanStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            db.executescript(
                "CREATE TABLE IF NOT EXISTS scans ("
                "tenant TEXT, scan_id TEXT, content_hash TEXT NOT NULL, body TEXT, "
                "PRIMARY KEY (tenant, scan_id));"
                "CREATE TABLE IF NOT EXISTS findings ("
                "tenant TEXT, scan_id TEXT, finding_id TEXT, body TEXT, "
                "PRIMARY KEY (tenant, scan_id, finding_id));"
                "CREATE TABLE IF NOT EXISTS deployments ("
                "tenant TEXT, deployment_id TEXT, body TEXT, "
                "PRIMARY KEY (tenant, deployment_id));"
                "CREATE TABLE IF NOT EXISTS policy_decisions ("
                "tenant TEXT, user_id TEXT, cache_key TEXT, body TEXT, "
                "PRIMARY KEY (tenant, user_id, cache_key));"
            )
            columns = {row[1] for row in db.execute("PRAGMA table_info(scans)")}
            if "content_hash" not in columns:
                # Preserve pre-adapter local state. Old records cannot safely deduplicate by hash.
                db.execute("ALTER TABLE scans ADD COLUMN content_hash TEXT NOT NULL DEFAULT ''")
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS scans_content ON scans(tenant, content_hash)"
            )

    def _connection(self):
        return sqlite3.connect(self.path, timeout=10)

    @staticmethod
    def _scan(data):
        return Scan(
            **{
                key: (ScanStatus(data[key]) if key == "status" else data[key])
                for key in Scan.__dataclass_fields__
            }
        )

    @staticmethod
    def _deployment(data):
        return DeploymentAttempt(
            **{
                key: (DeploymentStatus(data[key]) if key == "status" else data[key])
                for key in DeploymentAttempt.__dataclass_fields__
            }
        )

    def create_scan(self, scan):
        with self._connection() as db:
            try:
                db.execute(
                    "INSERT INTO scans VALUES (?,?,?,?)",
                    (
                        scan.tenant_id,
                        scan.scan_id,
                        scan.content_hash,
                        json.dumps(scan.to_dict()),
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def get_scan(self, tenant_id, scan_id):
        with self._connection() as db:
            row = db.execute(
                "SELECT body FROM scans WHERE tenant=? AND scan_id=?", (tenant_id, scan_id)
            ).fetchone()
        return self._scan(json.loads(row[0])) if row else None

    def set_scan_status(self, tenant_id, scan_id, status, updated_at):
        scan = self.get_scan(tenant_id, scan_id)
        if not scan:
            return False
        updated = Scan(**{**scan.to_dict(), "status": status, "updated_at": updated_at})
        with self._connection() as db:
            db.execute(
                "UPDATE scans SET body=? WHERE tenant=? AND scan_id=?",
                (json.dumps(updated.to_dict()), tenant_id, scan_id),
            )
        return True

    def put_findings(self, tenant_id, scan_id, findings):
        if not self.get_scan(tenant_id, scan_id):
            raise ConflictError("scan_not_found_for_tenant")
        written = 0
        with self._connection() as db:
            for finding in findings:
                try:
                    db.execute(
                        "INSERT INTO findings VALUES (?,?,?,?)",
                        (
                            tenant_id,
                            scan_id,
                            finding.finding_id,
                            json.dumps(finding.to_dict(), sort_keys=True),
                        ),
                    )
                    written += 1
                except sqlite3.IntegrityError:
                    pass
        return written

    def get_findings(self, tenant_id, scan_id):
        with self._connection() as db:
            rows = db.execute(
                "SELECT body FROM findings WHERE tenant=? AND scan_id=? ORDER BY finding_id",
                (tenant_id, scan_id),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def create_deployment(self, attempt):
        with self._connection() as db:
            try:
                db.execute(
                    "INSERT INTO deployments VALUES (?,?,?)",
                    (attempt.tenant_id, attempt.deployment_id, json.dumps(attempt.to_dict())),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def get_deployment(self, tenant_id, deployment_id):
        with self._connection() as db:
            row = db.execute(
                "SELECT body FROM deployments WHERE tenant=? AND deployment_id=?",
                (tenant_id, deployment_id),
            ).fetchone()
        return self._deployment(json.loads(row[0])) if row else None

    def get_policy_decision(self, tenant_id, user_id, key):
        with self._connection() as db:
            row = db.execute(
                "SELECT body FROM policy_decisions WHERE tenant=? AND user_id=? AND cache_key=?",
                (tenant_id, user_id, key),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put_policy_decision(self, tenant_id, user_id, key, result):
        with self._connection() as db:
            try:
                db.execute(
                    "INSERT INTO policy_decisions VALUES (?,?,?,?)",
                    (tenant_id, user_id, key, json.dumps(result, sort_keys=True)),
                )
                return True
            except sqlite3.IntegrityError:
                return False


class DynamoScanStore:
    """Boto3 adapter. DynamoDB conditional writes make retries idempotent."""

    def __init__(self, table, client=None):
        import boto3

        self.table = table
        self.client = client or boto3.resource("dynamodb").Table(table)

    @staticmethod
    def _pk(tenant):
        return f"TENANT#{tenant}"

    @staticmethod
    def _scan_key(scan):
        return f"SCAN#{scan}"

    def create_scan(self, scan):
        item = {
            "PK": self._pk(scan.tenant_id),
            "SK": self._scan_key(scan.scan_id),
            "entity": "Scan",
            **scan.to_dict(),
        }
        try:
            self.client.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
            )
            return True
        except self.client.meta.client.exceptions.ConditionalCheckFailedException:
            return False

    def get_scan(self, tenant_id, scan_id):
        result = self.client.get_item(
            Key={"PK": self._pk(tenant_id), "SK": self._scan_key(scan_id)}
        )
        item = result.get("Item")
        return (
            Scan(
                **{
                    key: (ScanStatus(item[key]) if key == "status" else item.get(key))
                    for key in Scan.__dataclass_fields__
                }
            )
            if item
            else None
        )

    def set_scan_status(self, tenant_id, scan_id, status, updated_at):
        try:
            self.client.update_item(
                Key={"PK": self._pk(tenant_id), "SK": self._scan_key(scan_id)},
                ConditionExpression="attribute_exists(PK)",
                UpdateExpression="SET #s=:s, updated_at=:u",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":s": str(status), ":u": updated_at},
            )
            return True
        except self.client.meta.client.exceptions.ConditionalCheckFailedException:
            return False

    def put_findings(self, tenant_id, scan_id, findings):
        written = 0
        for finding in findings:
            try:
                self.client.put_item(
                    Item={
                        "PK": self._pk(tenant_id),
                        "SK": f"FINDING#{scan_id}#{finding.finding_id}",
                        "entity": "Finding",
                        "scan_id": scan_id,
                        "finding": finding.to_dict(),
                    },
                    ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
                )
                written += 1
            except self.client.meta.client.exceptions.ConditionalCheckFailedException:
                pass
        return written

    def get_findings(self, tenant_id, scan_id):
        from boto3.dynamodb.conditions import Key

        result = self.client.query(
            KeyConditionExpression=Key("PK").eq(self._pk(tenant_id))
            & Key("SK").begins_with(f"FINDING#{scan_id}#")
        )
        return [item["finding"] for item in result.get("Items", [])]

    def create_deployment(self, attempt):
        try:
            self.client.put_item(
                Item={
                    "PK": self._pk(attempt.tenant_id),
                    "SK": f"DEPLOYMENT#{attempt.deployment_id}",
                    "entity": "DeploymentAttempt",
                    **attempt.to_dict(),
                },
                ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
            )
            return True
        except self.client.meta.client.exceptions.ConditionalCheckFailedException:
            return False

    def get_deployment(self, tenant_id, deployment_id):
        result = self.client.get_item(
            Key={"PK": self._pk(tenant_id), "SK": f"DEPLOYMENT#{deployment_id}"}
        )
        item = result.get("Item")
        return (
            DeploymentAttempt(
                **{
                    key: (DeploymentStatus(item[key]) if key == "status" else item.get(key))
                    for key in DeploymentAttempt.__dataclass_fields__
                }
            )
            if item
            else None
        )

    def get_policy_decision(self, tenant_id, user_id, key):
        result = self.client.get_item(
            Key={"PK": self._pk(tenant_id), "SK": f"POLICY#{user_id}#{key}"}
        )
        item = result.get("Item")
        return item.get("result") if item else None

    def put_policy_decision(self, tenant_id, user_id, key, result):
        try:
            self.client.put_item(
                Item={
                    "PK": self._pk(tenant_id),
                    "SK": f"POLICY#{user_id}#{key}",
                    "entity": "PolicyDecision",
                    "policy_version": result.get("policy_version"),
                    "source_hash": result.get("source_hash"),
                    "result": result,
                },
                ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
            )
            return True
        except self.client.meta.client.exceptions.ConditionalCheckFailedException:
            return False
