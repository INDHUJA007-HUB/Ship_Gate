"""Durable pipeline state behind one interface: SQLite and files locally, DynamoDB/S3/SQS on AWS.

Runs          one record per run, updated with generation-aware merges so a late duplicate
              step (Lambda and Step Functions are at-least-once) cannot roll an outcome back.
Checkpoints   write-once JSON keyed by content: a retry rewrites nothing, and a resume reuses
              every detector result that already succeeded.
Snapshots     the preflighted source as a deterministic, uncompressed zip keyed by content hash.
Review items  the dead-letter path: write-once per (run, generation, step), plus a queue message
              on AWS so a person is notified exactly once.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

from agent.orchestration.contracts import tenant_key

FINAL = {"completed", "partial", "failed"}


class StateUnavailable(RuntimeError):
    """Storage could not be reached; callers treat it as transient."""


class PipelineState(Protocol):
    def create_run(self, run: dict) -> bool: ...
    def get_run(self, tenant: str, run_id: str) -> dict | None: ...
    def update_run(self, tenant: str, run_id: str, changes: dict) -> dict | None: ...
    def get_checkpoint(self, tenant: str, key: str) -> dict | None: ...
    def put_checkpoint(self, tenant: str, key: str, body: dict) -> bool: ...
    def put_snapshot(self, tenant: str, content_hash: str, archive: Path) -> bool: ...
    def fetch_snapshot(self, tenant: str, content_hash: str, destination: Path) -> bool: ...
    def fetch_upload(self, tenant: str, name: str, destination: Path) -> bool: ...
    def put_review(self, item: dict) -> bool: ...
    def list_reviews(self, tenant: str, run_id: str | None = None) -> list[dict]: ...
    def resolve_reviews(self, tenant: str, run_id: str, step: str, generation: int) -> int: ...


def merge_run(current: dict, changes: dict) -> dict | None:
    """Apply `changes` unless they come from an older generation or undo a final outcome."""
    generation = changes.get("generation", current.get("generation", 0))
    if generation < current.get("generation", 0):
        return None
    same = generation == current.get("generation", 0)
    if same and current.get("status") in FINAL and changes.get("status") in {"queued", "running"}:
        return None
    return {**current, **changes, "version": current.get("version", 0) + 1}


class LocalPipelineState:
    def __init__(self, root: Path, clock=time.time):
        self.root = root
        self.clock = clock
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "pipeline.sqlite3"
        self.snapshots = root / "snapshots"
        self.uploads = root / "uploads"
        self._lock = threading.Lock()
        with self._connect() as db:
            db.executescript(
                "CREATE TABLE IF NOT EXISTS runs (tenant TEXT, run_id TEXT, body TEXT, "
                "PRIMARY KEY (tenant, run_id));"
                "CREATE TABLE IF NOT EXISTS checkpoints (tenant TEXT, key TEXT, body TEXT, "
                "created INTEGER, PRIMARY KEY (tenant, key));"
                "CREATE TABLE IF NOT EXISTS reviews (tenant TEXT, review_id TEXT, run_id TEXT, "
                "body TEXT, created INTEGER, PRIMARY KEY (tenant, review_id));"
            )

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        try:
            with db:  # Commits on success, rolls back on error.
                yield db
        finally:
            db.close()

    def create_run(self, run):
        with self._connect() as db:
            try:
                db.execute(
                    "INSERT INTO runs VALUES (?,?,?)",
                    (run["tenant_id"], run["run_id"], json.dumps(run, sort_keys=True)),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def get_run(self, tenant, run_id):
        with self._connect() as db:
            row = db.execute(
                "SELECT body FROM runs WHERE tenant=? AND run_id=?", (tenant, run_id)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def update_run(self, tenant, run_id, changes):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            db.execute("BEGIN IMMEDIATE")  # Serializes concurrent step updates across processes.
            row = db.execute(
                "SELECT body FROM runs WHERE tenant=? AND run_id=?", (tenant, run_id)
            ).fetchone()
            merged = merge_run(json.loads(row[0]), changes) if row else None
            if merged:
                db.execute(
                    "UPDATE runs SET body=? WHERE tenant=? AND run_id=?",
                    (json.dumps(merged, sort_keys=True), tenant, run_id),
                )
            db.execute("COMMIT")
            return merged
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    def get_checkpoint(self, tenant, key):
        with self._connect() as db:
            row = db.execute(
                "SELECT body FROM checkpoints WHERE tenant=? AND key=?", (tenant, key)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put_checkpoint(self, tenant, key, body):
        with self._connect() as db:
            try:
                db.execute(
                    "INSERT INTO checkpoints VALUES (?,?,?,?)",
                    (tenant, key, json.dumps(body, sort_keys=True), int(self.clock())),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def _snapshot_path(self, tenant, content_hash):
        return self.snapshots / tenant_key(tenant) / f"{content_hash}.zip"

    def put_snapshot(self, tenant, content_hash, archive):
        target = self._snapshot_path(tenant, content_hash)
        with self._lock:
            if target.exists():
                return False
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_suffix(f".{threading.get_ident()}.tmp")
            shutil.copyfile(archive, temporary)
            temporary.replace(target)
            return True

    def fetch_snapshot(self, tenant, content_hash, destination):
        source = self._snapshot_path(tenant, content_hash)
        if not source.is_file():
            return False
        shutil.copyfile(source, destination)
        return True

    def fetch_upload(self, tenant, name, destination):
        source = self.uploads / tenant_key(tenant) / name
        if not source.is_file():
            return False
        shutil.copyfile(source, destination)
        return True

    def put_review(self, item):
        with self._connect() as db:
            try:
                db.execute(
                    "INSERT INTO reviews VALUES (?,?,?,?,?)",
                    (
                        item["tenant_id"],
                        item["review_id"],
                        item["run_id"],
                        json.dumps(item, sort_keys=True),
                        int(self.clock()),
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def list_reviews(self, tenant, run_id=None):
        query = "SELECT body FROM reviews WHERE tenant=?"
        parameters: tuple = (tenant,)
        if run_id:
            query, parameters = query + " AND run_id=?", (tenant, run_id)
        with self._connect() as db:
            rows = db.execute(query + " ORDER BY created, review_id", parameters).fetchall()
        return [json.loads(row[0]) for row in rows]

    def resolve_reviews(self, tenant, run_id, step, generation):
        """Close older review items after the same check succeeds on a resumed generation."""
        resolved = 0
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT review_id, body FROM reviews WHERE tenant=? AND run_id=?",
                (tenant, run_id),
            ).fetchall()
            for review_id, encoded in rows:
                item = json.loads(encoded)
                if (
                    item.get("step") != step
                    or item.get("status") != "open"
                    or item.get("generation", generation) >= generation
                ):
                    continue
                item.update(
                    status="resolved",
                    resolved_by_generation=generation,
                    resolved_at=int(self.clock()),
                )
                db.execute(
                    "UPDATE reviews SET body=? WHERE tenant=? AND review_id=?",
                    (json.dumps(item, sort_keys=True), tenant, review_id),
                )
                resolved += 1
            db.execute("COMMIT")
            return resolved
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()


def _error_code(error: Exception) -> str | None:
    return getattr(error, "response", {}).get("Error", {}).get("Code")


class AwsPipelineState:
    """DynamoDB for runs and review items, S3 for checkpoints and snapshots, SQS for review."""

    def __init__(
        self,
        table: str,
        bucket: str,
        queue_url: str | None = None,
        *,
        dynamodb=None,
        s3=None,
        sqs=None,
        clock=time.time,
    ):
        if dynamodb is None or s3 is None or (queue_url and sqs is None):
            import boto3

            dynamodb = dynamodb or boto3.resource("dynamodb").Table(table)
            s3 = s3 or boto3.client("s3")
            sqs = sqs or (boto3.client("sqs") if queue_url else None)
        self.table, self.bucket, self.queue_url = dynamodb, bucket, queue_url
        self.s3, self.sqs, self.clock = s3, sqs, clock

    @staticmethod
    def _pk(tenant):
        return f"TENANT#{tenant}"

    def _conditional(self):
        return self.table.meta.client.exceptions.ConditionalCheckFailedException

    def _key(self, tenant, *parts):
        return "/".join(("tenant", tenant_key(tenant), *parts))

    def create_run(self, run):
        try:
            self.table.put_item(
                Item={
                    "PK": self._pk(run["tenant_id"]),
                    "SK": f"RUN#{run['run_id']}",
                    "entity": "PipelineRun",
                    "version": run.get("version", 0),
                    "body": json.dumps(run, sort_keys=True),
                },
                ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
            )
            return True
        except self._conditional():
            return False

    def get_run(self, tenant, run_id):
        item = self.table.get_item(Key={"PK": self._pk(tenant), "SK": f"RUN#{run_id}"}).get("Item")
        return json.loads(item["body"]) if item else None

    def update_run(self, tenant, run_id, changes):
        for _ in range(5):  # Optimistic concurrency on the record version.
            current = self.get_run(tenant, run_id)
            merged = merge_run(current, changes) if current else None
            if not merged:
                return None
            try:
                self.table.put_item(
                    Item={
                        "PK": self._pk(tenant),
                        "SK": f"RUN#{run_id}",
                        "entity": "PipelineRun",
                        "version": merged["version"],
                        "body": json.dumps(merged, sort_keys=True),
                    },
                    ConditionExpression="version = :version",
                    ExpressionAttributeValues={":version": current.get("version", 0)},
                )
                return merged
            except self._conditional():
                continue
        raise StateUnavailable("run_update_conflict")

    def get_checkpoint(self, tenant, key):
        try:
            response = self.s3.get_object(
                Bucket=self.bucket, Key=self._key(tenant, "checkpoints", f"{key}.json")
            )
        except Exception as error:
            if _error_code(error) in {"NoSuchKey", "404"}:
                return None
            raise
        return json.loads(response["Body"].read())

    def put_checkpoint(self, tenant, key, body):
        try:
            self.s3.put_object(
                Bucket=self.bucket,
                Key=self._key(tenant, "checkpoints", f"{key}.json"),
                Body=json.dumps(body, sort_keys=True).encode(),
                ContentType="application/json",
                IfNoneMatch="*",  # S3 conditional write: the first writer wins.
            )
            return True
        except Exception as error:
            if _error_code(error) in {"PreconditionFailed", "ConditionalRequestConflict"}:
                return False
            raise

    def put_snapshot(self, tenant, content_hash, archive):
        try:
            with archive.open("rb") as body:
                self.s3.put_object(
                    Bucket=self.bucket,
                    Key=self._key(tenant, "snapshots", f"{content_hash}.zip"),
                    Body=body,
                    ContentType="application/zip",
                    IfNoneMatch="*",
                )
            return True
        except Exception as error:
            if _error_code(error) in {"PreconditionFailed", "ConditionalRequestConflict"}:
                return False
            raise

    def _download(self, key, destination):
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
        except Exception as error:
            if _error_code(error) in {"NoSuchKey", "404"}:
                return False
            raise
        with destination.open("wb") as output:
            shutil.copyfileobj(response["Body"], output)
        return True

    def fetch_snapshot(self, tenant, content_hash, destination):
        return self._download(self._key(tenant, "snapshots", f"{content_hash}.zip"), destination)

    def fetch_upload(self, tenant, name, destination):
        return self._download(self._key(tenant, "uploads", name), destination)

    def put_review(self, item):
        created = True
        try:
            self.table.put_item(
                Item={
                    "PK": self._pk(item["tenant_id"]),
                    "SK": f"REVIEW#{item['run_id']}#{item['review_id']}",
                    "entity": "ReviewItem",
                    "body": json.dumps(item, sort_keys=True),
                },
                ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
            )
        except self._conditional():
            created = False
        if self.sqs and self.queue_url:
            # Sent even when the record already existed: a retry after a failed send must still
            # notify. FIFO deduplication on the review ID drops the duplicate otherwise.
            self.sqs.send_message(
                QueueUrl=self.queue_url,
                MessageBody=json.dumps(item, sort_keys=True),
                MessageGroupId=tenant_key(item["tenant_id"]),
                MessageDeduplicationId=item["review_id"],
            )
        return created

    def list_reviews(self, tenant, run_id=None):
        from boto3.dynamodb.conditions import Key

        prefix = f"REVIEW#{run_id}#" if run_id else "REVIEW#"
        response = self.table.query(
            KeyConditionExpression=Key("PK").eq(self._pk(tenant)) & Key("SK").begins_with(prefix)
        )
        return [json.loads(item["body"]) for item in response.get("Items", [])]

    def resolve_reviews(self, tenant, run_id, step, generation):
        """Optimistically close older review records without erasing their audit history."""
        from boto3.dynamodb.conditions import Key

        prefix = f"REVIEW#{run_id}#"
        response = self.table.query(
            KeyConditionExpression=Key("PK").eq(self._pk(tenant)) & Key("SK").begins_with(prefix)
        )
        resolved = 0
        for record in response.get("Items", []):
            item = json.loads(record["body"])
            if (
                item.get("step") != step
                or item.get("status") != "open"
                or item.get("generation", generation) >= generation
            ):
                continue
            previous = record["body"]
            item.update(
                status="resolved",
                resolved_by_generation=generation,
                resolved_at=int(self.clock()),
            )
            try:
                self.table.update_item(
                    Key={"PK": record["PK"], "SK": record["SK"]},
                    UpdateExpression="SET #body = :body",
                    ConditionExpression="#body = :previous",
                    ExpressionAttributeNames={"#body": "body"},
                    ExpressionAttributeValues={
                        ":body": json.dumps(item, sort_keys=True),
                        ":previous": previous,
                    },
                )
                resolved += 1
            except self._conditional():
                continue
        return resolved
