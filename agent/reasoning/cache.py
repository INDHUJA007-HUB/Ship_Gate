"""Tenant-scoped explanation cache with in-flight leases.

Keys are content hashes of the evidence unit plus every version that shapes the output (prompt,
contract, knowledge, router, models, audience). Unchanged evidence therefore never re-spends a
model call, and any prompt or policy change invalidates exactly the affected entries. A lease
keeps concurrent identical requests, including separate processes, from paying twice.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Protocol


def cache_key(material: dict) -> str:
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


class ExplanationCache(Protocol):
    def get(self, tenant: str, key: str) -> dict | None: ...
    def put(self, tenant: str, key: str, value: dict) -> bool: ...
    def acquire(self, tenant: str, key: str, owner: str, ttl_seconds: int) -> bool: ...
    def release(self, tenant: str, key: str, owner: str) -> None: ...


class MemoryExplanationCache:
    def __init__(self, clock=time.time):
        self.values: dict[tuple[str, str], dict] = {}
        self.leases: dict[tuple[str, str], tuple[str, float]] = {}
        self.clock = clock
        self._lock = threading.Lock()

    def get(self, tenant, key):
        with self._lock:
            value = self.values.get((tenant, key))
            return json.loads(json.dumps(value)) if value is not None else None

    def put(self, tenant, key, value):
        with self._lock:
            if (tenant, key) in self.values:
                return False
            self.values[(tenant, key)] = json.loads(json.dumps(value))
            return True

    def acquire(self, tenant, key, owner, ttl_seconds):
        with self._lock:
            holder = self.leases.get((tenant, key))
            if holder and holder[0] != owner and holder[1] > self.clock():
                return False
            self.leases[(tenant, key)] = (owner, self.clock() + ttl_seconds)
            return True

    def release(self, tenant, key, owner):
        with self._lock:
            if self.leases.get((tenant, key), ("",))[0] == owner:
                del self.leases[(tenant, key)]


class SqliteExplanationCache:
    def __init__(self, path: Path, clock=time.time):
        self.path = path
        self.clock = clock
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(
                "CREATE TABLE IF NOT EXISTS explanations ("
                "tenant TEXT, cache_key TEXT, created INTEGER, body TEXT, "
                "PRIMARY KEY (tenant, cache_key));"
                "CREATE TABLE IF NOT EXISTS explanation_leases ("
                "tenant TEXT, cache_key TEXT, owner TEXT, expires REAL, "
                "PRIMARY KEY (tenant, cache_key));"
            )

    def _connect(self):
        return sqlite3.connect(self.path, timeout=15, isolation_level=None)

    def get(self, tenant, key):
        with self._connect() as db:
            row = db.execute(
                "SELECT body FROM explanations WHERE tenant=? AND cache_key=?", (tenant, key)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, tenant, key, value):
        with self._connect() as db:
            cursor = db.execute(
                "INSERT OR IGNORE INTO explanations VALUES (?,?,?,?)",
                (tenant, key, int(self.clock()), json.dumps(value, sort_keys=True)),
            )
            return cursor.rowcount == 1

    def acquire(self, tenant, key, owner, ttl_seconds):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT owner, expires FROM explanation_leases WHERE tenant=? AND cache_key=?",
                (tenant, key),
            ).fetchone()
            now = self.clock()
            if row and row[0] != owner and row[1] > now:
                connection.execute("COMMIT")
                return False
            connection.execute(
                "INSERT OR REPLACE INTO explanation_leases VALUES (?,?,?,?)",
                (tenant, key, owner, now + ttl_seconds),
            )
            connection.execute("COMMIT")
            return True
        except sqlite3.Error:
            connection.execute("ROLLBACK") if connection.in_transaction else None
            raise
        finally:
            connection.close()

    def release(self, tenant, key, owner):
        with self._connect() as db:
            db.execute(
                "DELETE FROM explanation_leases WHERE tenant=? AND cache_key=? AND owner=?",
                (tenant, key, owner),
            )


class DynamoExplanationCache:
    """Same single table as the control plane; the tenant partition key isolates entries."""

    def __init__(self, table: str, client=None, clock=time.time):
        if client is None:
            import boto3

            client = boto3.resource("dynamodb").Table(table)
        self.client = client
        self.clock = clock

    @staticmethod
    def _pk(tenant):
        return f"TENANT#{tenant}"

    def _conditional(self):
        return self.client.meta.client.exceptions.ConditionalCheckFailedException

    def get(self, tenant, key):
        item = self.client.get_item(Key={"PK": self._pk(tenant), "SK": f"EXPLAIN#{key}"}).get(
            "Item"
        )
        return json.loads(item["body"]) if item else None

    def put(self, tenant, key, value):
        try:
            self.client.put_item(
                Item={
                    "PK": self._pk(tenant),
                    "SK": f"EXPLAIN#{key}",
                    "entity": "Explanation",
                    "created": int(self.clock()),
                    "body": json.dumps(value, sort_keys=True),
                },
                ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
            )
            return True
        except self._conditional():
            return False

    def acquire(self, tenant, key, owner, ttl_seconds):
        now = int(self.clock())
        try:
            self.client.put_item(
                Item={
                    "PK": self._pk(tenant),
                    "SK": f"EXPLAIN_LEASE#{key}",
                    "entity": "ExplanationLease",
                    "owner": owner,
                    "expires_at": now + ttl_seconds,
                },
                ConditionExpression="attribute_not_exists(PK) OR expires_at < :now OR #o = :owner",
                ExpressionAttributeNames={"#o": "owner"},
                ExpressionAttributeValues={":now": now, ":owner": owner},
            )
            return True
        except self._conditional():
            return False

    def release(self, tenant, key, owner):
        try:
            self.client.delete_item(
                Key={"PK": self._pk(tenant), "SK": f"EXPLAIN_LEASE#{key}"},
                ConditionExpression="#o = :owner",
                ExpressionAttributeNames={"#o": "owner"},
                ExpressionAttributeValues={":owner": owner},
            )
        except self._conditional():
            pass
