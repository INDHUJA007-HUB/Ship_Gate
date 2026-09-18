"""Explanation cache semantics for the SQLite, DynamoDB and in-memory adapters."""

import pytest

from agent.reasoning.cache import (
    DynamoExplanationCache,
    MemoryExplanationCache,
    SqliteExplanationCache,
    cache_key,
)


class Clock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now


class ConditionalCheckFailed(Exception):
    pass


class FakeTable:
    """Implements exactly the conditional expressions the DynamoDB adapter uses."""

    def __init__(self):
        self.items = {}
        self.meta = type(
            "Meta",
            (),
            {
                "client": type(
                    "Client",
                    (),
                    {
                        "exceptions": type(
                            "E", (), {"ConditionalCheckFailedException": ConditionalCheckFailed}
                        )
                    },
                )
            },
        )

    def get_item(self, Key):
        item = self.items.get((Key["PK"], Key["SK"]))
        return {"Item": dict(item)} if item else {}

    def put_item(
        self,
        Item,
        ConditionExpression,
        ExpressionAttributeNames=None,
        ExpressionAttributeValues=None,
    ):
        key = (Item["PK"], Item["SK"])
        existing = self.items.get(key)
        if ConditionExpression == "attribute_not_exists(PK) AND attribute_not_exists(SK)":
            allowed = existing is None
        else:
            values = ExpressionAttributeValues
            allowed = (
                existing is None
                or existing["expires_at"] < values[":now"]
                or existing["owner"] == values[":owner"]
            )
        if not allowed:
            raise ConditionalCheckFailed()
        self.items[key] = dict(Item)

    def delete_item(
        self, Key, ConditionExpression, ExpressionAttributeNames, ExpressionAttributeValues
    ):
        key = (Key["PK"], Key["SK"])
        if key not in self.items or self.items[key]["owner"] != ExpressionAttributeValues[":owner"]:
            raise ConditionalCheckFailed()
        del self.items[key]


@pytest.fixture(params=["memory", "sqlite", "dynamo"])
def cache(request, tmp_path):
    clock = Clock()
    if request.param == "memory":
        return MemoryExplanationCache(clock), clock
    if request.param == "sqlite":
        return SqliteExplanationCache(tmp_path / "explanations.sqlite3", clock), clock
    return DynamoExplanationCache("table", client=FakeTable(), clock=clock), clock


def test_first_writer_wins_and_tenants_are_isolated(cache):
    store, _ = cache
    assert store.get("a", "k") is None
    assert store.put("a", "k", {"status": "model_validated", "value": 1})
    assert not store.put("a", "k", {"status": "model_validated", "value": 2})
    assert store.get("a", "k")["value"] == 1
    assert store.get("b", "k") is None


def test_leases_block_others_until_released_or_expired(cache):
    store, clock = cache
    assert store.acquire("a", "k", "worker-1", 60)
    assert store.acquire("a", "k", "worker-1", 60)  # re-entrant for the holder
    assert not store.acquire("a", "k", "worker-2", 60)
    assert store.acquire("b", "k", "worker-2", 60)  # other tenant, other lease
    store.release("a", "k", "worker-2")  # not the holder: no effect
    assert not store.acquire("a", "k", "worker-2", 60)
    store.release("a", "k", "worker-1")
    assert store.acquire("a", "k", "worker-2", 60)
    clock.now += 61
    assert store.acquire("a", "k", "worker-3", 60)


def test_cache_keys_are_order_independent_content_hashes():
    first = cache_key({"tenant": "a", "facts": {"x": 1, "y": [1, 2]}})
    assert first == cache_key({"facts": {"y": [1, 2], "x": 1}, "tenant": "a"})
    assert first != cache_key({"tenant": "b", "facts": {"x": 1, "y": [1, 2]}})
    assert len(first) == 64
