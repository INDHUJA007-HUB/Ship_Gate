from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from agent.store import paginate_query


class FakeDynamoTable:
    def __init__(self, items: list[dict], page_size: int = 2):
        self.items = items
        self.page_size = page_size
        self.calls = 0

    def query(self, **kwargs):
        self.calls += 1
        start = 0
        if "ExclusiveStartKey" in kwargs:
            # Simple fake logic: LastEvaluatedKey is just the index of the last item returned
            start = kwargs["ExclusiveStartKey"]["index"]
        
        end = start + self.page_size
        page_items = self.items[start:end]
        
        response = {"Items": page_items}
        if end < len(self.items):
            response["LastEvaluatedKey"] = {"index": end}
            
        return response


def test_paginate_query_returns_all_items_across_pages():
    items = [{"id": i} for i in range(5)]
    table = FakeDynamoTable(items, page_size=2)
    
    result = paginate_query(table)
    
    assert result == items
    assert table.calls == 3


def test_paginate_query_prevents_infinite_loop():
    class LoopingTable:
        def query(self, **kwargs):
            return {"Items": [{"id": 1}], "LastEvaluatedKey": {"token": "same_token"}}
            
    table = LoopingTable()
    result = paginate_query(table, max_pages=10)
    
    # Should only return one page because the token repeats immediately
    assert len(result) == 1


def test_no_raw_single_page_queries_in_repo():
    agent_dir = Path(__file__).parent.parent
    
    for py_file in agent_dir.rglob("*.py"):
        # We don't audit tests themselves or the store.py helper implementation
        if py_file.name in ("test_dynamo_pagination.py", "store.py"):
            continue
            
        content = py_file.read_text(encoding="utf-8")
        
        # Look for .query( which isn't the paginate_query helper
        lines = content.splitlines()
        for idx, line in enumerate(lines):
            # Check if there is a raw .query( call on a dynamodb table
            # Exclude our local pipeline sqlite execute("... query ...") or similar string manipulation
            if ".query(" in line and "execute(" not in line and "paginate_query(" not in line:
                # In our codebase, boto3 table query is the main concern
                # There should be exactly zero .query( calls outside paginate_query
                raise AssertionError(f"Found raw .query() at {py_file.name}:{idx+1}:\n{line}")
