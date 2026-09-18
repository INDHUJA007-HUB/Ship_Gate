"""Single adapter boundary. Domain code does not select AWS services directly."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from agent.store import DynamoScanStore, LocalScanStore, ScanStore


@dataclass(frozen=True, slots=True)
class RuntimeAdapters:
    mode: str
    store: ScanStore


def load_adapters(mode: str | None = None) -> RuntimeAdapters:
    selected = mode or os.getenv("FIRST_COMMIT_MODE", "local")
    if selected == "local":
        return RuntimeAdapters(
            "local", LocalScanStore(Path(".first-commit-cache") / "state.sqlite3")
        )
    if selected == "aws":
        table = os.getenv("FIRST_COMMIT_TABLE_NAME")
        if not table:
            raise ValueError("FIRST_COMMIT_TABLE_NAME is required in aws mode")
        return RuntimeAdapters("aws", DynamoScanStore(table))
    raise ValueError("FIRST_COMMIT_MODE must be local or aws")
