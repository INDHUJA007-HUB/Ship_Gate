"""Single adapter boundary. Domain code does not select AWS services directly."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from agent.orchestration.state import AwsPipelineState, LocalPipelineState, PipelineState
from agent.reasoning.cache import (
    DynamoExplanationCache,
    ExplanationCache,
    SqliteExplanationCache,
)
from agent.store import DynamoScanStore, LocalScanStore, ScanStore

LOCAL_ROOT = Path(".first-commit-cache")


@dataclass(frozen=True, slots=True)
class RuntimeAdapters:
    mode: str
    store: ScanStore
    explanations: ExplanationCache
    pipeline: PipelineState
    workspace: Path


def load_adapters(mode: str | None = None) -> RuntimeAdapters:
    selected = mode or os.getenv("FIRST_COMMIT_MODE", "local")
    if selected == "local":
        state = LOCAL_ROOT / "state.sqlite3"
        return RuntimeAdapters(
            "local",
            LocalScanStore(state),
            SqliteExplanationCache(state),
            LocalPipelineState(LOCAL_ROOT / "pipeline"),
            LOCAL_ROOT / "pipeline" / "workspace",
        )
    if selected == "aws":
        table = os.getenv("FIRST_COMMIT_TABLE_NAME")
        bucket = os.getenv("FIRST_COMMIT_ARCHIVE_BUCKET")
        if not table or not bucket:
            raise ValueError("FIRST_COMMIT_TABLE_NAME and FIRST_COMMIT_ARCHIVE_BUCKET are required")
        return RuntimeAdapters(
            "aws",
            DynamoScanStore(table),
            DynamoExplanationCache(table),
            AwsPipelineState(table, bucket, os.getenv("FIRST_COMMIT_REVIEW_QUEUE_URL")),
            # Lambda's only writable path; a warm worker reuses its verified snapshot tree.
            Path("/tmp/first-commit-workspace"),  # noqa: S108
        )
    raise ValueError("FIRST_COMMIT_MODE must be local or aws")
