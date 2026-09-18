from __future__ import annotations

import json
from pathlib import Path

from agent.models import (
    SCHEMA_VERSION,
    Evidence,
    Finding,
    FindingType,
    Location,
    ScanReport,
    Severity,
)


class ScanCache:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def _path(self, content_hash: str) -> Path:
        return self.directory / f"{content_hash}.json"

    def get(self, content_hash: str) -> ScanReport | None:
        path = self._path(content_hash)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("schema_version") != SCHEMA_VERSION or not data.get("complete"):
                return None
            findings = tuple(_finding(item) for item in data["findings"])
            return ScanReport(
                SCHEMA_VERSION, data["source"], content_hash, findings, (), cached=True
            )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def put(self, report: ScanReport) -> None:
        if not report.complete:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        target = self._path(report.content_hash)
        temporary = target.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )
        temporary.replace(target)


def _finding(item: dict) -> Finding:
    location = item["location"]
    evidence = item["evidence"]
    return Finding(
        schema_version=item["schema_version"],
        finding_id=item["finding_id"],
        finding_type=FindingType(item["finding_type"]),
        severity=Severity(item["severity"]),
        location=Location(**location),
        evidence=Evidence(**evidence),
        content_hash=item["content_hash"],
    )
