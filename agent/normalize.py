from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from agent.models import SCHEMA_VERSION, Evidence, Finding, FindingType, Location, Severity


def normalized_finding(
    *,
    finding_type: FindingType,
    severity: Severity,
    root: Path,
    path: str | Path,
    line: int | None,
    detector: str,
    rule_id: str,
    message: str,
    content_hash: str,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    candidate = Path(path)
    if not candidate.is_absolute():
        # Relative detector paths are relative to the scan root, never the process directory.
        candidate = root / candidate
    try:
        relative = candidate.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        relative = Path(path).as_posix()
    stable = "|".join((finding_type, relative, str(line), detector, rule_id, content_hash))
    finding_id = hashlib.sha256(stable.encode("utf-8")).hexdigest()[:20]
    return Finding(
        schema_version=SCHEMA_VERSION,
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        location=Location(relative, line, line),
        evidence=Evidence(detector, rule_id, message, metadata or {}),
        content_hash=content_hash,
    )
