"""Stable, versioned normalized output shared by every detector."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = "1.0"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(StrEnum):
    SECRET = "secret"
    IAM_WILDCARD = "iam_wildcard"
    MISSING_AUTH = "missing_auth"
    MISSING_INPUT_VALIDATION = "missing_input_validation"
    MISSING_ENVIRONMENT_VARIABLE = "missing_environment_variable"
    UNSAFE_COMMAND_EXECUTION = "unsafe_command_execution"


@dataclass(frozen=True, slots=True)
class Location:
    path: str
    start_line: int | None = None
    end_line: int | None = None


@dataclass(frozen=True, slots=True)
class Evidence:
    detector: str
    rule_id: str
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Finding:
    schema_version: str
    finding_id: str
    finding_type: FindingType
    severity: Severity
    location: Location
    evidence: Evidence
    content_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DetectorResult:
    detector: str
    findings: tuple[Finding, ...]
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ScanReport:
    schema_version: str
    source: str
    content_hash: str
    findings: tuple[Finding, ...]
    detector_errors: tuple[str, ...]
    cached: bool = False

    @property
    def complete(self) -> bool:
        return not self.detector_errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source": self.source,
            "content_hash": self.content_hash,
            "findings": [finding.to_dict() for finding in self.findings],
            "detector_errors": list(self.detector_errors),
            "complete": self.complete,
            "cached": self.cached,
        }
