"""Durable domain records. IDs are content-derived; no counter can duplicate a retry."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PARTIAL = "partial"
    COMPLETED = "completed"
    TOO_LARGE = "too_large"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DeploymentStatus(StrEnum):
    REQUESTED = "requested"
    AWAITING_APPROVAL = "awaiting_approval"
    VALIDATING = "validating"
    CHANGE_SET_READY = "change_set_ready"
    DEPLOYING = "deploying"
    SUCCEEDED = "succeeded"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class Scan:
    tenant_id: str
    scan_id: str
    content_hash: str
    source_ref: str
    status: ScanStatus
    created_at: int
    updated_at: int
    execution_id: str | None = None
    revision: str | None = None

    def to_dict(self):
        data = asdict(self)
        data["status"] = str(self.status)
        return data


@dataclass(frozen=True, slots=True)
class DeploymentAttempt:
    tenant_id: str
    deployment_id: str
    scan_id: str
    proposal_id: str
    environment: str
    status: DeploymentStatus
    created_at: int
    updated_at: int
    change_set_arn: str | None = None
    rollback_status: str | None = None

    def to_dict(self):
        data = asdict(self)
        data["status"] = str(self.status)
        return data
