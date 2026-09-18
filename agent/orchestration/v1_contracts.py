from dataclasses import dataclass, asdict
from typing import Any

@dataclass(frozen=True, slots=True)
class ValidationResultV1:
    schema_version: str
    tenant_id: str
    candidate_id: str
    status: str
    validation_digest: str
    issues: list[dict[str, Any]]
    
    def to_dict(self):
        return asdict(self)

@dataclass(frozen=True, slots=True)
class DeploymentRequestV1:
    schema_version: str
    tenant_id: str
    candidate_id: str
    validation_digest: str
    target_stack: str
    target_region: str
    approval_record_id: str
    requires_smoke_test: bool = False
    smoke_test_endpoint: str | None = None
    
    def to_dict(self):
        return asdict(self)

@dataclass(frozen=True, slots=True)
class DeploymentResultV1:
    schema_version: str
    tenant_id: str
    deployment_id: str
    candidate_id: str
    status: str
    change_set_arn: str | None
    rollback_status: str | None
    error_reason: str | None
    
    def to_dict(self):
        return asdict(self)

@dataclass(frozen=True, slots=True)
class RuntimeEvidenceV1:
    schema_version: str
    tenant_id: str
    trace_id: str
    time_window_start: int
    time_window_end: int
    status: str
    failing_hop: str | None
    redacted_logs: list[str]
    
    def to_dict(self):
        return asdict(self)
