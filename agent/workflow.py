"""Deterministic async scan lifecycle shared by local and AWS entry points."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from agent.domain import Scan, ScanStatus
from agent.models import ScanReport
from agent.store import ScanStore


def stable_scan_id(tenant_id: str, content_hash: str) -> str:
    return hashlib.sha256(f"{tenant_id}\0{content_hash}".encode()).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class ScanStart:
    scan: Scan
    created: bool


def start_scan(
    store: ScanStore,
    *,
    tenant_id: str,
    content_hash: str,
    source_ref: str,
    execution_id: str | None = None,
    now: int | None = None,
) -> ScanStart:
    if not tenant_id or not content_hash or len(source_ref) > 2048:
        raise ValueError("invalid_scan_request")
    timestamp = int(time.time()) if now is None else now
    scan = Scan(
        tenant_id,
        stable_scan_id(tenant_id, content_hash),
        content_hash,
        source_ref,
        ScanStatus.QUEUED,
        timestamp,
        timestamp,
        execution_id,
    )
    return ScanStart(scan, store.create_scan(scan))


def record_scan_report(
    store: ScanStore, tenant_id: str, scan_id: str, report: ScanReport, now: int | None = None
) -> ScanStatus:
    timestamp = int(time.time()) if now is None else now
    scan = store.get_scan(tenant_id, scan_id)
    if not scan or scan.content_hash != report.content_hash:
        raise ValueError("scan_not_found_or_hash_mismatch")
    store.put_findings(tenant_id, scan_id, report.findings)
    status = ScanStatus.COMPLETED if report.complete else ScanStatus.PARTIAL
    if not store.set_scan_status(tenant_id, scan_id, status, timestamp):
        raise ValueError("scan_status_update_failed")
    return status
