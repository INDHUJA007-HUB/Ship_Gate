"""Bounded embedded Cedar triage. No model calls or remediation authorization."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

import cedarpy

from agent.models import Finding, ScanReport

ENGINE_VERSION = "finding-policy-1"
# Deterministic rule certainty, not severity and never model self-confidence.
RULE_CONFIDENCE = {
    ("first-commit-patterns", "missing-required-environment"): 90,
    ("first-commit-patterns", "route-missing-auth"): 70,
    ("first-commit-patterns", "route-missing-input-validation"): 70,
    ("gitleaks", "aws-access-token"): 95,
}
CATEGORIES = {
    "secret",
    "iam_wildcard",
    "missing_auth",
    "missing_input_validation",
    "missing_environment_variable",
}


def stable(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class PolicyContext:
    tenant: str
    user: str
    owner: str
    environments: tuple[str, ...]
    current_hash: str


@dataclass(frozen=True)
class PolicyLimits:
    max_findings: int = 500
    summary_threshold: int = 100
    compound_threshold: int = 3

    def __post_init__(self):
        if not 1 <= self.compound_threshold <= self.summary_threshold <= self.max_findings <= 5000:
            raise ValueError("Invalid policy processing limits")


def facts(finding: Finding):
    path = finding.location.path.replace("\\", "/")
    parts = PurePosixPath(path).parts
    valid_path = bool(parts) and not path.startswith("/") and ":" not in path and ".." not in parts
    # A path alone never downgrades a secret. The adapter must attest an exact known example.
    example = (
        finding.finding_type == "secret"
        and finding.evidence.detector == "gitleaks"
        and finding.evidence.rule_id == "aws-access-token"
        and finding.evidence.metadata.get("known_example") is True
        and valid_path
        and bool(set(parts[:-1]) & {"test", "tests", "fixtures", "docs"})
    )
    resource = finding.evidence.metadata.get("resource")
    if not isinstance(resource, str) or not resource or len(resource) > 256:
        resource = path  # Conservative file-level grouping when no shared resource ID exists.
    return {
        "id": finding.finding_id,
        "source": finding.content_hash,
        "category": str(finding.finding_type),
        "path": path,
        "line": finding.location.start_line,
        "severity": str(finding.severity),
        "resource": resource,
        "example": example,
        "validPath": valid_path,
        "confidence": RULE_CONFIDENCE.get(
            (finding.evidence.detector, finding.evidence.rule_id), 50
        ),
        "detector": finding.evidence.detector,
        "rule": finding.evidence.rule_id,
    }


class FindingPolicy:
    def __init__(self, cache_path: Path, limits: PolicyLimits | None = None):
        directory = Path(__file__).parent / "policies" / "findings"
        self.policy_text = "\n".join(
            p.read_text(encoding="utf-8") for p in sorted(directory.glob("*.cedar"))
        )
        self.version = hashlib.sha256(self.policy_text.encode()).hexdigest()
        self.reason_names = dict(enumerate(re.findall(r'@id\("([^"]+)"\)', self.policy_text)))
        self.limits = limits or PolicyLimits()
        self.cache_path = cache_path
        # Parse errors are caught during evaluate and never treated as a clean result.
        self._parsed = None

    def evaluate(self, report: ScanReport, context: PolicyContext):
        base = {
            "schema_version": "1.0",
            "policy_version": self.version,
            "engine_version": ENGINE_VERSION,
            "source_hash": report.content_hash,
            "model_calls": 0,
            "backend": "embedded_cedar",
            "cached": False,
            "total_findings": len(report.findings),
        }
        if len(report.findings) > self.limits.max_findings:
            return {
                **base,
                "status": "capped",
                "processing": "batch_summary",
                "reason": "finding_cap_exceeded",
                "decisions": [],
                "cedar_requests": 0,
            }
        normalized = sorted((facts(f) for f in report.findings), key=stable)
        material = {
            "facts": normalized,
            "context": asdict(context),
            "source": report.content_hash,
            "complete": report.complete,
            "policy": self.version,
            "engine": ENGINE_VERSION,
            "limits": asdict(self.limits),
        }
        # Environment order and duplicate tags cannot create retry cache misses.
        material["context"]["environments"] = sorted(set(context.environments))
        key = hashlib.sha256(stable(material).encode()).hexdigest()
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.cache_path, timeout=10)
        except (OSError, sqlite3.Error):
            return {
                **base,
                "status": "error",
                "reason": "policy_cache_unavailable",
                "decisions": [],
                "cedar_requests": 0,
            }
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS decisions "
                "(key TEXT PRIMARY KEY, tenant TEXT, user TEXT, created INTEGER, result TEXT)"
            )
            # Serializes concurrent misses, including separate CLI processes; evaluation is bounded.
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT result FROM decisions WHERE key=? AND tenant=? AND user=?",
                (key, context.tenant, context.user),
            ).fetchone()
            if row:
                result = json.loads(row[0])
                connection.commit()
                return {**result, "cached": True, "cedar_requests": 0}
            result = self._evaluate(normalized, report, context, base)
            if result["status"] != "error":
                connection.execute(
                    "INSERT INTO decisions VALUES (?,?,?,?,?)",
                    (key, context.tenant, context.user, int(time.time()), stable(result)),
                )
            connection.commit()
            return result
        except (sqlite3.Error, ValueError, TypeError):
            connection.rollback()
            return {
                **base,
                "status": "error",
                "reason": "policy_cache_or_engine_error",
                "decisions": [],
                "cedar_requests": 0,
            }
        finally:
            connection.close()

    def _evaluate(self, normalized, report, context, base):
        environments = set(context.environments)
        known = {"development", "staging", "production"}
        environment = (
            "production"
            if len(environments) > 1 or "production" in environments
            else next(iter(environments), None)
        )
        valid = bool(context.tenant and context.user and context.owner) and environments <= known
        counts = Counter(f["resource"] for f in normalized)
        common = {
            "sameTenant": context.tenant == context.owner,
            "valid": valid,
            "complete": report.complete,
            "fresh": bool(report.content_hash) and report.content_hash == context.current_hash,
            "findingCount": len(normalized),
            "summaryThreshold": self.limits.summary_threshold,
            "compoundThreshold": self.limits.compound_threshold,
        }
        if not normalized and not (
            valid
            and environment is not None
            and common["sameTenant"]
            and common["complete"]
            and common["fresh"]
        ):
            return {
                **base,
                "status": "denied",
                "reason": "missing_or_invalid_scan_context",
                "decisions": [],
                "cedar_requests": 0,
            }
        entities, requests = [], []
        for index, finding in enumerate(normalized):
            attrs = {
                "category": finding["category"],
                "confidence": finding["confidence"],
                "severity": finding["severity"],
                "example": finding["example"],
                "resourceCount": counts[finding["resource"]],
            }
            if environment is not None:
                attrs["environment"] = environment
            uid = {"type": "Finding", "id": str(index)}
            entities.append({"uid": uid, "attrs": attrs, "parents": []})
            for action in ("process", "review"):
                requests.append(
                    {
                        "principal": f"User::{json.dumps(context.user)}",
                        "resource": f'Finding::"{index}"',
                        "action": f'Action::"{action}"',
                        "context": {
                            **common,
                            "valid": valid
                            and finding["validPath"]
                            and finding["category"] in CATEGORIES,
                            "fresh": common["fresh"] and finding["source"] == report.content_hash,
                        },
                    }
                )
        try:
            if self._parsed is None:
                self._parsed = cedarpy.PolicySet.from_str(self.policy_text)
            results = (
                cedarpy.is_authorized_batch(requests, self._parsed, entities) if requests else []
            )
            decisions = []
            for index, finding in enumerate(normalized):
                process, review = results[index * 2 : index * 2 + 2]
                errors = bool(process.diagnostics.errors or review.diagnostics.errors)
                outcome = (
                    "deny"
                    if errors
                    else "permit"
                    if process.allowed
                    else "needs_human_approval"
                    if review.allowed
                    else "deny"
                )
                decisions.append(
                    {
                        "finding_id": finding["id"],
                        "outcome": outcome,
                        "policy_version": self.version,
                        "content_hash": finding["source"],
                        "effective_environment": environment,
                        "confidence_percent": finding["confidence"],
                        "effective_severity": "info" if finding["example"] else finding["severity"],
                        "resource_count": counts[finding["resource"]],
                        "reasons": sorted(
                            {
                                self.reason_names.get(int(reason.removeprefix("policy")), reason)
                                for reason in set(process.diagnostics.reasons)
                                | set(review.diagnostics.reasons)
                            }
                        ),
                        "evaluation_error": errors,
                    }
                )
            return {
                **base,
                "status": "error" if any(d["evaluation_error"] for d in decisions) else "evaluated",
                "decisions": decisions,
                "category_counts": dict(sorted(Counter(f["category"] for f in normalized).items())),
                "processing": "batch_summary"
                if len(normalized) >= self.limits.summary_threshold
                else "individual",
                "cedar_requests": len(requests),
            }
        except Exception:
            return {
                **base,
                "status": "error",
                "reason": "cedar_evaluation_error",
                "decisions": [],
                "cedar_requests": len(requests),
            }
