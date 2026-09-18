"""Bounded, sanitized evidence packets built from Phase 3 findings and Phase 4 decisions.

Nothing here reads source code. Repository-controlled strings (paths, resource names) are
normalized, length-capped, secret-redacted and screened for instruction-like text before any
prompt sees them. Findings sharing a category, rule, decision and severity become one group,
so one explanation covers every location with the same issue.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field

from agent.models import ScanReport
from agent.reasoning.knowledge import PLAYBOOKS

PACKET_VERSION = "evidence-packet-1"
OUTCOMES = ("deny", "needs_human_approval", "permit")
OUTCOME_ORDER = {"deny": 0, "needs_human_approval": 1, "permit": 2}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CATEGORY_ORDER = {
    "secret": 0,
    "iam_wildcard": 1,
    "missing_auth": 2,
    "unsafe_command_execution": 3,
    "missing_input_validation": 4,
    "missing_environment_variable": 5,
}
GROUP_FIELDS = frozenset(
    {
        "category",
        "rule",
        "detector",
        "severity",
        "decision",
        "policy_reasons",
        "evidence",
        "environment",
        "count",
        "locations",
        "details",
        "messages",
        "shared_resource_count",
        "flags",
    }
)
SCAN_FIELDS = frozenset(
    {"complete", "detector_errors", "findings", "groups", "environment", "processing", "categories"}
)

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# Zero-width and bidirectional marks are removed, not spaced, so they cannot split a phrase.
_FORMAT = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
SECRET_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]{6,}"),
)
INSTRUCTION_LIKE = re.compile(
    r"(?i)(\b(ignore|disregard|forget|override)\b.{0,40}\b(instruction|rule|prompt|polic|previous|above)"
    r"|system\s*prompt|\byou are now\b|\bact as\b|developer mode|jailbreak"
    r"|</?\s*(system|assistant|instructions?)\s*>|\b(assistant|system)\s*:"
    r"|\bmark\b.{0,20}\b(safe|approved|resolved)\b|false[\s_-]*positive|\bdo not report\b)"
)
CHECK_ID = re.compile(r"CKV2?_[A-Z0-9_]{1,40}")
VARIABLE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


class InputRejected(ValueError):
    """The scan report and policy result are inconsistent; nothing may be explained."""


@dataclass(frozen=True)
class PacketLimits:
    max_locations: int = 12
    max_text: int = 240
    max_list: int = 8


@dataclass(frozen=True)
class Cleaned:
    text: str
    truncated: bool = False
    redacted: bool = False
    suspicious: bool = False


def clean(value: object, limit: int) -> Cleaned:
    text = unicodedata.normalize("NFKC", str(value))
    text = " ".join(_CONTROL.sub(" ", _FORMAT.sub("", text)).split())
    redacted = False
    for pattern in SECRET_PATTERNS:
        text, count = pattern.subn("[REDACTED]", text)
        redacted = redacted or bool(count)
    # File names hide phrases behind separators ("ignore_previous_instructions.py").
    suspicious = bool(
        INSTRUCTION_LIKE.search(text) or INSTRUCTION_LIKE.search(re.sub(r"[_./\\-]+", " ", text))
    )
    truncated = len(text) > limit
    if truncated:
        text = text[: limit - 1] + "…"
    return Cleaned(text, truncated, redacted, suspicious)


def stable(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class GroupLocation:
    ref: str
    path: str
    line: int | None


@dataclass(frozen=True)
class Group:
    id: str
    category: str
    rule: str
    detector: str
    severity: str
    decision: str
    reasons: tuple[str, ...]
    evidence_class: str
    environment: str | None
    finding_ids: tuple[str, ...]
    locations: tuple[GroupLocation, ...]
    locations_omitted: int
    messages: tuple[str, ...]
    details: dict = field(hash=False)
    shared_resource_count: int
    flags: tuple[str, ...]

    @property
    def count(self) -> int:
        return len(self.finding_ids)

    @property
    def playbook(self):
        return PLAYBOOKS[self.category]

    def facts(self) -> dict:
        data = {
            "id": self.id,
            "category": self.category,
            "rule": self.rule,
            "detector": self.detector,
            "severity": self.severity,
            "decision": self.decision,
            "policy_reasons": list(self.reasons),
            "evidence": self.evidence_class,
            "environment": self.environment,
            "count": self.count,
            "locations": [
                {"ref": item.ref, "path": item.path, "line": item.line} for item in self.locations
            ],
            "messages": list(self.messages),
            "shared_resource_count": self.shared_resource_count,
        }
        if self.locations_omitted:
            data["locations_omitted"] = self.locations_omitted
        if self.details:
            data["details"] = self.details
        if self.flags:
            data["flags"] = list(self.flags)
        return data

    def refs(self) -> frozenset[str]:
        refs = {self.id, *(f"{self.id}.{name}" for name in GROUP_FIELDS)}
        refs.update(item.ref for item in self.locations)
        refs.update(f"{self.id}.details.{key}" for key in self.details)
        return frozenset(refs)

    def rank_key(self) -> tuple:
        return (
            OUTCOME_ORDER[self.decision],
            SEVERITY_ORDER.get(self.severity, 5),
            CATEGORY_ORDER.get(self.category, 9),
            -self.count,
            self.rule,
            self.locations[0].path if self.locations else "",
        )


@dataclass(frozen=True)
class EvidencePacket:
    state: str
    state_reason: str | None
    source_hash: str
    policy_version: str
    environment: str | None
    complete: bool
    detector_errors: int
    total_findings: int
    processing: str
    groups: tuple[Group, ...]

    def scan_facts(self) -> dict:
        return {
            "complete": self.complete,
            "detector_errors": self.detector_errors,
            "findings": self.total_findings,
            "groups": len(self.groups),
            "environment": self.environment,
            "processing": self.processing,
            "categories": dict(
                sorted(Counter(g.category for g in self.groups for _ in g.finding_ids).items())
            ),
        }

    def group(self, group_id: str) -> Group | None:
        return next((group for group in self.groups if group.id == group_id), None)

    @property
    def priority_order(self) -> tuple[str, ...]:
        return tuple(group.id for group in self.groups)

    def scan_refs(self) -> frozenset[str]:
        return frozenset({"SCAN", *(f"SCAN.{name}" for name in SCAN_FIELDS)})

    def digest(self) -> str:
        material = {
            "version": PACKET_VERSION,
            "policy": self.policy_version,
            "scan": self.scan_facts(),
            "groups": [group.facts() for group in self.groups],
        }
        return hashlib.sha256(stable(material).encode()).hexdigest()


def _environment(decisions) -> str | None:
    values = {d.get("effective_environment") for d in decisions}
    return values.pop() if len(values) == 1 else None


def build_packet(
    report: ScanReport, policy: Mapping, limits: PacketLimits | None = None
) -> EvidencePacket:
    limits = limits or PacketLimits()
    if not isinstance(policy, Mapping):
        raise InputRejected("policy_result_invalid")
    version = policy.get("policy_version")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9a-f]{64}", version):
        raise InputRejected("policy_version_invalid")
    if policy.get("source_hash") != report.content_hash or not report.content_hash:
        raise InputRejected("policy_source_mismatch")
    state = policy.get("status")
    base = {
        "source_hash": report.content_hash,
        "policy_version": version,
        "complete": report.complete,
        "detector_errors": len(report.detector_errors),
        "total_findings": len(report.findings),
        "processing": str(policy.get("processing", "individual")),
    }
    if state != "evaluated":
        return EvidencePacket(
            state=state if state in {"denied", "capped", "error"} else "error",
            state_reason=clean(policy.get("reason") or "unknown", 80).text,
            environment=None,
            groups=(),
            **base,
        )
    decisions = policy.get("decisions")
    if not isinstance(decisions, list) or not all(isinstance(d, Mapping) for d in decisions):
        raise InputRejected("policy_decisions_invalid")
    by_id = {d.get("finding_id"): d for d in decisions}
    findings = {finding.finding_id: finding for finding in report.findings}
    if len(by_id) != len(decisions) or set(by_id) != set(findings):
        raise InputRejected("policy_findings_mismatch")
    for decision in decisions:
        if (
            decision.get("outcome") not in OUTCOMES
            or decision.get("content_hash") != report.content_hash
            or decision.get("policy_version") != version
            or str(findings[decision["finding_id"]].finding_type) not in PLAYBOOKS
        ):
            raise InputRejected("policy_decision_inconsistent")

    buckets: dict[tuple, list] = {}
    for finding in report.findings:
        decision = by_id[finding.finding_id]
        key = (
            str(finding.finding_type),
            finding.evidence.rule_id,
            finding.evidence.detector,
            decision["outcome"],
            str(decision.get("effective_severity") or finding.severity),
        )
        buckets.setdefault(key, []).append((finding, decision))

    drafts = []
    for (category, rule, detector, outcome, severity), members in buckets.items():
        members.sort(key=lambda m: (m[0].location.path, m[0].location.start_line or 0))
        flags: set[str] = set()
        details: dict[str, set] = {}
        messages: list[str] = []
        locations = []
        for finding, _ in members:
            path = clean(finding.location.path.replace("\\", "/"), limits.max_text)
            if path.suspicious:
                flags.add("untrusted_text")
            if path.truncated or path.redacted:
                flags.add("truncated")
            line = finding.location.start_line
            locations.append((path.text, line if isinstance(line, int) and line > 0 else None))
            message = clean(finding.evidence.message, limits.max_text)
            if message.suspicious:
                flags.add("untrusted_text")
            if message.text not in messages:
                messages.append(message.text)
            metadata = finding.evidence.metadata or {}
            resource = metadata.get("resource")
            if isinstance(resource, str) and resource:
                cleaned = clean(resource, 160)
                flags.update({"untrusted_text"} if cleaned.suspicious else set())
                details.setdefault("resources", set()).add(cleaned.text)
            for key in ("checks", "inline_suppressed_checks"):
                values = metadata.get(key) or []
                if isinstance(values, list):
                    details.setdefault(key, set()).update(
                        v for v in values if isinstance(v, str) and CHECK_ID.fullmatch(v)
                    )
            variable = metadata.get("environment_variable")
            if isinstance(variable, str) and VARIABLE.fullmatch(variable):
                details.setdefault("environment_variables", set()).add(variable)
        details_out = {
            key: sorted(values)[: limits.max_list] for key, values in details.items() if values
        }
        if details_out.get("inline_suppressed_checks"):
            flags.add("suppressed_checks")
        reasons = sorted(
            {r for _, d in members for r in d.get("reasons", []) if isinstance(r, str)}
        )
        classes = {d.get("evidence_class", "detector_or_heuristic") for _, d in members}
        environment = _environment([d for _, d in members])
        flags.update(
            flag
            for flag, present in (
                ("compound_risk", "compound-risk" in reasons),
                ("production", environment == "production"),
                ("batch_summary", "batch-summary-required" in reasons),
                ("known_example", "known-example-in-documentation" in reasons),
                ("many_locations", len(members) > 1),
                ("mixed_evidence", len(classes) > 1),
                ("truncated", len(members) > limits.max_locations or len(messages) > 3),
            )
            if present
        )
        drafts.append(
            {
                "category": category,
                "rule": clean(rule, 80).text,
                "detector": clean(detector, 40).text,
                "severity": severity,
                "decision": outcome,
                "reasons": tuple(reasons),
                "evidence_class": classes.pop() if len(classes) == 1 else "mixed",
                "environment": environment,
                "finding_ids": tuple(f.finding_id for f, _ in members),
                "locations": locations,
                "messages": tuple(messages[:3]),
                "details": details_out,
                "shared_resource_count": max(int(d.get("resource_count") or 1) for _, d in members),
                "flags": tuple(sorted(flags)),
            }
        )

    def rank(draft):
        return (
            OUTCOME_ORDER[draft["decision"]],
            SEVERITY_ORDER.get(draft["severity"], 5),
            CATEGORY_ORDER.get(draft["category"], 9),
            -len(draft["finding_ids"]),
            draft["rule"],
            draft["locations"][0][0],
        )

    groups = []
    for index, draft in enumerate(sorted(drafts, key=rank), start=1):
        group_id = f"G{index}"
        shown = draft.pop("locations")
        groups.append(
            Group(
                id=group_id,
                locations=tuple(
                    GroupLocation(f"{group_id}.L{n}", path, line)
                    for n, (path, line) in enumerate(shown[: limits.max_locations], start=1)
                ),
                locations_omitted=max(0, len(shown) - limits.max_locations),
                **draft,
            )
        )
    return EvidencePacket(
        state="evaluated",
        state_reason=None,
        environment=_environment(decisions),
        groups=tuple(groups),
        **base,
    )
