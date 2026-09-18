"""Shared Phase 5 fixtures: the planted-issue scan, real Cedar decisions, and scripted models."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

from agent.config import Settings
from agent.finding_policy import FindingPolicy, PolicyContext
from agent.models import FindingType, ScanReport, Severity
from agent.normalize import normalized_finding
from agent.reasoning.evidence import build_packet
from agent.reasoning.knowledge import template_explanation
from agent.reasoning.providers import ModelResponse
from agent.reasoning.service import template_synthesis
from agent.scan import ScanService

GOLDEN = Path(__file__).parents[2] / "fixtures" / "golden-repo"


def golden_report() -> ScanReport:
    """The planted-issue fixture: first-party findings plus the Checkov and Gitleaks shapes."""
    base = ScanService(Settings(), external_detectors=False).scan(GOLDEN)
    extra = (
        normalized_finding(
            finding_type=FindingType.IAM_WILDCARD,
            severity=Severity.HIGH,
            root=GOLDEN,
            path="infra/template.yaml",
            line=3,
            detector="checkov",
            rule_id="iam-policy-overly-permissive",
            message="IAM policy grants unconstrained access: CKV_AWS_108, CKV_AWS_109, CKV_AWS_111",
            content_hash=base.content_hash,
            metadata={
                "resource": "AWS::IAM::Role.UploadFunctionRole",
                "checks": ["CKV_AWS_108", "CKV_AWS_109", "CKV_AWS_111"],
                "inline_suppressed_checks": [],
            },
        ),
        normalized_finding(
            finding_type=FindingType.SECRET,
            severity=Severity.CRITICAL,
            root=GOLDEN,
            path="src/credentials.py",
            line=1,
            detector="gitleaks",
            rule_id="aws-access-token",
            message="Identified a pattern that may indicate AWS credentials",
            content_hash=base.content_hash,
            metadata={"known_example": False},
        ),
    )
    return replace(base, findings=tuple(sorted(base.findings + extra, key=lambda f: f.finding_id)))


def evaluate(report: ScanReport, tmp_path: Path, environments=("development",), tenant="tenant-a"):
    return FindingPolicy(tmp_path / "policy.sqlite3").evaluate(
        report, PolicyContext(tenant, "alice", tenant, tuple(environments), report.content_hash)
    )


def sections(prompt: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in re.finditer(r"<(\w+)>\n(.*?)\n</\1>", prompt, re.S)}


def tool_response(payload, *, model="claude-opus-5", stop="tool_use", tokens=(1200, 400), **extra):
    return ModelResponse(
        tool_input=payload,
        stop_reason=stop,
        model=model,
        input_tokens=tokens[0],
        output_tokens=tokens[1],
        **extra,
    )


class GroundedModel:
    """A well-behaved model: grounded explanations for exactly the requested groups."""

    def __init__(self, report: ScanReport, policy: dict, mutate=None):
        self.packet = build_packet(report, policy)
        self.mutate = mutate or (lambda request, payload, attempt: payload)
        self.calls = 0

    def __call__(self, request):
        self.calls += 1
        parts = sections(request.user)
        if request.tool["name"] == "submit_explanations":
            requested = [g for g in parts["requested_groups"].split(",") if g.startswith("G")]
            payload = {
                "explanations": [
                    {"group_id": g, **template_explanation(self.packet.group(g))} for g in requested
                ],
                "synthesis": template_synthesis(self.packet)
                if parts.get("priority_order")
                else None,
            }
        elif request.tool["name"] == "submit_answer":
            evidence = json.loads(parts["evidence"])
            refs = [g["id"] for g in evidence["groups"]] or ["SCAN"]
            payload = {
                "answer": "The evidence shows what the detector matched; a reviewer should confirm "
                "the context before any change, and the policy decision stays in place.",
                "key_points": ["The policy decision is final."],
                "refs": refs,
                "answerable": True,
                "limitation": "none",
                "follow_up": "",
                "escalation": "none",
            }
        else:
            payload = {
                "intent": "general",
                "group_ids": [],
                "difficulty": "low",
                "needs_clarification": True,
                "clarifying_question": "Which finding do you mean?",
            }
        payload = self.mutate(request, payload, self.calls)
        if isinstance(payload, ModelResponse):
            return payload
        return tool_response(payload, model=request.model)
