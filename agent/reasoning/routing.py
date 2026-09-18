"""Deterministic, explainable difficulty routing across three tiers.

Tier 0 renders a vetted template with no model call. The small tier handles bulk,
classification-shaped work; the large tier handles nuanced security reasoning and the scan
synthesis. The score and every contributing feature are recorded. A model may ask to move a
unit up a tier; nothing ever moves a unit down.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from agent.reasoning.evidence import EvidencePacket, Group

ROUTER_VERSION = "router-1"


class Tier(StrEnum):
    DETERMINISTIC = "deterministic"
    SMALL = "small"
    LARGE = "large"


TIER_RANK = {Tier.DETERMINISTIC: 0, Tier.SMALL: 1, Tier.LARGE: 2}
SEVERITY_WEIGHT = {"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0}
CATEGORY_WEIGHT = {
    "iam_wildcard": 3,
    "secret": 2,
    "missing_auth": 2,
    "unsafe_command_execution": 2,
    "missing_input_validation": 1,
    "missing_environment_variable": 0,
}
SMALL_MAX_SCORE = 5
DETERMINISTIC_MAX_SCORE = 1
INTENT_WEIGHT = {
    "explain_finding": 0,
    "why_risky": 1,
    "how_to_fix": 1,
    "concept": 1,
    "general": 2,
    "scan_overview": 2,
    "prioritize": 2,
    "compare": 4,
    "false_positive_challenge": 6,
}


@dataclass(frozen=True)
class Route:
    tier: Tier
    score: int
    features: tuple[tuple[str, int], ...]
    forced: str | None = None
    escalated_from: Tier | None = None
    escalation_reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "tier": str(self.tier),
            "score": self.score,
            "features": dict(self.features),
            "forced": self.forced,
            "escalated_from": str(self.escalated_from) if self.escalated_from else None,
            "escalation_reason": self.escalation_reason,
        }


def _tier(score: int, deterministic_ok: bool) -> Tier:
    if deterministic_ok and score <= DETERMINISTIC_MAX_SCORE:
        return Tier.DETERMINISTIC
    return Tier.SMALL if score <= SMALL_MAX_SCORE else Tier.LARGE


def route_group(group: Group) -> Route:
    features = {
        f"severity_{group.severity}": SEVERITY_WEIGHT.get(group.severity, 1),
        f"category_{group.category}": CATEGORY_WEIGHT.get(group.category, 2),
        "needs_review_or_denied": int(group.decision != "permit"),
        "compound_risk": int("compound_risk" in group.flags),
        "production": 2 * int("production" in group.flags),
        "batch_summary": int("batch_summary" in group.flags),
        "many_locations": int(group.count > 1) + int(group.count > 10),
        "suppressed_checks": 2 * int("suppressed_checks" in group.flags),
        "mixed_evidence": int("mixed_evidence" in group.flags),
        "truncated": int("truncated" in group.flags),
        "deterministic_fact": -int(group.evidence_class == "deterministic_fact"),
    }
    score = sum(features.values())
    features_out = tuple(sorted((k, v) for k, v in features.items() if v))
    if group.decision == "deny":
        # Denied means the context is invalid, stale or incomplete: explain without spending.
        return Route(Tier.DETERMINISTIC, score, features_out, "policy_denied")
    clean_flags = not {"untrusted_text", "suppressed_checks", "truncated"} & set(group.flags)
    tier = _tier(score, group.playbook.deterministic_ok and clean_flags)
    forced = None
    if "untrusted_text" in group.flags:
        # Instruction-like repository text goes to the model most resistant to it.
        tier, forced = Tier.LARGE, "untrusted_text"
    return Route(tier, score, features_out, forced)


def route_synthesis(packet: EvidencePacket, routes: dict[str, Route]) -> Route | None:
    """None when there is nothing to synthesize (a single group)."""
    if len(packet.groups) < 2:
        return None
    categories = {group.category for group in packet.groups}
    features = {
        "groups": min(len(packet.groups), 6),
        "categories": len(categories),
        "model_routed_groups": sum(r.tier != Tier.DETERMINISTIC for r in routes.values()),
        "compound_risk": 2 * any("compound_risk" in g.flags for g in packet.groups),
        "production": 2 * any("production" in g.flags for g in packet.groups),
        "incomplete_scan": 3 * int(not packet.complete),
    }
    score = sum(features.values())
    features_out = tuple(sorted((k, v) for k, v in features.items() if v))
    if all(group.decision == "deny" for group in packet.groups):
        return Route(Tier.DETERMINISTIC, score, features_out, "policy_denied")
    simple = all(r.tier == Tier.DETERMINISTIC for r in routes.values()) and not (
        features["compound_risk"] or features["production"] or features["incomplete_scan"]
    )
    return Route(Tier.DETERMINISTIC if simple else Tier.LARGE, score, features_out)


def route_question(intents: tuple[str, ...], groups: list[Group], difficulty: str | None) -> Route:
    features = {f"intent_{intent}": INTENT_WEIGHT.get(intent, 2) for intent in intents}
    features["multiple_intents"] = int(len(intents) > 1)
    features["groups_referenced"] = min(len(groups), 3) - 1 if groups else 0
    features["hardest_group"] = max((route_group(g).score for g in groups), default=0) // 2
    features["model_difficulty"] = {"high": 4, "medium": 1}.get(difficulty or "", 0)
    score = sum(features.values())
    return Route(
        Tier.SMALL if score <= SMALL_MAX_SCORE else Tier.LARGE,
        score,
        tuple(sorted((k, v) for k, v in features.items() if v)),
    )


def escalate(route: Route, reason: str) -> Route:
    """Move up exactly one tier (never down); the large tier is the ceiling."""
    target = Tier.LARGE if TIER_RANK[route.tier] >= TIER_RANK[Tier.SMALL] else Tier.SMALL
    if route.tier == Tier.LARGE:
        return replace(route, escalation_reason=route.escalation_reason or reason)
    return replace(route, tier=target, escalated_from=route.tier, escalation_reason=reason)
