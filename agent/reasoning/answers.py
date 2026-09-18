"""Zero-cost answers composed from policy facts, the glossary and validated explanations."""

from __future__ import annotations

from agent.reasoning.evidence import EvidencePacket
from agent.reasoning.knowledge import (
    DECISIONS,
    PLAYBOOKS,
    concept_entry,
    reason_text,
    template_explanation,
    where,
)
from agent.reasoning.query import EnhancedQuery

MAX_ANSWER = 1800


def answer(
    text: str,
    *,
    refs=(),
    key_points=(),
    answerable=True,
    limitation="none",
    follow_up="",
    escalation="none",
) -> dict:
    return {
        "answer": text[:MAX_ANSWER],
        "key_points": [point[:280] for point in key_points][:5],
        "refs": list(dict.fromkeys(refs))[:20],
        "answerable": answerable,
        "limitation": limitation,
        "follow_up": follow_up[:280],
        "escalation": escalation,
    }


def _index(packet: EvidencePacket, ids=None) -> list[str]:
    groups = [g for g in packet.groups if ids is None or g.id in ids]
    return [f"{g.id}: {PLAYBOOKS[g.category].label} at {where(g)}" for g in groups]


def blocked(query: EnhancedQuery, packet: EvidencePacket) -> dict:
    groups = [packet.group(g) for g in query.group_ids if packet.group(g)]
    if query.block_reason == "injection_attempt":
        return answer(
            "I can't change my rules or ignore my instructions. I can explain any finding in "
            "this scan, why it matters, how to fix it, or what to fix first.",
            answerable=False,
            limitation="request_not_allowed",
            follow_up="Which finding would you like explained?",
        )
    if query.block_reason == "authorization_override":
        return answer(
            "Findings can't be marked safe, approved, resolved or downgraded from here. The "
            "Cedar policy decision is final, and findings that need approval are reviewed by a "
            "person. I can explain what a reviewer will look at for any finding.",
            refs=[f"{g.id}.decision" for g in groups],
            answerable=False,
            limitation="policy_decision_is_final",
            follow_up="Would you like the fix steps for a finding instead?",
        )
    if query.block_reason == "secret_disclosure":
        secrets = [g for g in packet.groups if g.category == "secret"]
        where_text = "; ".join(f"{g.id} at {where(g)}" for g in secrets) or "none in this scan"
        return answer(
            "Secret values are never displayed or sent to a model. Findings record only where a "
            f"secret is ({where_text}). Treat any exposed credential as compromised and rotate it "
            "with its provider.",
            refs=[g.id for g in secrets],
            answerable=False,
            limitation="request_not_allowed",
            follow_up="Do you want the steps to rotate and remove it?",
        )
    if query.block_reason == "runtime_error":
        related = [
            g
            for g in packet.groups
            if g.category in {"iam_wildcard", "missing_environment_variable"}
        ]
        hint = (
            " Findings that commonly cause runtime failures in this scan: "
            + "; ".join(_index(packet, {g.id for g in related}))
            + "."
            if related
            else ""
        )
        return answer(
            "Tracing a live error needs runtime evidence such as traces and logs, which this step "
            f"does not collect, so I won't guess at a cause.{hint}",
            refs=[g.id for g in related],
            answerable=False,
            limitation="needs_runtime_evidence",
        )
    if query.block_reason == "help":
        return answer(
            "I explain this scan's findings using only its evidence: what each finding means, why "
            "it matters, how to fix it, what to fix first, why the policy needs review, and "
            "whether anything blocks deployment. I never show secret values or change policy "
            "decisions.",
            key_points=_index(packet),
            refs=[g.id for g in packet.groups],
            follow_up="What should I fix first?",
        )
    return answer(
        "That is outside what First Commit can help with. Ask about this scan: what a finding "
        "means, why it matters, how to fix it, or what to fix first.",
        answerable=False,
        limitation="outside_scan_scope",
    )


def clarification(query: EnhancedQuery, packet: EvidencePacket) -> dict:
    options = _index(packet)
    return answer(
        "Which finding do you mean? This scan has: " + "; ".join(options[:8]) + "."
        if options
        else "This scan has no findings to discuss.",
        key_points=options,
        refs=[g.id for g in packet.groups][:20],
        answerable=False,
        limitation="insufficient_evidence",
        follow_up="Name a group such as G1, or a file and line.",
    )


def no_findings(packet: EvidencePacket) -> dict:
    note = "" if packet.complete else " The scan was incomplete, so issues may be missing."
    return answer(
        f"This scan has no findings with policy decisions to discuss.{note}",
        refs=["SCAN.findings", "SCAN.complete"],
        answerable=False,
        limitation="insufficient_evidence",
    )


def deploy_readiness(packet: EvidencePacket) -> dict:
    blockers = [g for g in packet.groups if g.decision != "permit"]
    refs = ["SCAN.complete", *(f"{g.id}.decision" for g in blockers)]
    if blockers or not packet.complete:
        lines = [
            f"{g.id} ({PLAYBOOKS[g.category].label}) {DECISIONS[g.decision]}" for g in blockers
        ]
        incomplete = (
            " The scan is also incomplete, so other issues may be missing."
            if not packet.complete
            else ""
        )
        return answer(
            f"Not yet. {len(blockers)} finding group(s) need human review or are blocked: "
            + "; ".join(lines)
            + f".{incomplete} Fix and review these first; deployment always goes through "
            "validation and a human checkpoint.",
            key_points=lines,
            refs=refs,
            limitation="policy_decision_is_final",
            follow_up="What should I fix first?",
        )
    return answer(
        "The policy permits automated processing for every finding in this scan. That is not a "
        "deployment approval: a deploy still requires a validated change and a human checkpoint.",
        refs=refs,
        limitation="policy_decision_is_final",
    )


def policy_decisions(query: EnhancedQuery, packet: EvidencePacket) -> dict:
    groups = [packet.group(g) for g in query.group_ids] or list(packet.groups)
    lines = []
    for group in groups:
        reasons = " ".join(reason_text(r) for r in group.reasons if r != "review-supported-finding")
        lines.append(
            f"{group.id} ({PLAYBOOKS[group.category].label}) "
            f"{DECISIONS[group.decision]}. {reasons}".strip()
        )
    return answer(
        "\n".join(lines)
        + "\nPolicy decisions come from versioned Cedar rules and cannot be changed here.",
        refs=[r for g in groups for r in (f"{g.id}.decision", f"{g.id}.policy_reasons")],
        limitation="policy_decision_is_final",
    )


def from_explanations(query: EnhancedQuery, units: list) -> dict:
    intents = set(query.intents)
    parts, points, refs = [], [], []
    for unit in units:
        explanation = unit.result["explanation"]
        group = unit.group
        header = f"{group.id}: {explanation['headline']}"
        section = [header]
        if "explain_finding" in intents or not intents & {"why_risky", "how_to_fix"}:
            section.append(explanation["what_happened"])
        if "why_risky" in intents or "explain_finding" in intents:
            section.append(f"Why it matters: {explanation['why_it_matters']}")
        if "how_to_fix" in intents:
            steps = " ".join(
                f"{n}. {s['action']}" for n, s in enumerate(explanation["fix_steps"], 1)
            )
            section.append(f"How to fix: {steps}")
            points += explanation["verify"]
        if "policy_decision" in intents:
            section.append(
                f"Policy: {DECISIONS[group.decision]}. "
                + " ".join(reason_text(r) for r in group.reasons if r != "review-supported-finding")
            )
        if unit.result["status"] not in {"model_validated", "deterministic"}:
            section.append(
                "(Showing First Commit's vetted explanation because the model's answer needed "
                "review.)"
            )
        parts.append("\n".join(section))
        refs += explanation["refs"]
    text = "\n\n".join(parts)
    truncated = len(text) > MAX_ANSWER
    return answer(
        text
        if not truncated
        else text[: MAX_ANSWER - 60] + "\n… (more groups in the full explanation report)",
        key_points=points,
        refs=refs,
        follow_up="What should I fix first?" if len(units) > 1 else "",
    )


def from_synthesis(query: EnhancedQuery, packet: EvidencePacket, unit, group_units: list) -> dict:
    if unit is None:
        return from_explanations(query, group_units)
    synthesis = unit.result["synthesis"]
    priorities = [f"{p['group_id']}: {p['why_now']}" for p in synthesis["priorities"]]
    if "prioritize" in query.intents:
        text = "Fix in this order:\n" + "\n".join(
            f"{n}. {line}" for n, line in enumerate(priorities, 1)
        )
    else:
        text = f"{synthesis['headline']}\n{synthesis['overview']}"
    text += f"\nNext step: {synthesis['next_step']}"
    refs = [r for p in synthesis["priorities"] for r in p["refs"]]
    return answer(text, key_points=priorities, refs=refs or list(packet.priority_order))


def template_answer(query: EnhancedQuery, packet: EvidencePacket) -> dict | None:
    """Grounded answer from vetted knowledge for reasoning intents, or None if none applies."""
    intents = set(query.intents)
    groups = [packet.group(g) for g in query.group_ids if packet.group(g)]
    if intents == {"concept"} and (entry := concept_entry(query.concept)):
        return concept(entry, packet)
    if "false_positive_challenge" in intents and groups:
        return challenge(groups)
    if "compare" in intents and len(groups) >= 2:
        return compare(groups)
    return None


def concept(entry, packet: EvidencePacket) -> dict:
    _, definition, categories = entry
    related = [g for g in packet.groups if g.category in categories]
    text = definition
    if related:
        mentions = "; ".join(_index(packet, {g.id for g in related}))
        text += f" In this scan it relates to {mentions}."
    return answer(
        text, refs=[g.id for g in related], follow_up="How do I fix it?" if related else ""
    )


def challenge(groups) -> dict:
    lines, points, refs = [], [], []
    for group in groups:
        explanation = template_explanation(group)
        lines.append(
            f"{group.id} ({PLAYBOOKS[group.category].label} at {where(group)}) "
            f"{DECISIONS[group.decision]}, and that decision stands. {explanation['what_happened']}"
        )
        if explanation["uncertainty"]:
            lines.append("What this evidence cannot show: " + " ".join(explanation["uncertainty"]))
        else:
            lines.append("This evidence is a deterministic fact rather than a pattern match.")
        lines.append("To check whether it applies to you: " + " ".join(explanation["verify"]))
        points += explanation["verify"]
        refs += [group.id, f"{group.id}.decision", *(loc.ref for loc in group.locations[:3])]
    lines.append(
        "If it does not apply, write down the reason for the reviewer instead of suppressing the "
        "finding."
    )
    return answer(
        "\n".join(lines),
        key_points=points,
        refs=refs,
        limitation="policy_decision_is_final",
        follow_up="How do I fix it?",
    )


def compare(groups) -> dict:
    ordered = sorted(groups, key=lambda g: g.rank_key())
    lines = [
        f"{g.id}: {PLAYBOOKS[g.category].label} at {where(g)}, {g.severity} severity, "
        f"{DECISIONS[g.decision]}. {PLAYBOOKS[g.category].why}"
        for g in ordered
    ]
    lines.append(
        "Fix order: "
        + ", then ".join(g.id for g in ordered)
        + " (ranked by policy outcome, severity and category)."
    )
    return answer(
        "\n".join(lines),
        refs=[r for g in ordered for r in (g.id, f"{g.id}.severity", f"{g.id}.decision")],
        follow_up=f"How do I fix {ordered[0].id}?",
    )


def fallback(query: EnhancedQuery, packet: EvidencePacket, reason: str) -> dict:
    ids = set(query.group_ids) or None
    lines = _index(packet, ids)
    return answer(
        "I couldn't produce a validated answer to that question, so I won't guess. Here is what "
        "the evidence shows: " + "; ".join(lines[:8]) + ".",
        key_points=lines,
        refs=[g for g in (query.group_ids or packet.priority_order)][:20],
        answerable=False,
        limitation="insufficient_evidence",
        follow_up="Try asking how to fix or why a specific group matters.",
        escalation="needs_stronger_model" if reason.startswith("validation") else "none",
    )
