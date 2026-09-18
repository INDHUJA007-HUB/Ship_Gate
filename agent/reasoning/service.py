"""Phase 5 orchestration: plan, route, cache, call, validate, retry once, escalate, degrade.

Per scan, at most one small-tier call per batch, one large-tier call per batch (which also writes
the synthesis), and one corrective large-tier retry for units that still fail validation. A unit
that fails its one retry is shown with the vetted template and marked for human review; provider
or budget failures degrade the same way but are never cached. Cedar decisions pass through
unchanged, and the report asserts it.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field, replace

from agent.models import ScanReport
from agent.reasoning import answers
from agent.reasoning.budget import Budget, BudgetExhausted, Ledger
from agent.reasoning.cache import ExplanationCache, cache_key
from agent.reasoning.evidence import (
    PACKET_VERSION,
    EvidencePacket,
    InputRejected,
    build_packet,
    stable,
)
from agent.reasoning.knowledge import (
    AUDIENCES,
    DECISIONS,
    KNOWLEDGE_VERSION,
    PLAYBOOKS,
    template_explanation,
    where,
)
from agent.reasoning.prompts import (
    PROMPT_VERSION,
    RenderedPrompt,
    answer_prompt,
    classify_prompt,
    explain_prompt,
)
from agent.reasoning.providers import ModelProvider, ModelRequest, ProviderError
from agent.reasoning.query import QUERY_VERSION, EnhancedQuery, enhance, plan
from agent.reasoning.routing import (
    ROUTER_VERSION,
    Route,
    Tier,
    escalate,
    route_group,
    route_question,
    route_synthesis,
)
from agent.reasoning.schemas import CONTRACT_VERSION, MAX_BATCH
from agent.reasoning.validation import (
    SYNTHESIS_ID,
    Violation,
    check_answer,
    check_classification,
    check_explanation_batch,
)

REPORT_VERSION = "reasoning-report-1"
ANSWER_VERSION = "reasoning-answer-1"
VERSIONS = {
    "prompt": PROMPT_VERSION,
    "contract": CONTRACT_VERSION,
    "knowledge": KNOWLEDGE_VERSION,
    "router": ROUTER_VERSION,
    "packet": PACKET_VERSION,
    "query": QUERY_VERSION,
}
# Escalations that move work to the large tier, and those that force human review.
ESCALATE_TIER = {
    "needs_stronger_model",
    "conflicting_evidence",
    "insufficient_evidence",
    "possible_prompt_injection",
}
REVIEW_ESCALATIONS = {
    "possible_prompt_injection",
    "risk_higher_than_policy",
    "conflicting_evidence",
}
USABLE = {"model_validated", "deterministic"}


@dataclass(frozen=True)
class ReasoningContext:
    tenant: str
    user: str
    audience: str = "beginner"
    refresh: bool = False

    def __post_init__(self):
        if not self.tenant or not self.user or self.audience not in AUDIENCES:
            raise ValueError("invalid_reasoning_context")


@dataclass(frozen=True)
class ReasoningConfig:
    budget: Budget = field(default_factory=Budget)
    batch_size: int = MAX_BATCH  # Weighted: the synthesis counts as two explanations.
    lease_seconds: int = 180
    wait_seconds: float = 180.0
    poll_seconds: float = 0.2
    large_effort: str = "medium"
    retry_effort: str = "high"
    small_tokens_per_item: int = 700
    large_tokens_per_item: int = 900
    synthesis_tokens: int = 1400
    thinking_allowance: int = 4000
    max_tokens_cap: int = 16000


@dataclass
class Unit:
    id: str
    kind: str  # group | synthesis | answer
    route: Route
    key: str
    group: object = None
    result: dict | None = None
    attempts: list = field(default_factory=list)
    corrections: dict | None = None
    retried: bool = False
    fallback_item: dict | None = None
    fallback_model: str | None = None


@dataclass(frozen=True)
class Outcome:
    kind: str  # accepted | invalid | refusal | degraded
    item: dict | None = None
    violations: tuple[Violation, ...] = ()
    reason: str | None = None
    model: str | None = None


def _digest(value) -> str:
    return hashlib.sha256(stable(value).encode()).hexdigest()[:16]


class ReasoningService:
    def __init__(
        self,
        provider: ModelProvider | None,
        cache: ExplanationCache,
        config: ReasoningConfig | None = None,
        *,
        clock=time.monotonic,
        sleep=time.sleep,
    ):
        self.provider = provider
        self.cache = cache
        self.config = config or ReasoningConfig()
        self.clock = clock
        self.sleep = sleep

    # ----------------------------------------------------------------- public API
    def explain(self, report: ScanReport, policy: dict, context: ReasoningContext) -> dict:
        ledger = Ledger(self.config.budget)
        try:
            packet = build_packet(report, policy)
        except InputRejected as error:
            return self._rejected(REPORT_VERSION, str(error), ledger)
        if packet.state != "evaluated":
            return self._state_report(packet, ledger)
        units, synthesis = self._plan(packet, context)
        self._resolve([*units, *([synthesis] if synthesis else [])], packet, context, ledger)
        return self._report(packet, context, units, synthesis, ledger)

    def ask(
        self, question: str, report: ScanReport, policy: dict, context: ReasoningContext
    ) -> dict:
        ledger = Ledger(self.config.budget)
        try:
            packet = build_packet(report, policy)
        except InputRejected as error:
            return self._rejected(ANSWER_VERSION, str(error), ledger)
        if packet.state != "evaluated":
            state = self._state_report(packet, ledger)
            return self._answer_report(
                None,
                answers.answer(
                    state["explanation"], answerable=False, limitation="insufficient_evidence"
                ),
                "no_decisions",
                "deterministic",
                ledger,
                packet,
            )
        query = enhance(question, packet)
        if query.handling == "classify":
            query = self._classify(query, packet, context, ledger)
        status, source, related = "answered", "deterministic", []
        if query.handling == "blocked":
            result, status = answers.blocked(query, packet), "blocked"
        elif query.handling == "clarify":
            result, status = answers.clarification(query, packet), "clarification_needed"
        elif not packet.groups:
            result = answers.no_findings(packet)
        elif query.handling == "deterministic":
            if "deploy_readiness" in query.intents:
                result = answers.deploy_readiness(packet)
            else:
                result = answers.policy_decisions(query, packet)
        elif query.handling == "explanations":
            units, _ = self._plan(packet, context, only=set(query.group_ids), synthesis=False)
            self._resolve(units, packet, context, ledger)
            result, source, related = answers.from_explanations(query, units), "explanations", units
            if any(u.result["status"] not in USABLE for u in units):
                status = "needs_human_review"
        elif query.handling == "synthesis":
            units, synthesis = self._plan(packet, context)
            targets = [synthesis] if synthesis else units
            self._resolve(targets, packet, context, ledger)
            result = answers.from_synthesis(query, packet, synthesis, units)
            source, related = "synthesis", targets
            if any(u.result["status"] not in USABLE for u in targets):
                status = "needs_human_review"
        elif (template := answers.template_answer(query, packet)) is not None and (
            self.provider is None or query.intents == ("concept",)
        ):
            # Known concepts never need a model; without a provider, vetted knowledge answers.
            ledger.note("deterministic_units")
            result = template
            source = "knowledge" if query.intents == ("concept",) else "template"
        else:
            result, status, source, related = self._answer_with_model(
                query, packet, context, ledger
            )
        return self._answer_report(query, result, status, source, ledger, packet, related)

    @staticmethod
    def _fallback_answer(query, packet, reason):
        return answers.template_answer(query, packet) or answers.fallback(query, packet, reason)

    # ----------------------------------------------------------------- planning
    def _key(self, context: ReasoningContext, material: dict) -> str:
        return cache_key(
            {
                "tenant": context.tenant,
                "audience": context.audience,
                "versions": VERSIONS,
                "provider": self.provider.name if self.provider else "none",
                "models": self._models(),
                **material,
            }
        )

    def _models(self) -> dict:
        return {str(t): m for t, m in sorted(self.provider.models.items())} if self.provider else {}

    def _plan(self, packet, context, only=None, synthesis=True):
        units, routes = [], {}
        for group in packet.groups:
            route = route_group(group)
            routes[group.id] = route
            if only is not None and group.id not in only:
                continue
            material = {
                "kind": "group",
                "facts": group.facts(),
                "policy": packet.policy_version,
                "complete": packet.complete,
            }
            units.append(Unit(group.id, "group", route, self._key(context, material), group))
        synthesis_unit = None
        route = route_synthesis(packet, routes) if synthesis else None
        if route:
            material = {"kind": "synthesis", "packet": packet.digest()}
            synthesis_unit = Unit(SYNTHESIS_ID, "synthesis", route, self._key(context, material))
        return units, synthesis_unit

    # ----------------------------------------------------------------- resolution
    def _resolve(self, units, packet, context, ledger):
        owner = uuid.uuid4().hex
        needed = []
        for unit in units:
            if unit.route.tier == Tier.DETERMINISTIC:
                self._deterministic(unit, packet, "deterministic", ledger)
            elif self.provider is None:
                self._deterministic(
                    unit, packet, "deterministic", ledger, note="model_provider_disabled"
                )
            elif not context.refresh and (cached := self.cache.get(context.tenant, unit.key)):
                self._from_cache(unit, cached, packet, ledger)
            else:
                needed.append(unit)
        # All-or-none leases: concurrent identical runs never split a batch across workers.
        mine, foreign = [], []
        for unit in needed:
            if self.cache.acquire(context.tenant, unit.key, owner, self.config.lease_seconds):
                mine.append(unit)
                continue
            for held in mine:
                self.cache.release(context.tenant, held.key, owner)
            mine, foreign = [], needed
            break
        try:
            if mine:
                self._explain_passes(mine, packet, context, ledger)
        finally:
            for unit in mine:
                self.cache.release(context.tenant, unit.key, owner)
        for unit in foreign:
            self._await(unit, packet, context, ledger, owner)

    def _await(self, unit, packet, context, ledger, owner):
        """Another worker is producing this unit; wait for it instead of paying twice."""
        deadline = self.clock() + self.config.wait_seconds
        while True:
            if cached := self.cache.get(context.tenant, unit.key):
                ledger.note("deduplicated_concurrent")
                return self._from_cache(unit, cached, packet, ledger)
            if self.cache.acquire(context.tenant, unit.key, owner, self.config.lease_seconds):
                try:
                    if cached := self.cache.get(context.tenant, unit.key):
                        return self._from_cache(unit, cached, packet, ledger)
                    return self._explain_passes([unit], packet, context, ledger)
                finally:
                    self.cache.release(context.tenant, unit.key, owner)
            if self.clock() >= deadline:
                return self._degrade(unit, packet, ledger, "concurrent_request_timeout")
            self.sleep(self.config.poll_seconds)

    def _chunks(self, units):
        batch, weight = [], 0
        capacity = max(2, min(self.config.batch_size, MAX_BATCH))
        for unit in sorted(units, key=lambda u: (u.kind != "synthesis", u.id)):
            cost = 2 if unit.kind == "synthesis" else 1
            if batch and weight + cost > capacity:
                yield batch
                batch, weight = [], 0
            batch.append(unit)
            weight += cost
        if batch:
            yield batch

    def _explain_passes(self, units, packet, context, ledger):
        small = [u for u in units if u.route.tier == Tier.SMALL]
        large = [u for u in units if u.route.tier == Tier.LARGE]
        for batch in self._chunks(small):
            outcomes = self._call_explain(batch, Tier.SMALL, packet, context, ledger)
            for unit in batch:
                outcome = outcomes[unit.id]
                if outcome.kind == "accepted" and outcome.item["escalation"] in ESCALATE_TIER:
                    unit.fallback_item, unit.fallback_model = outcome.item, outcome.model
                    unit.route = escalate(unit.route, f"model:{outcome.item['escalation']}")
                    ledger.note("escalations")
                    large.append(unit)
                elif outcome.kind == "accepted":
                    self._accept(
                        unit, outcome.item, Tier.SMALL, outcome.model, packet, context, ledger
                    )
                elif outcome.kind in {"invalid", "refusal"}:
                    # The one retry happens on the large tier, with the validation errors.
                    if outcome.kind == "invalid":
                        unit.corrections, unit.retried = {unit.id: list(outcome.violations)}, True
                    unit.route = escalate(
                        unit.route, "validation_failed" if outcome.kind == "invalid" else "refusal"
                    )
                    ledger.note("escalations")
                    large.append(unit)
                else:
                    self._degrade(unit, packet, ledger, outcome.reason)
        retry = []
        for batch in self._chunks(large):
            outcomes = self._call_explain(batch, Tier.LARGE, packet, context, ledger)
            for unit in batch:
                outcome = outcomes[unit.id]
                if outcome.kind == "accepted":
                    self._accept(
                        unit, outcome.item, Tier.LARGE, outcome.model, packet, context, ledger
                    )
                elif outcome.kind == "invalid" and not unit.retried:
                    unit.corrections, unit.retried = {unit.id: list(outcome.violations)}, True
                    retry.append(unit)
                else:
                    self._unresolved(unit, outcome, packet, context, ledger)
        for batch in self._chunks(retry):
            ledger.note("corrective_retries", len(batch))
            outcomes = self._call_explain(
                batch, Tier.LARGE, packet, context, ledger, corrective=True
            )
            for unit in batch:
                outcome = outcomes[unit.id]
                if outcome.kind == "accepted":
                    self._accept(
                        unit, outcome.item, Tier.LARGE, outcome.model, packet, context, ledger
                    )
                else:
                    self._unresolved(unit, outcome, packet, context, ledger)

    def _unresolved(self, unit, outcome, packet, context, ledger):
        if unit.fallback_item is not None and outcome.kind != "refusal":
            # A valid small-tier answer that asked for help is better than a template, but
            # a person must look at it.
            reason = (
                "escalation_unavailable"
                if outcome.kind == "degraded"
                else "escalation_failed_validation"
            )
            return self._accept(
                unit,
                unit.fallback_item,
                Tier.SMALL,
                unit.fallback_model,
                packet,
                context,
                ledger,
                reasons=[reason],
                cache=outcome.kind != "degraded",
            )
        if outcome.kind == "degraded":
            return self._degrade(unit, packet, ledger, outcome.reason)
        reasons = [v.code for v in outcome.violations] or [
            outcome.reason or "model_output_rejected"
        ]
        return self._human_review(unit, packet, context, ledger, reasons)

    # ----------------------------------------------------------------- model calls
    def _max_tokens(self, tier, items, synthesis, corrective):
        if tier == Tier.SMALL:
            tokens = 400 + self.config.small_tokens_per_item * items
        else:
            tokens = (
                400 + self.config.large_tokens_per_item * items + self.config.thinking_allowance
            )
            tokens += self.config.synthesis_tokens if synthesis else 0
        if corrective:
            tokens = int(tokens * 1.5)
        return min(tokens, self.config.max_tokens_cap)

    def _invoke(self, tier, prompt: RenderedPrompt, max_tokens, effort, purpose, ledger):
        model = self.provider.models[tier]
        try:
            reserved = ledger.reserve(
                model, prompt.estimated_input_tokens, max_tokens, self.provider.name
            )
        except BudgetExhausted as error:
            return None, str(error)
        ledger.prompts.append(
            {
                "purpose": purpose,
                "tier": str(tier),
                "modules": list(prompt.modules),
                "estimated_input_tokens": prompt.estimated_input_tokens,
                "evidence_chars": prompt.facts_chars,
                "max_tokens": max_tokens,
            }
        )
        request = ModelRequest(
            tier, model, prompt.system, prompt.user, prompt.tool, max_tokens, effort, purpose
        )
        try:
            response = self.provider.complete(request)
        except ProviderError as error:
            ledger.record_failure(error.kind, reserved)
            return None, f"provider_{error.kind}"
        except Exception:
            ledger.record_failure("unexpected", reserved)
            return None, "provider_unexpected"
        ledger.record(str(tier), response, reserved, self.provider.name)
        return response, None

    def _attempt(self, tier, response, prompt, corrective):
        return {
            "tier": str(tier),
            "model": response.model,
            "stop_reason": response.stop_reason,
            "corrective": corrective,
            "fallback_used": response.fallback_used,
            "prompt_sha256": prompt.fingerprint[:16],
            "output_sha256": _digest(response.tool_input)
            if response.tool_input is not None
            else None,
            "request_id": response.request_id,
        }

    def _call_explain(self, batch, tier, packet, context, ledger, corrective=False):
        groups = [u.group for u in batch if u.kind == "group"]
        synthesis = any(u.kind == "synthesis" for u in batch)
        corrections = {k: v for u in batch if u.corrections for k, v in u.corrections.items()}
        escalated = any(u.route.escalated_from is not None for u in batch)
        prompt = explain_prompt(
            groups,
            packet,
            context.audience,
            synthesis=synthesis,
            corrections=corrections or None,
            escalated=escalated,
        )
        effort = (
            None
            if tier == Tier.SMALL
            else (self.config.retry_effort if corrective or escalated else self.config.large_effort)
        )
        max_tokens = self._max_tokens(tier, len(groups), synthesis, corrective)
        response, failure = self._invoke(tier, prompt, max_tokens, effort, "explain", ledger)
        if failure:
            return {u.id: Outcome("degraded", reason=failure) for u in batch}
        attempt = self._attempt(tier, response, prompt, corrective)
        batch_level = None
        if response.stop_reason == "refusal":
            ledger.note("refusals")
            outcomes = {
                u.id: Outcome(
                    "refusal", reason=f"refusal:{response.refusal_category or 'unspecified'}"
                )
                for u in batch
            }
        elif response.stop_reason == "max_tokens":
            batch_level = Violation(
                "TRUNCATED_OUTPUT", "batch", "output hit max_tokens; be more concise"
            )
        elif response.tool_input is None:
            batch_level = Violation(
                "MISSING_TOOL_CALL", "batch", f"respond by calling {prompt.tool['name']}"
            )
        if batch_level:
            outcomes = {u.id: Outcome("invalid", violations=(batch_level,)) for u in batch}
        elif response.stop_reason != "refusal":
            check = check_explanation_batch(
                response.tool_input, packet, [g.id for g in groups], synthesis
            )
            outcomes = {}
            for unit in batch:
                if unit.id in check.accepted:
                    outcomes[unit.id] = Outcome(
                        "accepted", item=check.accepted[unit.id], model=response.model
                    )
                else:
                    found = check.violations.get(unit.id) or [
                        Violation("SCHEMA", unit.id, "rejected")
                    ]
                    outcomes[unit.id] = Outcome("invalid", violations=tuple(found))
        for unit in batch:
            outcome = outcomes[unit.id]
            if outcome.kind == "invalid":
                ledger.note("validation_failures")
            unit.attempts.append(
                {
                    **attempt,
                    "outcome": outcome.kind,
                    "violations": sorted({v.code for v in outcome.violations}),
                }
            )
        return outcomes

    # ----------------------------------------------------------------- unit results
    def _unit_result(
        self, unit, packet, *, status, source, content, model=None, reasons=(), note=None
    ):
        result = {
            "unit_id": unit.id,
            "kind": unit.kind,
            "status": status,
            "source": source,
            "model": model,
            "routing": unit.route.to_dict(),
            "attempts": list(unit.attempts),
            "review_reasons": sorted(set(reasons)),
            "note": note,
            "cached": False,
        }
        if unit.kind == "group":
            group = unit.group
            result.update(
                {
                    "finding_ids": list(group.finding_ids),
                    "category": group.category,
                    "label": PLAYBOOKS[group.category].label,
                    "rule": group.rule,
                    "severity": group.severity,
                    "decision": group.decision,
                    "policy_reasons": list(group.reasons),
                    "evidence_class": group.evidence_class,
                    "locations": [{"path": loc.path, "line": loc.line} for loc in group.locations],
                    "locations_omitted": group.locations_omitted,
                    "requires_human_review": group.decision != "permit" or bool(reasons),
                    "explanation": content,
                }
            )
        else:
            result.update(
                {
                    "priority_order": list(packet.priority_order),
                    "requires_human_review": bool(reasons),
                    "synthesis": content,
                }
            )
        return result

    def _content(self, unit, packet):
        return (
            template_explanation(unit.group) if unit.kind == "group" else template_synthesis(packet)
        )

    def _deterministic(self, unit, packet, status, ledger, note=None):
        ledger.note("deterministic_units" if note is None else "model_disabled_units")
        unit.result = self._unit_result(
            unit,
            packet,
            status=status,
            source="template",
            content=self._content(unit, packet),
            note=note,
        )

    def _from_cache(self, unit, cached, packet, ledger):
        ledger.note("cache_hits")
        content = cached.get("explanation") if unit.kind == "group" else cached.get("synthesis")
        unit.attempts = cached.get("attempts", [])
        # Authoritative fields are rebuilt from current facts; only the reviewed content is reused.
        unit.result = {
            **self._unit_result(
                unit,
                packet,
                status=cached["status"],
                source=cached["source"],
                content=content,
                model=cached.get("model"),
                reasons=cached.get("review_reasons", ()),
                note=cached.get("note"),
            ),
            "cached": True,
        }

    def _accept(self, unit, item, tier, model, packet, context, ledger, reasons=(), cache=True):
        content = {k: v for k, v in item.items() if k != "group_id"}
        reasons = list(reasons)
        if content["escalation"] in REVIEW_ESCALATIONS:
            reasons.append(f"model_escalation:{content['escalation']}")
        unit.result = self._unit_result(
            unit,
            packet,
            status="model_validated",
            source=f"model:{tier}",
            content=content,
            model=model,
            reasons=reasons,
        )
        ledger.note("model_validated_units")
        if cache:
            self.cache.put(context.tenant, unit.key, unit.result)

    def _human_review(self, unit, packet, context, ledger, reasons):
        ledger.note("human_review_units")
        unit.result = self._unit_result(
            unit,
            packet,
            status="needs_human_review",
            source="template",
            content=self._content(unit, packet),
            reasons=reasons,
            note="model output failed validation after one retry; showing the vetted template",
        )
        # The failure is tied to this evidence, so rerunning unchanged content must not re-spend.
        self.cache.put(context.tenant, unit.key, unit.result)

    def _degrade(self, unit, packet, ledger, reason):
        ledger.note("degraded_units")
        unit.result = self._unit_result(
            unit,
            packet,
            status="degraded",
            source="template",
            content=self._content(unit, packet),
            reasons=[reason or "provider_unavailable"],
            note="model unavailable or budget reached; showing the vetted template (not cached)",
        )

    # ----------------------------------------------------------------- questions
    def _classify(self, query, packet, context, ledger):
        if self.provider is None:
            return replace(query, handling="clarify")
        key = self._key(
            context,
            {
                "kind": "classify",
                "text": query.text.lower(),
                "index": [(g.id, g.category, g.decision) for g in packet.groups],
            },
        )
        payload = None if context.refresh else self.cache.get(context.tenant, key)
        if payload:
            ledger.note("cache_hits")
        else:
            prompt = classify_prompt(query.text, packet)
            response, failure = self._invoke(Tier.SMALL, prompt, 400, None, "classify", ledger)
            if failure or response.stop_reason != "tool_use" or response.tool_input is None:
                return replace(
                    query, handling="clarify", flags=(*query.flags, "classification_unavailable")
                )
            if check_classification(response.tool_input, packet):
                ledger.note("validation_failures")
                return replace(
                    query, handling="clarify", flags=(*query.flags, "classification_invalid")
                )
            payload = response.tool_input
            self.cache.put(context.tenant, key, payload)
        if payload["needs_clarification"]:
            return replace(query, handling="clarify", flags=(*query.flags, "model_classified"))
        classified = replace(
            query,
            intents=(payload["intent"],),
            group_ids=tuple(g for g in packet.priority_order if g in set(payload["group_ids"])),
            difficulty=payload["difficulty"],
            confidence=0.7,
            flags=(*query.flags, "model_classified"),
        )
        return plan(classified, packet)

    def _answer_with_model(self, query: EnhancedQuery, packet, context, ledger):
        groups = [packet.group(g) for g in query.group_ids]
        route = route_question(query.intents, groups, query.difficulty)
        material = {
            "kind": "answer",
            "query": query.canonical(),
            "groups": [g.facts() for g in groups],
            "scan": packet.scan_facts(),
            "policy": packet.policy_version,
            "order": list(packet.priority_order),
        }
        unit = Unit("ANSWER", "answer", route, self._key(context, material))
        if self.provider is None:
            ledger.note("model_disabled_units")
            return (
                self._fallback_answer(query, packet, "model_provider_disabled"),
                "degraded",
                "template",
                [],
            )
        if not context.refresh and (cached := self.cache.get(context.tenant, unit.key)):
            ledger.note("cache_hits")
            return cached["answer"], cached["status"], cached["source"], []
        owner = uuid.uuid4().hex
        if not self.cache.acquire(context.tenant, unit.key, owner, self.config.lease_seconds):
            deadline = self.clock() + self.config.wait_seconds
            while self.clock() < deadline:
                self.sleep(self.config.poll_seconds)
                if cached := self.cache.get(context.tenant, unit.key):
                    ledger.note("deduplicated_concurrent")
                    return cached["answer"], cached["status"], cached["source"], []
            return (
                self._fallback_answer(query, packet, "concurrent_request_timeout"),
                "degraded",
                "template",
                [],
            )
        try:
            return self._answer_attempts(unit, query, groups, packet, context, ledger)
        finally:
            self.cache.release(context.tenant, unit.key, owner)

    def _answer_attempts(self, unit, query, groups, packet, context, ledger):
        """At most: small attempt, one escalation or corrective retry on large, one more retry."""
        tier = unit.route.tier
        corrections = fallback_item = None
        escalated = retried = False
        while True:
            prompt = answer_prompt(
                intents=query.intents,
                question=query.rewritten(),
                user_context=query.user_context,
                groups=groups,
                packet=packet,
                audience=context.audience,
                corrections=corrections,
                escalated=escalated,
            )
            corrective = corrections is not None
            effort = (
                None
                if tier == Tier.SMALL
                else (
                    self.config.retry_effort
                    if corrective or escalated
                    else self.config.large_effort
                )
            )
            base = 900 if tier == Tier.SMALL else 1500 + self.config.thinking_allowance
            max_tokens = min(self.config.max_tokens_cap, base * 3 // 2 if corrective else base)
            response, failure = self._invoke(tier, prompt, max_tokens, effort, "answer", ledger)
            if failure:
                ledger.note("degraded_units")
                if fallback_item:
                    return fallback_item, "needs_human_review", "model:small", []
                return self._fallback_answer(query, packet, failure), "degraded", "template", []
            if response.stop_reason == "refusal":
                ledger.note("refusals")
                violations = [
                    Violation("REFUSAL", "ANSWER", response.refusal_category or "unspecified")
                ]
            elif response.tool_input is None or response.stop_reason == "max_tokens":
                code = "MISSING_TOOL_CALL" if response.tool_input is None else "TRUNCATED_OUTPUT"
                violations = [
                    Violation(code, "ANSWER", "call submit_answer once with a complete answer")
                ]
            else:
                violations = check_answer(response.tool_input, packet, tuple(groups))
            unit.attempts.append(
                {
                    **self._attempt(tier, response, prompt, corrective),
                    "violations": sorted({v.code for v in violations}),
                }
            )
            if not violations:
                item = response.tool_input
                if tier == Tier.SMALL and item["escalation"] in ESCALATE_TIER and not escalated:
                    fallback_item, tier, escalated, corrections = item, Tier.LARGE, True, None
                    unit.route = escalate(unit.route, f"model:{item['escalation']}")
                    ledger.note("escalations")
                    continue
                return (
                    self._store_answer(unit, item, f"model:{tier}", context),
                    "answered",
                    f"model:{tier}",
                    [],
                )
            ledger.note("validation_failures")
            refusal = violations[0].code == "REFUSAL"
            if tier == Tier.SMALL and not escalated:
                # The one retry runs on the large tier, carrying the validation errors.
                tier, escalated, retried = Tier.LARGE, True, not refusal
                corrections = None if refusal else {"ANSWER": violations}
                unit.route = escalate(unit.route, "refusal" if refusal else "validation_failed")
                ledger.note("escalations")
                continue
            if not retried and not refusal:
                retried, corrections = True, {"ANSWER": violations}
                ledger.note("corrective_retries")
                continue
            break
        if fallback_item:
            return fallback_item, "needs_human_review", "model:small", []
        ledger.note("human_review_units")
        result = self._fallback_answer(query, packet, "validation_failed")
        self.cache.put(
            context.tenant,
            unit.key,
            {
                "answer": result,
                "status": "needs_human_review",
                "source": "template",
                "attempts": unit.attempts,
            },
        )
        return result, "needs_human_review", "template", []

    def _store_answer(self, unit, item, source, context):
        self.cache.put(
            context.tenant,
            unit.key,
            {"answer": item, "status": "answered", "source": source, "attempts": unit.attempts},
        )
        return item

    # ----------------------------------------------------------------- reports
    def _rejected(self, version, reason, ledger):
        return {
            "schema_version": version,
            "status": "rejected",
            "reason": reason,
            "usage": ledger.to_dict(),
        }

    def _state_report(self, packet: EvidencePacket, ledger):
        reason = packet.state_reason or "unknown"
        messages = {
            "capped": (
                "Too many findings to explain one by one",
                f"The scan reported {packet.total_findings} findings, more than the policy engine "
                "processes at once, so no finding was explained individually. Narrow the scan or "
                "review the findings in bulk.",
            ),
            "denied": (
                "The policy denied processing",
                f"The policy engine denied processing ({reason}). That concerns the scan context "
                "(tenant, environment tag, freshness or completeness), not a specific code change. "
                "Correct the context and evaluate the policy again.",
            ),
            "error": (
                "Policy decisions are unavailable",
                f"The policy engine reported an error ({reason}), so explanations are withheld: "
                "nothing is explained without a decision.",
            ),
        }
        headline, text = messages.get(packet.state, messages["error"])
        return {
            "schema_version": REPORT_VERSION,
            "status": "no_decisions",
            "policy_state": packet.state,
            "reason": reason,
            "headline": headline,
            "explanation": text,
            "source_hash": packet.source_hash,
            "policy_version": packet.policy_version,
            "units": [],
            "synthesis": None,
            "findings": {},
            "usage": ledger.to_dict(),
        }

    def _report(self, packet, context, units, synthesis, ledger):
        every = [*units, *([synthesis] if synthesis else [])]
        for unit in units:
            if unit.result["decision"] != unit.group.decision or unit.result["finding_ids"] != list(
                unit.group.finding_ids
            ):
                raise AssertionError("reasoning must never alter policy decisions")
        statuses = Counter(u.result["status"] for u in every)
        return {
            "schema_version": REPORT_VERSION,
            "status": "complete" if set(statuses) <= USABLE else "partial",
            "source_hash": packet.source_hash,
            "policy_version": packet.policy_version,
            "decisions_unchanged": True,
            "audience": context.audience,
            "provider": self.provider.name if self.provider else "none",
            "models": self._models(),
            "versions": VERSIONS,
            "scan": packet.scan_facts(),
            "findings": {fid: u.id for u in units for fid in u.group.finding_ids},
            "units": [u.result for u in units],
            "synthesis": synthesis.result if synthesis else None,
            "summary": {
                "units": len(every),
                "by_status": dict(sorted(statuses.items())),
                "requires_human_review": [
                    u.id for u in every if u.result.get("requires_human_review")
                ],
            },
            "usage": ledger.to_dict(),
        }

    def _answer_report(self, query, result, status, source, ledger, packet, related=()):
        return {
            "schema_version": ANSWER_VERSION,
            "status": status,
            "source": source,
            "question": query.public() if query else None,
            "answer": result,
            "related_units": [
                {"unit_id": u.id, "status": u.result["status"], "cached": u.result["cached"]}
                for u in related
                if u.result
            ],
            "source_hash": packet.source_hash if packet else None,
            "policy_version": packet.policy_version if packet else None,
            "decisions_unchanged": True,
            "versions": VERSIONS,
            "usage": ledger.to_dict(),
        }


def template_synthesis(packet: EvidencePacket) -> dict:
    """Deterministic synthesis: ranked priorities and shared-file interactions from facts."""
    groups = list(packet.groups)
    blockers = [g for g in groups if g.decision != "permit"]
    priorities = [
        {
            "group_id": g.id,
            "why_now": (
                f"{PLAYBOOKS[g.category].label}, {g.severity} severity, {DECISIONS[g.decision]}."
            ),
            "refs": [g.id, f"{g.id}.severity", f"{g.id}.decision"],
        }
        for g in groups[:12]
    ]
    by_path: dict[str, list[str]] = {}
    for group in groups:
        for path in {loc.path for loc in group.locations}:
            by_path.setdefault(path, []).append(group.id)
    combined = [
        {
            "group_ids": ids[:6],
            "risk": (
                f"{len(ids)} different issues affect {path}; fix them together so one "
                "change does not undo another."
            ),
            "refs": ids[:6],
        }
        for path, ids in sorted(by_path.items())
        if len(ids) > 1
    ][:5]
    first = groups[0]
    incomplete = (
        "" if packet.complete else " The scan is incomplete, so other issues may be missing."
    )
    return {
        "headline": (
            f"{packet.total_findings} finding(s) in {len(groups)} group(s); "
            f"{len(blockers)} need review or are blocked"
        ),
        "overview": (
            f"The most urgent issue is {PLAYBOOKS[first.category].label.lower()} "
            f"at {where(first)}. "
            f"Work through the groups in the priority order below.{incomplete}"
        ),
        "priorities": priorities,
        "combined_risks": combined,
        "next_step": (
            f"Start with {first.id}: {template_explanation(first)['fix_steps'][0]['action']}"
        ),
        "escalation": "none",
    }
