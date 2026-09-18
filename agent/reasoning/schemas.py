"""Versioned model output contracts and the local validator that enforces them.

The Claude API enforces `strict` tool schemas, but Claude in Amazon Bedrock does not support
structured outputs, and length, count and pattern keywords are never enforced server-side.
Every model response is therefore validated here against the complete schema before use.
"""

from __future__ import annotations

import re
from typing import Any

CONTRACT_VERSION = "reasoning-contract-1"
MAX_BATCH = 8

ESCALATIONS = (
    "none",
    "needs_stronger_model",
    "conflicting_evidence",
    "insufficient_evidence",
    "possible_prompt_injection",
    "risk_higher_than_policy",
)
IMPACTS = (
    "credential_exposure",
    "privilege_escalation",
    "data_exposure",
    "unauthorized_access",
    "unsafe_code_execution",
    "runtime_failure",
    "misconfiguration",
)
LIMITATIONS = (
    "none",
    "needs_runtime_evidence",
    "needs_source_code",
    "outside_scan_scope",
    "policy_decision_is_final",
    "request_not_allowed",
    "insufficient_evidence",
)
INTENTS = (
    "explain_finding",
    "why_risky",
    "how_to_fix",
    "false_positive_challenge",
    "prioritize",
    "compare",
    "policy_decision",
    "deploy_readiness",
    "scan_overview",
    "concept",
    "general",
)
DIFFICULTIES = ("low", "medium", "high")
# JSON Schema keywords the Claude API does not accept in strict schemas; enforced locally instead.
UNSUPPORTED_BY_API = frozenset(
    {"minLength", "maxLength", "pattern", "minItems", "maxItems", "minimum", "maximum"}
)


def text(max_length: int, min_length: int = 1) -> dict:
    return {"type": "string", "minLength": min_length, "maxLength": max_length}


def array(items: dict, max_items: int, min_items: int = 0) -> dict:
    return {"type": "array", "items": items, "minItems": min_items, "maxItems": max_items}


def choice(values: tuple[str, ...]) -> dict:
    return {"type": "string", "enum": list(values)}


def strict_object(properties: dict) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


# Patterns are matched against the whole string.
REF = {
    "type": "string",
    "maxLength": 48,
    "pattern": r"(SCAN|G[1-9][0-9]{0,2})(\.[A-Za-z][A-Za-z0-9_]{0,23}){0,2}",
}
GROUP_ID = {"type": "string", "maxLength": 4, "pattern": r"G[1-9][0-9]{0,2}"}
REFS = array(REF, 20, 1)

EXPLANATION = strict_object(
    {
        "group_id": GROUP_ID,
        "headline": text(140, 10),
        "what_happened": text(700, 30),
        "why_it_matters": text(700, 30),
        "impact": choice(IMPACTS),
        "fix_steps": array(strict_object({"action": text(360, 10), "refs": REFS}), 6, 1),
        "verify": array(text(280, 10), 3, 1),
        "uncertainty": array(text(280, 10), 3),
        "refs": REFS,
        "escalation": choice(ESCALATIONS),
    }
)
SYNTHESIS = strict_object(
    {
        "headline": text(160, 10),
        "overview": text(1100, 40),
        "priorities": array(
            strict_object({"group_id": GROUP_ID, "why_now": text(360, 10), "refs": REFS}), 12, 1
        ),
        "combined_risks": array(
            strict_object(
                {"group_ids": array(GROUP_ID, 6, 2), "risk": text(480, 20), "refs": REFS}
            ),
            5,
        ),
        "next_step": text(360, 10),
        "escalation": choice(ESCALATIONS),
    }
)
ANSWER = strict_object(
    {
        "answer": text(1800, 20),
        "key_points": array(text(280, 5), 5),
        "refs": array(REF, 20),
        "answerable": {"type": "boolean"},
        "limitation": choice(LIMITATIONS),
        "follow_up": text(280, 0),
        "escalation": choice(ESCALATIONS),
    }
)
CLASSIFICATION = strict_object(
    {
        "intent": choice(INTENTS),
        "group_ids": array(GROUP_ID, 10),
        "difficulty": choice(DIFFICULTIES),
        "needs_clarification": {"type": "boolean"},
        "clarifying_question": text(280, 0),
    }
)

EXPLAIN_TOOL = {
    "name": "submit_explanations",
    "description": (
        "Submit one plain-language explanation for each requested finding group and, only when "
        "requested, the scan synthesis (otherwise null). Call exactly once."
    ),
    "input_schema": strict_object(
        {
            "explanations": array(EXPLANATION, MAX_BATCH),
            "synthesis": {"anyOf": [SYNTHESIS, {"type": "null"}]},
        }
    ),
}
ANSWER_TOOL = {
    "name": "submit_answer",
    "description": "Submit the grounded answer to the user's question. Call exactly once.",
    "input_schema": ANSWER,
}
CLASSIFY_TOOL = {
    "name": "classify_question",
    "description": "Classify the user's question about this scan. Call exactly once.",
    "input_schema": CLASSIFICATION,
}


def api_schema(schema: Any) -> Any:
    """Copy of `schema` without keywords the API rejects in strict mode."""
    if isinstance(schema, dict):
        return {k: api_schema(v) for k, v in schema.items() if k not in UNSUPPORTED_BY_API}
    if isinstance(schema, list):
        return [api_schema(item) for item in schema]
    return schema


def tool_definition(tool: dict, *, strict: bool) -> dict:
    definition = {
        "name": tool["name"],
        "description": tool["description"],
        "input_schema": api_schema(tool["input_schema"]),
    }
    if strict:
        definition["strict"] = True
    return definition


_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def _safe_name(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "?", str(value))[:32]


def validate(schema: dict, value: Any, path: str = "$", limit: int = 40) -> list[str]:
    """Validate `value` against the schema subset used by these contracts.

    Messages never echo model-supplied string values, only paths and property names.
    """
    errors: list[str] = []
    _validate(schema, value, path, errors, limit)
    return errors


def _validate(schema: dict, value: Any, path: str, errors: list[str], limit: int) -> None:
    if len(errors) >= limit:
        return
    if "anyOf" in schema:
        if not any(not validate(option, value, path, limit) for option in schema["anyOf"]):
            errors.append(f"{path}: does not match any allowed shape")
        return
    kind = schema.get("type")
    if kind in {"integer", "number"}:
        valid = isinstance(value, int if kind == "integer" else (int, float))
        valid = valid and not isinstance(value, bool)
    else:
        valid = kind is None or isinstance(value, _TYPES[kind])
    if not valid:
        errors.append(f"{path}: expected {kind}")
        return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value is not one of the allowed options")
    if kind == "string":
        if len(value) < schema.get("minLength", 0) or not value.strip() and schema.get("minLength"):
            errors.append(f"{path}: too short or blank")
        if len(value) > schema.get("maxLength", 10**9):
            errors.append(f"{path}: longer than {schema['maxLength']} characters")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            errors.append(f"{path}: invalid format")
    elif kind == "array":
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 10**9):
            errors.append(
                f"{path}: needs {schema.get('minItems', 0)}-{schema.get('maxItems')} items"
            )
        for index, item in enumerate(value[: schema.get("maxItems", len(value))]):
            _validate(schema["items"], item, f"{path}[{index}]", errors, limit)
    elif kind == "object":
        properties = schema.get("properties", {})
        for name in schema.get("required", ()):
            if name not in value:
                errors.append(f"{path}: missing required field {name}")
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    errors.append(f"{path}: unexpected field {_safe_name(name)}")
        for name, subschema in properties.items():
            if name in value:
                _validate(subschema, value[name], f"{path}.{name}", errors, limit)
