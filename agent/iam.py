"""Conservative subset proof for simple identity policies; never guess on IAM semantics."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase


@dataclass(frozen=True)
class AccessCheck:
    status: str  # safe, expansion, inconclusive
    reason: str
    method: str = "static_identity_policy_subset"


def _values(value):
    values = [value] if isinstance(value, str) else value
    if (
        not isinstance(values, list)
        or not values
        or not all(isinstance(item, str) and item for item in values)
    ):
        raise ValueError("expected non-empty string or string array")
    return values


def statements(policy):
    if not isinstance(policy, dict) or set(policy) - {"Version", "Id", "Statement"}:
        raise ValueError("unsupported policy document")
    if policy.get("Version") != "2012-10-17":
        raise ValueError("unsupported policy version")
    items = policy.get("Statement")
    items = [items] if isinstance(items, dict) else items
    if not isinstance(items, list) or not items or len(items) > 100:
        raise ValueError("expected 1–100 statements")
    for item in items:
        if not isinstance(item, dict) or set(item) - {"Sid", "Effect", "Action", "Resource"}:
            raise ValueError("Condition/NotAction/NotResource/Principal require AWS review")
        if item.get("Effect") != "Allow":
            raise ValueError("Deny semantics require AWS review")
        _values(item.get("Action"))
        _values(item.get("Resource"))
    return items


def _covered(candidate, existing, *, action=False):
    if action:
        candidate, existing = candidate.lower(), existing.lower()
    if candidate == existing or existing == "*":
        return True
    # Python glob character classes are not IAM wildcard syntax.
    if any(char in candidate for char in "*?${}") or any(char in existing for char in "[]${}"):
        return False
    return fnmatchcase(candidate, existing)


def covered_by(candidate: str, existing: str, *, action: bool = False) -> bool:
    """Public form of the containment rule `check_no_expansion` applies to a single value."""
    return _covered(candidate, existing, action=action)


def check_no_expansion(before, after) -> AccessCheck:
    try:
        old, new = statements(before), statements(after)
    except ValueError as error:
        return AccessCheck("inconclusive", str(error))
    for statement in new:
        for action in _values(statement["Action"]):
            for resource in _values(statement["Resource"]):
                if not any(
                    any(_covered(action, a, action=True) for a in _values(existing["Action"]))
                    and any(_covered(resource, r) for r in _values(existing["Resource"]))
                    for existing in old
                ):
                    return AccessCheck("expansion", "Candidate access is not provably contained")
    return AccessCheck("safe", "Every candidate action/resource pair is contained in the original")


def policy_from_evidence(operations: list[dict]) -> dict:
    """Caller supplies reviewed exact operations, never inferred ARNs or activity claims."""
    if not operations or len(operations) > 100:
        raise ValueError("Provide 1–100 reviewed action/resource operations")
    result = []
    for operation in operations:
        if set(operation) != {"action", "resource"}:
            raise ValueError("Each operation needs exactly action and resource")
        action, resource = operation["action"], operation["resource"]
        if not isinstance(action, str) or not isinstance(resource, str):
            raise ValueError("Operations must contain strings")
        if (
            ":" not in action
            or not resource.startswith("arn:")
            or any(char in action + resource for char in "*?${}[]\n\r")
        ):
            raise ValueError(
                "Exact action and ARN required; wildcards and variables are unsupported"
            )
        result.append({"Effect": "Allow", "Action": action, "Resource": resource})
    return {"Version": "2012-10-17", "Statement": result}
