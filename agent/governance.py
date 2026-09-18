"""Real embedded Cedar evaluation and source-bound human approval records."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import cedarpy


@dataclass(frozen=True)
class Approval:
    proposal_id: str
    source_hash: str
    policy_version: str
    tenant: str
    environment: str
    reviewer: str
    expires_at: int

    def matches(self, proposal_id, source_hash, policy_version, tenant, environment, now):
        return (
            bool(self.reviewer.strip())
            and self.expires_at > now
            and (
                self.proposal_id,
                self.source_hash,
                self.policy_version,
                self.tenant,
                self.environment,
            )
            == (proposal_id, source_hash, policy_version, tenant, environment)
        )


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str
    policy_version: str

    def to_dict(self):
        return asdict(self)


class Governance:
    def __init__(self, policies: str | None = None):
        self.policies = (
            policies
            if policies is not None
            else (Path(__file__).parent / "policies" / "remediation.cedar").read_text(
                encoding="utf-8"
            )
        )
        self.version = hashlib.sha256(self.policies.encode()).hexdigest()

    def evaluate(
        self,
        *,
        action: str,
        tenant: str,
        owner: str,
        environment: str,
        source_hash: str,
        current_hash: str,
        proposal_id: str = "none",
        validated: bool = False,
        runtime_validated: bool = False,
        access_safe: bool = False,
        approval: Approval | None = None,
        now: int | None = None,
    ) -> Decision:
        try:
            approved = approval is not None and approval.matches(
                proposal_id,
                source_hash,
                self.version,
                tenant,
                environment,
                int(time.time()) if now is None else now,
            )
        except (AttributeError, TypeError, ValueError):
            return Decision("deny", "Invalid approval record", self.version)
        context = {
            "sameTenant": bool(tenant) and tenant == owner,
            "knownEnvironment": environment in {"development", "staging", "production"},
            "fresh": bool(source_hash) and source_hash == current_hash,
            "validated": validated,
            "runtimeValidated": runtime_validated,
            "accessSafe": access_safe,
            "approved": approved,
        }

        def allowed(verb):
            request = {
                "principal": 'User::"operator"',
                "action": f"Action::{json.dumps(verb)}",
                "resource": 'Proposal::"candidate"',
                "context": context,
            }
            result = cedarpy.is_authorized(request, self.policies, [])
            # Cedar may permit when another policy has an evaluation error: fail closed.
            if result.diagnostics.errors:
                raise ValueError("policy evaluation error")
            return result.allowed

        try:
            if allowed(action):
                return Decision("permit", "Cedar permits this operation", self.version)
            if (
                action == "openPR"
                and validated
                and runtime_validated
                and access_safe
                and not approved
                and allowed("review")
            ):
                return Decision(
                    "needs_human_approval", "Approval must bind this exact proposal", self.version
                )
            return Decision("deny", "Cedar denies this operation", self.version)
        except Exception:
            return Decision("deny", "Cedar policy or evaluation error", self.version)
