"""Reviewable IAM proposals; source files are never modified by this module."""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from agent.config import ScanLimits
from agent.governance import Governance
from agent.iam import check_no_expansion, policy_from_evidence
from agent.preflight import inspect_tree


class ValidationRejected(ValueError):
    """A safe, source-free rejection code suitable for public reports."""


def canonical(value):
    return json.dumps(value, sort_keys=True, indent=2) + "\n"


def _target(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("Target must be a relative file inside the repository")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink() or current.is_junction():
            raise ValueError("Linked targets are not permitted")
    current.resolve(strict=True).relative_to(root.resolve(strict=True))
    return current


@dataclass(frozen=True)
class Proposal:
    proposal_id: str
    source_hash: str
    target: str
    before_hash: str
    replacement: str
    diff: str
    method: str
    policy_version: str
    environment: str
    tenant: str

    def to_dict(self):
        return asdict(self)


def propose_iam(
    root: Path,
    relative: str,
    operations: list[dict],
    *,
    tenant: str,
    environment: str,
    governance: Governance | None = None,
) -> Proposal:
    governance = governance or Governance()
    root = root.resolve(strict=True)
    scan = inspect_tree(root, ScanLimits())
    decision = governance.evaluate(
        action="propose",
        tenant=tenant,
        owner=tenant,
        environment=environment,
        source_hash=scan.content_hash,
        current_hash=scan.content_hash,
    )
    if decision.outcome != "permit":
        raise ValueError(decision.reason)
    path = _target(root, relative)
    if path.suffix.lower() != ".json":
        raise ValueError("This phase supports standalone JSON identity policies only")
    before_bytes = path.read_bytes()
    before = before_bytes.decode("utf-8")
    candidate = policy_from_evidence(operations)
    check = check_no_expansion(json.loads(before), candidate)
    if check.status != "safe":
        raise ValueError(f"{check.status}: {check.reason}")
    replacement = canonical(candidate)
    fields = {
        "source_hash": scan.content_hash,
        "target": Path(relative).as_posix(),
        "before_hash": hashlib.sha256(before_bytes).hexdigest(),
        "replacement": replacement,
        "diff": "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                replacement.splitlines(keepends=True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
            )
        ),
        "method": "static_reviewed_operations_not_activity_history",
        "policy_version": governance.version,
        "environment": environment,
        "tenant": tenant,
    }
    identity = hashlib.sha256(canonical(fields).encode()).hexdigest()
    return Proposal(proposal_id=identity, **fields)


@dataclass(frozen=True)
class Validation:
    status: str
    checks: tuple[str, ...]
    errors: tuple[str, ...]
    runtime_status: str = "not_run"
    aws_iam_status: str = "not_verified"

    def to_dict(self):
        return asdict(self)


def validate_proposal(
    root: Path,
    proposal: Proposal,
    *,
    tenant: str,
    environment: str,
    governance: Governance | None = None,
) -> Validation:
    """Read-only patch/syntax validation. No build scripts, imports or tests are executed."""
    checks = []
    try:
        root = root.resolve(strict=True)
        fields = proposal.to_dict()
        identity = fields.pop("proposal_id")
        if hashlib.sha256(canonical(fields).encode()).hexdigest() != identity:
            raise ValidationRejected("proposal_integrity_mismatch")
        governance = governance or Governance()
        if proposal.policy_version != governance.version:
            raise ValidationRejected("policy_version_changed")
        if proposal.tenant != tenant or proposal.environment != environment:
            raise ValidationRejected("tenant_or_environment_mismatch")
        scan = inspect_tree(root, ScanLimits())
        if scan.content_hash != proposal.source_hash:
            raise ValidationRejected("source_changed_rescan_required")
        path = _target(root, proposal.target)
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != proposal.before_hash:
            raise ValidationRejected("patch_precondition_failed")
        checks.append("source_and_proposal_integrity")
        check = check_no_expansion(json.loads(content), json.loads(proposal.replacement))
        if check.status != "safe":
            raise ValidationRejected(f"iam_{check.status}")
        checks.append("static_iam_subset")
        for source in scan.files:
            if source.suffix == ".py":
                ast.parse(source.read_bytes(), filename=source.relative_to(root).as_posix())
        checks.append("python_syntax_without_execution")
        return Validation("static_validated", tuple(checks), ())
    except ValidationRejected as error:
        return Validation("unvalidated", tuple(checks), (str(error),))
    except (ValueError, OSError, SyntaxError, TypeError, RecursionError):
        # Never echo source text or parser snippets into reports.
        return Validation(
            "unvalidated",
            tuple(checks),
            ("Validation rejected; stale, unsupported, or invalid input",),
        )
