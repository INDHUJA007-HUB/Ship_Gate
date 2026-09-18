"""Phase 7: turn an over-broad identity policy into a strictly narrower, reviewable one.

Two methods can produce a recommendation, and they are never presented as the same thing:

* ``access_analyzer_activity`` — IAM Access Analyzer generated a policy from what the principal
  was *observed* doing in CloudTrail. This is evidence about the past, so it can miss code paths
  that have not run yet.
* ``static_estimate`` — the candidate is derived from the literal boto3 calls the scanned source
  makes. There is no activity behind it, so every surface labels it as an estimate.

A candidate is only offered as a recommendation when it is provably narrower than the policy it
replaces: the local subset proof must conclude that nothing new is granted, and at least one
action or resource the original allowed must be gone. When AWS is reachable, ``CheckNoNewAccess``
is the second opinion. Nothing here writes to a repository, a role, or a deployed policy.
"""

from __future__ import annotations

import difflib
import hashlib
import time
from dataclasses import asdict, dataclass, replace
from fnmatch import fnmatchcase
from pathlib import Path

from agent.access_analyzer import (
    AnalysisUnavailable,
    ExpansionCheck,
    GenerationOutcome,
    GenerationRequest,
    PolicyGenerator,
    await_generation,
)
from agent.code_actions import required_actions
from agent.config import ScanLimits
from agent.governance import Governance
from agent.iam import check_no_expansion, covered_by
from agent.policy_documents import identity_policy, load_document, replace_policy, serialize
from agent.preflight import inspect_tree
from agent.remediation import canonical, resolve_target

ACTIVITY = "access_analyzer_activity"
STATIC = "static_estimate"
METHODS = (ACTIVITY, STATIC)
WILDCARD = ("*", "?")
PLACEHOLDER = "${"

# One label and one confidence per method, so no surface can present a static estimate as
# observed activity.
PROVENANCE = {
    ACTIVITY: {
        "label": "Generated from real access activity (IAM Access Analyzer + CloudTrail)",
        "confidence": "observed_activity",
    },
    STATIC: {
        "label": "Estimated from static analysis of the source (no activity history used)",
        "confidence": "static_estimate",
    },
}

NO_ACTIVITY_GUIDANCE = (
    "Analyzing recent activity — run your app a few times first, then re-run this command.",
    "For a policy now, re-run with --method static to get a clearly labelled estimate instead.",
)


@dataclass(frozen=True)
class Provenance:
    method: str
    label: str
    confidence: str
    reasons: tuple[str, ...] = ()
    activity: tuple[tuple[str, str], ...] = ()
    guidance: tuple[str, ...] = ()

    @property
    def observed(self) -> bool:
        return self.confidence == PROVENANCE[ACTIVITY]["confidence"]

    def to_dict(self):
        result = asdict(self)
        result["activity"] = dict(self.activity)
        return result


@dataclass(frozen=True)
class Narrowing:
    """The proof that a candidate grants less, and that it grants nothing new."""

    verdict: str  # strictly_narrower, not_narrower, expansion, inconclusive
    reason: str
    method: str = "static_identity_policy_subset"
    aws_status: str = "not_run"
    aws_method: str | None = None
    aws_reasons: tuple[str, ...] = ()
    removed_actions: tuple[str, ...] = ()
    removed_resources: tuple[str, ...] = ()
    retained_actions: tuple[str, ...] = ()
    retained_resource_wildcards: int = 0
    resource_placeholders: int = 0

    @property
    def strictly_narrower(self) -> bool:
        return self.verdict == "strictly_narrower"

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class Coverage:
    """What the source says the code needs, and what a candidate does or does not grant."""

    code_actions: tuple[str, ...] = ()
    unresolved_files: tuple[str, ...] = ()
    ungranted_by_original: tuple[str, ...] = ()
    missing_from_candidate: tuple[str, ...] = ()
    outside_target_scope: tuple[str, ...] = ()
    note: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class Attempt:
    method: str
    status: str  # recommended, needs_review, rejected, unavailable
    provenance: Provenance
    reasons: tuple[str, ...] = ()
    candidate: dict | None = None
    diff: str = ""
    policy_diff: str = ""
    narrowing: Narrowing | None = None
    coverage: Coverage | None = None
    guidance: tuple[str, ...] = ()

    @property
    def offered(self) -> bool:
        return self.status in {"recommended", "needs_review"} and self.candidate is not None

    def to_dict(self):
        return {
            "method": self.method,
            "status": self.status,
            "provenance": self.provenance.to_dict(),
            "reasons": list(self.reasons),
            "candidate": self.candidate,
            "diff": self.diff,
            "policy_diff": self.policy_diff,
            "narrowing": self.narrowing.to_dict() if self.narrowing else None,
            "coverage": self.coverage.to_dict() if self.coverage else None,
            "guidance": list(self.guidance),
        }


@dataclass(frozen=True)
class Recommendation:
    recommendation_id: str
    target: str
    role_arn: str | None
    tenant: str
    environment: str
    source_hash: str
    policy_version: str
    status: str  # recommended, needs_review, none
    before: dict
    attempts: tuple[Attempt, ...]

    @property
    def chosen(self) -> Attempt | None:
        for status in ("recommended", "needs_review"):
            for attempt in self.attempts:
                if attempt.status == status:
                    return attempt
        return None

    def to_dict(self):
        return {
            "recommendation_id": self.recommendation_id,
            "target": self.target,
            "role_arn": self.role_arn,
            "tenant": self.tenant,
            "environment": self.environment,
            "source_hash": self.source_hash,
            "policy_version": self.policy_version,
            "status": self.status,
            "before": self.before,
            "chosen_method": self.chosen.method if self.chosen else None,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
        }


def _values(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [item for item in value or [] if isinstance(item, str)]


def action_values(policy: dict) -> list[str]:
    """Actions as written. Comparison is case-insensitive, but reports keep the source casing."""
    return _values_for(policy, "Action")


def _lower(values) -> set[str]:
    return {value.lower() for value in values}


def resource_values(policy: dict) -> list[str]:
    return _values_for(policy, "Resource")


def _values_for(policy: dict, key: str) -> list[str]:
    found: list[str] = []
    for statement in policy.get("Statement") or []:
        found.extend(_values(statement.get(key)))
    return found


def over_broad(policy: dict) -> bool:
    """A policy is over-broad when at least one statement grants a wildcard action."""
    return any(any(char in action for char in WILDCARD) for action in action_values(policy))


def provenance_for(method: str, *, reasons=(), activity=(), guidance=()) -> Provenance:
    if method not in PROVENANCE:
        raise ValueError("unknown_method")
    return Provenance(
        method=method,
        label=PROVENANCE[method]["label"],
        confidence=PROVENANCE[method]["confidence"],
        reasons=tuple(reasons),
        activity=tuple(activity),
        guidance=tuple(guidance),
    )


def static_candidate(before: dict, wanted: tuple[str, ...]) -> tuple[dict, tuple[str, ...]]:
    """Narrow the wildcard-granting statements to the actions the source actually calls.

    Each kept action stays inside the resource scope of the statement that granted it, so the
    candidate cannot widen resources while narrowing actions. Statements that are already exact
    are left untouched, and a wildcard statement nothing needs is dropped rather than rewritten.

    Returns the candidate and the estimated actions no statement granted at all.
    """
    if not wanted:
        raise ValueError("no_static_actions")
    remaining = list(wanted)
    statements = []
    for statement in before.get("Statement") or []:
        granted = _values(statement.get("Action"))
        broad = [pattern for pattern in granted if any(char in pattern for char in WILDCARD)]
        if not broad:
            # Already exact, so it is kept untouched — but its actions are covered, not missing.
            statements.append(statement)
            remaining = [action for action in remaining if action.lower() not in _lower(granted)]
            continue
        needed = [action for action in remaining if any(_granted_by(action, p) for p in broad)]
        remaining = [action for action in remaining if action not in needed]
        if not needed:
            continue
        replacement = dict(statement)
        replacement["Action"] = needed[0] if len(needed) == 1 else needed
        statements.append(replacement)
    if not statements:
        raise ValueError("no_reducible_actions")
    return {"Version": before.get("Version", "2012-10-17"), "Statement": statements}, tuple(
        remaining
    )


def activity_candidate(outcome: GenerationOutcome) -> dict:
    """The generated document as AWS returned it, with every generated statement preserved."""
    statements = []
    for policy in outcome.policies:
        statements.extend(policy.get("Statement") or [])
    if not statements:
        raise ValueError("no_activity_history")
    version = next(
        (policy.get("Version") for policy in outcome.policies if policy.get("Version")),
        "2012-10-17",
    )
    return {"Version": version, "Statement": statements}


def scope_to_target(before: dict, generated: dict) -> tuple[dict, tuple[str, ...]]:
    """Restrict an AWS-generated profile to access the replaced policy already granted.

    Access Analyzer generates for the whole principal, so a role with other policies can come
    back with actions this policy never granted. Keeping only the contained
    action/resource pairs means the replacement stays a narrowing of the document it replaces,
    and everything dropped is reported instead of silently discarded.
    """
    allowed = [
        (action, resource)
        for statement in before.get("Statement") or []
        for action in _values(statement.get("Action"))
        for resource in _values(statement.get("Resource"))
    ]
    kept, outside = [], []
    for statement in generated.get("Statement") or []:
        actions = _values(statement.get("Action"))
        resources = _values(statement.get("Resource"))
        pairs = [
            (action, resource)
            for action in actions
            for resource in resources
            if any(
                covered_by(action, permitted, action=True) and covered_by(resource, scope)
                for permitted, scope in allowed
            )
        ]
        if not pairs:
            outside.extend(actions)
            continue
        outside.extend(action for action in actions if action not in {a for a, _ in pairs})
        replacement = dict(statement)
        kept_actions = [action for action in actions if any(action == a for a, _ in pairs)]
        kept_resources = [
            resource for resource in resources if any(resource == r for _, r in pairs)
        ]
        replacement["Action"] = kept_actions[0] if len(kept_actions) == 1 else kept_actions
        replacement["Resource"] = kept_resources[0] if len(kept_resources) == 1 else kept_resources
        kept.append(replacement)
    if not kept:
        raise ValueError("generated_policy_outside_target_scope")
    version = generated.get("Version") or "2012-10-17"
    return {"Version": version, "Statement": kept}, tuple(sorted(set(outside)))


def _granted_by(action: str, pattern: str) -> bool:
    return fnmatchcase(action.lower(), pattern.lower())


def _contains_placeholder(policy: dict) -> int:
    return sum(1 for resource in resource_values(policy) if PLACEHOLDER in resource)


def _proof_copy(policy: dict) -> dict:
    """Replace AWS resource placeholders with the widest value before proving containment.

    ``"arn:aws:s3:::${BucketName}"`` means "a bucket we could not name", so the subset rule
    treats it as unknown scope rather than assuming it stays inside the original policy.
    """
    if not _contains_placeholder(policy):
        return policy
    statements = []
    for statement in policy.get("Statement") or []:
        replaced = dict(statement)
        replaced["Resource"] = [
            "*" if PLACEHOLDER in resource else resource
            for resource in _values(statement.get("Resource"))
        ]
        statements.append(replaced)
    return {**policy, "Statement": statements}


def evaluate_narrowing(
    before: dict,
    candidate: dict,
    *,
    generator: PolicyGenerator | None = None,
    verify: str = "local",
) -> Narrowing:
    """Prove the candidate is a strict narrowing, or say exactly why it is not offered."""
    local = check_no_expansion(before, _proof_copy(candidate))
    removed_actions = tuple(
        sorted(
            action
            for action in set(action_values(before))
            if action.lower() not in _lower(action_values(candidate))
        )
    )
    removed_resources = tuple(
        sorted(
            resource
            for resource in set(resource_values(before))
            if resource not in set(resource_values(candidate))
        )
    )
    proof = Narrowing(
        verdict="inconclusive",
        reason="not_evaluated",
        removed_actions=removed_actions,
        removed_resources=removed_resources,
        retained_actions=tuple(sorted(set(action_values(candidate)))),
        retained_resource_wildcards=sum(1 for r in resource_values(candidate) if r == "*"),
        resource_placeholders=_contains_placeholder(candidate),
    )
    if local.status == "expansion":
        return replace(proof, verdict="expansion", reason="candidate_expands_access")
    if candidate == before or not (removed_actions or removed_resources):
        return replace(proof, verdict="not_narrower", reason="candidate_not_narrower")
    aws: ExpansionCheck | None = None
    if verify == "aws":
        if generator is None:
            raise ValueError("generator_required_for_aws_verification")
        aws = generator.no_new_access(before, candidate)
    aws_fields = {
        "aws_status": aws.status if aws else "not_run",
        "aws_method": aws.method if aws else None,
        "aws_reasons": aws.reasons if aws else (),
    }
    if aws is not None and aws.status == "expansion":
        return replace(
            proof, verdict="expansion", reason="aws_check_reports_new_access", **aws_fields
        )
    if local.status == "inconclusive" and (aws is None or aws.status != "safe"):
        # e.g. the original statement carries a Condition, which the local subset rule refuses.
        return replace(
            proof, verdict="inconclusive", reason="local_subset_proof_inconclusive", **aws_fields
        )
    if aws is not None and aws.status == "inconclusive":
        return replace(proof, verdict="inconclusive", reason="aws_check_inconclusive", **aws_fields)
    # Name the rule that actually established containment, so a report never implies AWS proved
    # something that only the local subset rule checked.
    authority = "static_identity_policy_subset" if local.status == "safe" else aws.method
    return replace(
        proof,
        verdict="strictly_narrower",
        reason="candidate_strictly_narrower",
        method=authority,
        **aws_fields,
    )


def render_diff(before_text: str, after_text: str, target: str) -> str:
    return "".join(
        difflib.unified_diff(
            before_text.splitlines(keepends=True),
            after_text.splitlines(keepends=True),
            fromfile=f"a/{target}",
            tofile=f"b/{target}",
        )
    )


def render(recommendation: Recommendation) -> str:
    """A human report. Every attempt states which method produced it, chosen or not."""
    lines = [
        f"target: {recommendation.target}",
        f"role: {recommendation.role_arn or '(none)'}",
        f"status: {recommendation.status}",
        f"recommendation_id: {recommendation.recommendation_id}",
    ]
    for attempt in recommendation.attempts:
        lines += [
            "",
            f"== method: {attempt.method} ==",
            f"provenance: {attempt.provenance.label}",
            f"confidence: {attempt.provenance.confidence}",
            f"status: {attempt.status}",
        ]
        if attempt.reasons:
            lines.append("reasons: " + ", ".join(attempt.reasons))
        for key, value in attempt.provenance.activity:
            lines.append(f"{key}: {value}")
        if attempt.narrowing:
            lines += [
                f"narrowing: {attempt.narrowing.verdict} ({attempt.narrowing.method})",
                f"aws_check_no_new_access: {attempt.narrowing.aws_status}",
                "removed: " + (", ".join(attempt.narrowing.removed_actions) or "(none)"),
                "kept: " + (", ".join(attempt.narrowing.retained_actions) or "(none)"),
                f"retained resource wildcards: {attempt.narrowing.retained_resource_wildcards}",
            ]
        if attempt.coverage:
            coverage = attempt.coverage
            lines.append("code actions: " + (", ".join(coverage.code_actions) or "(none resolved)"))
            for label, values in (
                ("not granted by the original", coverage.ungranted_by_original),
                ("missing from this candidate", coverage.missing_from_candidate),
                ("outside the replaced policy", coverage.outside_target_scope),
                ("unresolved files", coverage.unresolved_files),
            ):
                if values:
                    lines.append(f"{label}: " + ", ".join(values))
        for line in attempt.guidance:
            lines.append(f"note: {line}")
        if attempt.policy_diff:
            lines += ["", "policy before/after:", attempt.policy_diff.rstrip("\n")]
        if attempt.diff:
            lines += [
                "",
                "document patch (YAML is re-serialized in one format):",
                attempt.diff.rstrip("\n"),
            ]
    return "\n".join(lines) + "\n"


def _read_target(root: Path, target: str):
    path = resolve_target(root, target)
    if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
        raise ValueError("JSON or SAM YAML required")
    text = path.read_bytes().decode("utf-8")
    document = load_document(text)
    selector, policy = identity_policy(document)
    return document, selector, policy, text, path.suffix.lower()


def _coverage(
    root, files, before, candidate, *, observed: bool, dropped=(), outside=()
) -> Coverage:
    estimate = required_actions(root, files)
    ungranted = estimate.missing_from(action_values(before))
    missing = estimate.missing_from(action_values(candidate)) if candidate else estimate.actions
    note = (
        "Observed activity only covers code paths that have run; static calls that have not been "
        "exercised are reported as missing."
        if observed
        else "Coverage is estimated from literal boto3 client calls in the source; dynamic "
        "service names and boto3.resource usage are listed as unresolved."
    )
    return Coverage(
        code_actions=estimate.actions,
        unresolved_files=estimate.unresolved,
        ungranted_by_original=ungranted,
        missing_from_candidate=missing,
        outside_target_scope=tuple(outside) or dropped,
        note=note,
    )


def _status_for(narrowing: Narrowing, review_reasons) -> str:
    if narrowing.verdict == "strictly_narrower":
        return "needs_review" if review_reasons else "recommended"
    if narrowing.verdict == "inconclusive":
        return "needs_review"
    return "rejected"


def _unavailable(method: str, reason: str, guidance=(), activity=()) -> Attempt:
    return Attempt(
        method=method,
        status="unavailable",
        provenance=provenance_for(method, reasons=(reason,), guidance=guidance, activity=activity),
        reasons=(reason,),
        guidance=tuple(guidance),
    )


def _activity_attempt(
    before: dict,
    *,
    role_arn,
    generator,
    cloud_trail,
    verify,
    timeout_seconds,
    interval_seconds,
    sleep,
    clock,
    finish,
    coverage,
) -> Attempt:
    method = ACTIVITY
    if not role_arn:
        return _unavailable(
            method,
            "role_required_for_activity",
            (
                "Pass --role with the IAM role ARN of the principal whose activity should be "
                "analyzed.",
            ),
        )
    if generator is None:
        return _unavailable(
            method,
            "access_analyzer_not_configured",
            (
                "No IAM Access Analyzer client is configured; AWS credentials are required.",
                "Re-run with --method static for a labelled estimate that needs no AWS access.",
            ),
        )
    job_id = None
    activity: tuple[tuple[str, str], ...] = ()
    try:
        job_id = generator.start(GenerationRequest(principal_arn=role_arn, cloud_trail=cloud_trail))
        outcome = await_generation(
            generator,
            job_id,
            timeout_seconds=timeout_seconds,
            interval_seconds=interval_seconds,
            sleep=sleep,
            clock=clock,
        )
        activity = (("job_id", str(job_id)),) + tuple(outcome.activity)
        if outcome.status != "SUCCEEDED":
            raise AnalysisUnavailable(outcome.reason or "access_analyzer_job_failed")
        if outcome.no_activity:
            raise AnalysisUnavailable("no_activity_history")
        candidate, outside = scope_to_target(before, activity_candidate(outcome))
    except AnalysisUnavailable as error:
        guidance = list(NO_ACTIVITY_GUIDANCE) if error.code == "no_activity_history" else []
        if error.code in {"credentials_unavailable", "endpoint_unreachable", "access_denied"}:
            guidance.append("Re-run with --method static for a labelled estimate instead.")
        return _unavailable(method, error.code, tuple(guidance), activity=activity)
    except ValueError as error:
        return _unavailable(method, str(error), activity=activity)

    candidate, diff, policy_diff = finish(candidate)
    try:
        narrowing = evaluate_narrowing(before, candidate, generator=generator, verify=verify)
    except AnalysisUnavailable as error:
        return _unavailable(method, error.code, activity=activity)
    reasons = []
    guidance = []
    if not outcome.is_complete:
        reasons.append("access_analyzer_profile_incomplete")
        guidance.append(
            "AWS flagged this profile as incomplete for at least one service; review the actions "
            "it contains before relying on them."
        )
    report = coverage(candidate, outside)
    if report.missing_from_candidate:
        reasons.append("code_calls_unseen_in_activity")
        guidance.append(
            "The source calls actions this profile does not grant, because those code paths have "
            "not run yet. Re-generate after they have, with a wider CloudTrail window."
        )
    if outside:
        reasons.append("actions_outside_replaced_policy")
        guidance.append(
            "The role was observed using access this policy never granted ("
            + ", ".join(outside)
            + "); "
            "those actions came from other policies and are not part of this replacement."
        )
    if narrowing.resource_placeholders:
        reasons.append("resource_placeholders_need_review")
        guidance.append(
            "AWS returned resource placeholders instead of concrete ARNs; resolve them before "
            "applying, because the containment proof treats them as unknown scope."
        )
    status = _status_for(narrowing, review_reasons=narrowing.resource_placeholders or outside)
    return Attempt(
        method=method,
        status=status,
        provenance=provenance_for(
            method, reasons=tuple(reasons), activity=activity, guidance=tuple(guidance)
        ),
        reasons=tuple(reasons) or (narrowing.reason,),
        candidate=candidate,
        diff=diff,
        policy_diff=policy_diff,
        narrowing=narrowing,
        coverage=report,
        guidance=tuple(guidance),
    )


def _static_attempt(before: dict, *, verify, generator, finish, coverage, root, files) -> Attempt:
    method = STATIC
    estimate = required_actions(root, files)
    if not estimate.actions:
        return _unavailable(
            method,
            "no_static_evidence",
            (
                "No literal boto3 client calls were found, so no estimate can be derived from the "
                "source; use reviewed operations with propose-iam, or real activity.",
            ),
        )
    try:
        candidate, dropped = static_candidate(before, estimate.actions)
    except ValueError as error:
        return _unavailable(method, str(error))
    candidate, diff, policy_diff = finish(candidate)
    try:
        narrowing = evaluate_narrowing(before, candidate, generator=generator, verify=verify)
    except AnalysisUnavailable as error:
        return _unavailable(method, error.code)
    report = coverage(candidate, ())
    reasons = []
    guidance = [
        "This candidate is an estimate from static analysis, not evidence of real traffic.",
        "Re-run without --method static once the role has CloudTrail activity, so a policy "
        "generated from what it actually did replaces this estimate.",
    ]
    if dropped:
        reasons.append("code_actions_not_granted_by_original")
        guidance.append(
            "The source calls actions the current policy never granted: "
            + ", ".join(dropped)
            + ". A narrowing cannot fix that; widen the scope first or confirm the calls."
        )
    if estimate.unresolved:
        reasons.append("code_actions_partially_unresolved")
        guidance.append(
            "Some files use boto3 in ways this estimate cannot resolve (dynamic service names or "
            "boto3.resource), so their actions are missing from the candidate."
        )
    if not narrowing.strictly_narrower:
        reasons.append(narrowing.reason)
    status = _status_for(narrowing, review_reasons=dropped or estimate.unresolved)
    return Attempt(
        method=method,
        status=status,
        provenance=provenance_for(method, reasons=tuple(reasons), guidance=tuple(guidance)),
        reasons=tuple(reasons) or ("candidate_strictly_narrower",),
        candidate=candidate,
        diff=diff,
        policy_diff=policy_diff,
        narrowing=narrowing,
        coverage=report,
        guidance=tuple(guidance),
    )


def recommend(
    root: Path,
    target: str,
    *,
    tenant: str,
    environment: str,
    role_arn: str | None = None,
    method: str = "auto",
    generator: PolicyGenerator | None = None,
    cloud_trail=None,
    verify: str = "local",
    timeout_seconds: float = 600,
    interval_seconds: float = 5,
    governance: Governance | None = None,
    sleep=time.sleep,
    clock=time.monotonic,
) -> Recommendation:
    """Build the strictly narrower candidates for one over-broad policy, labelled by method."""
    if method not in {"auto", "activity", "static"}:
        raise ValueError("unknown_method")
    if verify not in {"local", "aws"}:
        raise ValueError("unknown_verification")
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
    document, selector, before, before_text, suffix = _read_target(root, target)

    def finish(candidate: dict) -> tuple[dict, str, str]:
        """Return the candidate, the document patch, and the focused policy before/after."""
        after = serialize(replace_policy(document, selector, candidate), suffix)
        return (
            candidate,
            render_diff(before_text, after, Path(target).as_posix()),
            render_diff(
                canonical(before), canonical(candidate), f"{Path(target).as_posix()}#PolicyDocument"
            ),
        )

    attempts = []
    if method in {"auto", "activity"}:
        attempts.append(
            _activity_attempt(
                before,
                role_arn=role_arn,
                generator=generator,
                cloud_trail=cloud_trail,
                verify=verify,
                timeout_seconds=timeout_seconds,
                interval_seconds=interval_seconds,
                sleep=sleep,
                clock=clock,
                finish=finish,
                coverage=lambda candidate, outside: _coverage(
                    root, scan.files, before, candidate, observed=True, outside=outside
                ),
            )
        )
    if method in {"auto", "static"}:
        attempts.append(
            _static_attempt(
                before,
                verify=verify,
                generator=generator,
                finish=finish,
                coverage=lambda candidate, dropped: _coverage(
                    root, scan.files, before, candidate, observed=False, dropped=dropped
                ),
                root=root,
                files=scan.files,
            )
        )
    fields = {
        "target": Path(target).as_posix(),
        "role_arn": role_arn,
        "tenant": tenant,
        "environment": environment,
        "source_hash": scan.content_hash,
        "policy_version": governance.version,
        "before": before,
        "attempts": [attempt.to_dict() for attempt in attempts],
    }
    chosen = next(
        (
            attempt
            for status in ("recommended", "needs_review")
            for attempt in attempts
            if attempt.status == status
        ),
        None,
    )
    return Recommendation(
        recommendation_id=hashlib.sha256(canonical(fields).encode()).hexdigest(),
        target=fields["target"],
        role_arn=role_arn,
        tenant=tenant,
        environment=environment,
        source_hash=scan.content_hash,
        policy_version=governance.version,
        status=chosen.status if chosen else "none",
        before=before,
        attempts=tuple(attempts),
    )
