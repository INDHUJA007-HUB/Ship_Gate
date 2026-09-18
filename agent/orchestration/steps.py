"""Pipeline steps: each is a function of (event, StepContext) that is safe to run more than once.

The same functions back the AWS Lambda tasks and the local state-machine runner. Idempotency is
structural, not bolted on: detector results are write-once checkpoints keyed by content hash,
detector fingerprint and tenant; findings use content-derived IDs with conditional writes;
per-run artifacts are write-once under (run, generation, input digest); explanations reuse the
Phase 5 content-hash cache; review items are write-once per (run, generation, step).
"""

from __future__ import annotations

import functools
import json
import logging
import sqlite3
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from agent.cache import finding_from_dict, report_from_dict
from agent.config import Settings
from agent.detectors import DETECTORS, Detector
from agent.domain import ScanStatus
from agent.finding_policy import FindingPolicy, PolicyContext, PolicyLimits
from agent.ingest import Ingested, ingest
from agent.models import SCHEMA_VERSION, ScanReport
from agent.orchestration.contracts import (
    PIPELINE_VERSION,
    PRINCIPAL,
    RESULT_SCHEMA,
    RUN_ID,
    InvalidRequest,
    digest,
    validate_request,
)
from agent.orchestration.failures import (
    DetectorDefect,
    PipelineDefect,
    ScanRejected,
    StepError,
    ToolUnavailable,
    TransientStepError,
    UnexpectedStepError,
    detector_failure,
    disposition,
    ingestion_failure,
    reason_from_error,
    safe_code,
)
from agent.orchestration.faults import FaultPlan
from agent.orchestration.snapshots import SnapshotWorkspace, build_snapshot
from agent.orchestration.state import PipelineState, StateUnavailable
from agent.preflight import PreflightError, inspect_tree
from agent.reasoning import ReasoningConfig, ReasoningContext, ReasoningService
from agent.reasoning.budget import TRANSIENT as PROVIDER_TRANSIENT
from agent.reasoning.cache import ExplanationCache
from agent.reasoning.knowledge import PLAYBOOKS
from agent.reasoning.providers import ProviderError
from agent.reasoning.service import VERSIONS as REASONING_VERSIONS
from agent.store import ScanStore
from agent.workflow import record_scan_report, start_scan

LOGGER = logging.getLogger("first_commit.pipeline")
TRANSIENT_AWS_CODES = {
    "ThrottlingException",
    "ProvisionedThroughputExceededException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "TransactionConflictException",
    "InternalServerError",
    "InternalError",
    "ServiceUnavailable",
    "SlowDown",
    "RequestTimeout",
}
TRANSIENT_EXCEPTIONS = {
    "EndpointConnectionError",
    "ConnectionClosedError",
    "ReadTimeoutError",
    "ConnectTimeoutError",
}
DISPOSITION_TEXT = {
    "retry_exhausted": "failed after automatic retries",
    "human_review": "failed on unexpected input and was sent for human review",
    "operator_action": "could not run and needs an operator to fix the configuration",
}


@dataclass
class StepContext:
    mode: str
    state: PipelineState
    store: ScanStore
    explanations: ExplanationCache
    settings: Settings
    workspace: SnapshotWorkspace
    faults: FaultPlan = field(default_factory=FaultPlan)
    provider_factory: Callable[[], object] = lambda: None
    provider_identity: str = "none"
    reasoning: ReasoningConfig = field(default_factory=ReasoningConfig)
    detectors: Mapping[str, Detector] = field(default_factory=lambda: DETECTORS)
    external_detectors: bool = True
    policy_limits: PolicyLimits | None = None
    clock: Callable[[], float] = time.time
    _policy: FindingPolicy | None = None

    def policy(self) -> FindingPolicy:
        if self._policy is None:
            self._policy = FindingPolicy(store=self.store, limits=self.policy_limits)
        return self._policy

    def selected(self) -> list[Detector]:
        return [d for d in self.detectors.values() if self.external_detectors or not d.external]


def log(**fields) -> None:
    LOGGER.info(json.dumps({"component": "pipeline", **fields}, sort_keys=True, default=str))


def _aws_code(error: Exception) -> str | None:
    response = getattr(error, "response", None)
    return response.get("Error", {}).get("Code") if isinstance(response, dict) else None


def step(name: str):
    """Classify every failure; unclassified exceptions lose their text before leaving the step."""

    def wrap(function):
        @functools.wraps(function)
        def run(event: dict, context: StepContext):
            label = name
            if name == "detect" and isinstance(event, dict):
                label = str((event.get("detector") or {}).get("name", "detect"))[:40]
            started = time.monotonic()
            base = {"step": label, "attempt": _attempt(event)}
            try:
                result = function(event if isinstance(event, dict) else {}, context)
            except StepError as error:
                log(**base, outcome="failed", error=type(error).__name__, reason=error.code)
                raise
            except Exception as error:
                transient = (
                    isinstance(error, StateUnavailable | sqlite3.OperationalError)
                    or isinstance(error, TimeoutError | ConnectionError)
                    or _aws_code(error) in TRANSIENT_AWS_CODES
                    or type(error).__name__ in TRANSIENT_EXCEPTIONS
                )
                replacement = (
                    TransientStepError("storage_unavailable")
                    if transient
                    else UnexpectedStepError("unexpected_error")
                )
                log(
                    **base,
                    outcome="failed",
                    error=type(replacement).__name__,
                    exception=type(error).__name__,
                )
                raise replacement from None
            log(**base, outcome="succeeded", seconds=round(time.monotonic() - started, 3))
            return result

        return run

    return wrap


def _attempt(event) -> int:
    attempt = event.get("attempt", 0) if isinstance(event, dict) else 0
    return attempt if isinstance(attempt, int) and 0 <= attempt <= 20 else 0


def _run(event: dict) -> dict:
    run = event.get("run")
    if (
        not isinstance(run, dict)
        or not all(isinstance(run.get(k), str) and PRINCIPAL.fullmatch(run[k]) for k in PRINCIPALS)
        or not isinstance(run.get("run_id"), str)
        or not RUN_ID.fullmatch(run["run_id"])
        or not isinstance(run.get("content_hash"), str)
    ):
        raise PipelineDefect("invalid_step_payload")
    return run


PRINCIPALS = ("tenant_id", "user_id")


def _request_as_run(state: dict) -> dict | None:
    """Identity of a run whose Prepare step never produced one (it failed or was rejected)."""
    if not all(isinstance(state.get(k), str) and PRINCIPAL.fullmatch(state[k]) for k in PRINCIPALS):
        return None
    if not isinstance(state.get("run_id"), str) or not RUN_ID.fullmatch(state["run_id"]):
        return None
    generation = state.get("generation", 0)
    return {
        "tenant_id": state["tenant_id"],
        "user_id": state["user_id"],
        "run_id": state["run_id"],
        "generation": generation if isinstance(generation, int) else 0,
        "content_hash": None,
        "scan_id": None,
        "source": {"kind": None, "label": None, "revision": None},
    }


def _artifact(run: dict, name: str, material) -> str:
    return f"run/{run['run_id']}/g{run.get('generation', 0)}/{name}-{digest(material, 16)}"


def _write_once(context: StepContext, tenant: str, key: str, body: dict) -> dict:
    """First writer wins, so a retried step returns exactly what the first attempt stored."""
    if context.state.put_checkpoint(tenant, key, body):
        return body
    existing = context.state.get_checkpoint(tenant, key)
    if existing is None:
        raise TransientStepError("checkpoint_unavailable")
    return existing


def _load(context: StepContext, tenant: str, key) -> dict:
    body = context.state.get_checkpoint(tenant, key) if isinstance(key, str) else None
    if body is None:
        raise PipelineDefect("checkpoint_missing")
    return body


def record_review(context: StepContext, run: dict, *, step: str, error: str, reason: str) -> dict:
    item = {
        "schema_version": "review-item-1",
        "review_id": digest(
            ["review", run["tenant_id"], run["run_id"], run.get("generation", 0), step], 24
        ),
        "tenant_id": run["tenant_id"],
        "run_id": run["run_id"],
        "generation": run.get("generation", 0),
        "scan_id": run.get("scan_id"),
        "content_hash": run.get("content_hash"),
        "step": step,
        "error": error,
        "reason": reason,
        "disposition": disposition(error),
        "status": "open",
        "created_at": int(context.clock()),
    }
    context.state.put_review(item)
    return item


# ---------------------------------------------------------------------------------- prepare
@contextmanager
def _source(request: dict, context: StepContext, scratch: Path) -> Iterator[Ingested]:
    reference = request["source_ref"]
    if reference.startswith("upload:"):
        archive = scratch / "upload.zip"
        if not context.state.fetch_upload(request["tenant_id"], reference[7:], archive):
            raise ScanRejected("upload_not_found")
        with ingest(str(archive), context.settings.limits) as ingested:
            yield Ingested(ingested.root, "upload", reference[7:])
        return
    with ingest(reference, context.settings.limits) as ingested:
        yield ingested


@functools.cache
def _policy_version() -> str:
    return FindingPolicy().version


def pipeline_fingerprint(context: StepContext) -> str:
    return digest(
        {
            "pipeline": PIPELINE_VERSION,
            "detectors": {d.name: d.fingerprint for d in context.selected()},
            "policy": _policy_version(),
            "reasoning": REASONING_VERSIONS,
            "provider": context.provider_identity,
        },
        24,
    )


@step("prepare")
def prepare(event: dict, context: StepContext) -> dict:
    attempt = _attempt(event)
    try:
        request = validate_request(event.get("request"), mode=context.mode)
    except InvalidRequest as error:
        return {"outcome": "rejected", "reason": safe_code(str(error)), "detectors": []}
    context.faults.before("prepare", attempt)
    tenant, now = request["tenant_id"], int(context.clock())
    context.state.update_run(
        tenant,
        request["run_id"],
        {"status": "running", "generation": request["generation"], "updated_at": now},
    )
    with tempfile.TemporaryDirectory(prefix="first-commit-prepare-") as scratch:
        try:
            with _source(request, context, Path(scratch)) as ingested:
                preflight = inspect_tree(ingested.root, context.settings.limits)
                archive = Path(scratch) / "snapshot.zip"
                build_snapshot(ingested.root, preflight, archive)
                source = {"kind": ingested.kind, "label": ingested.label}
                source["revision"] = ingested.revision
        except ScanRejected as error:
            return {"outcome": "rejected", "reason": error.code, "detectors": []}
        except (PreflightError, OSError) as error:
            failure = ingestion_failure(error)
            if isinstance(failure, ScanRejected):
                return {"outcome": "rejected", "reason": failure.code, "detectors": []}
            raise failure from None
        context.state.put_snapshot(tenant, preflight.content_hash, archive)

    content_hash = preflight.content_hash
    scan = start_scan(
        context.store,
        tenant_id=tenant,
        content_hash=content_hash,
        source_ref=request["source_ref"],
        execution_id=request["run_id"],
        now=now,
    ).scan
    detectors = context.selected()
    run = {
        "tenant_id": tenant,
        "user_id": request["user_id"],
        "run_id": request["run_id"],
        "generation": request["generation"],
        "environments": request["environments"],
        "audience": request["audience"],
        "source": source,
        "content_hash": content_hash,
        "scan_id": scan.scan_id,
        "fingerprint": pipeline_fingerprint(context),
    }
    run["reuse_key"] = digest(
        [
            "completed",
            tenant,
            run["user_id"],
            content_hash,
            run["environments"],
            run["audience"],
            run["fingerprint"],
        ]
    )
    changes = {"generation": run["generation"], "scan_id": scan.scan_id}
    context.state.update_run(tenant, run["run_id"], {**changes, "content_hash": content_hash})
    if not request["refresh"]:
        previous = context.state.get_checkpoint(tenant, f"completed/{run['reuse_key']}")
        if previous and isinstance(previous.get("result_ref"), str):
            # Identical content, context and pipeline version: nothing is scanned or explained.
            return {"outcome": "reused", "run": run, "detectors": [], "skipped": []}
    context.store.set_scan_status(tenant, scan.scan_id, ScanStatus.RUNNING, now)
    return {
        "outcome": "planned",
        "run": run,
        "detectors": [{"name": d.name} for d in detectors if d.applies(preflight.files)],
        "skipped": [{"name": d.name} for d in detectors if not d.applies(preflight.files)],
    }


# ----------------------------------------------------------------------------------- detect
@step("detect")
def detect(event: dict, context: StepContext) -> dict:
    run, attempt = _run(event), _attempt(event)
    name = (event.get("detector") or {}).get("name")
    detector = context.detectors.get(name) if isinstance(name, str) else None
    if detector is None:
        raise PipelineDefect("unknown_detector")
    context.faults.before(detector.name, attempt)
    tenant, content_hash = run["tenant_id"], run["content_hash"]
    key = f"detector/{content_hash}/{detector.name}/{detector.fingerprint}"
    body, cached = context.state.get_checkpoint(tenant, key), True
    if body is None:
        cached = False
        with context.workspace.materialize(tenant, content_hash) as (root, files):
            try:
                result = detector.run(root, content_hash, files, context.settings)
            except Exception:
                raise DetectorDefect("crashed") from None
        if result.error:
            failure = detector_failure(result.error)
            # A defect that still produced findings keeps them; anything else is retried or
            # dead-lettered by the state machine without writing a checkpoint.
            if not (result.findings and isinstance(failure, DetectorDefect)):
                raise failure
        body = _write_once(
            context,
            tenant,
            key,
            {
                "detector": detector.name,
                "fingerprint": detector.fingerprint,
                "content_hash": content_hash,
                "findings": [finding.to_dict() for finding in result.findings],
                "error": result.error,
            },
        )
    context.faults.after_write(detector.name, attempt)
    summary = {
        "detector": detector.name,
        "findings": len(body["findings"]),
        "checkpoint": key,
        "cached": cached,
    }
    if body.get("error"):
        item = record_review(
            context, run, step=detector.name, error="DetectorDefect", reason=body["error"]
        )
        return {
            **summary,
            "status": "incomplete",
            "reason": body["error"],
            "disposition": item["disposition"],
            "review_id": item["review_id"],
        }
    return {**summary, "status": "succeeded"}


# --------------------------------------------------------------------------------- incident
@step("incident")
def incident(event: dict, context: StepContext) -> dict:
    if "detector" in event:
        run = _run(event)
        name = (event.get("detector") or {}).get("name")
        if name not in context.detectors:
            raise PipelineDefect("unknown_detector")
        error, reason = reason_from_error(event.get("error"))
        item = record_review(context, run, step=name, error=error, reason=reason)
        return {
            "detector": name,
            "status": "incomplete",
            "reason": reason,
            "error": error,
            "disposition": item["disposition"],
            "review_id": item["review_id"],
        }
    state = event.get("state") if isinstance(event.get("state"), dict) else {}
    failures = state.get("failure") if isinstance(state.get("failure"), dict) else {}
    failed_step, failure = next(iter(failures.items()), ("unknown", None))
    error, reason = reason_from_error(failure)
    run = (state.get("prepare") or {}).get("run") or _request_as_run(state)
    item = (
        record_review(context, run, step=safe_code(failed_step), error=error, reason=reason)
        if run
        else None
    )
    return {
        "step": safe_code(failed_step),
        "reason": reason,
        "error": error,
        "disposition": disposition(error),
        "review_id": item["review_id"] if item else None,
    }


# ------------------------------------------------------------------------------------ merge
@step("merge")
def merge(event: dict, context: StepContext) -> dict:
    run, attempt = _run(event), _attempt(event)
    context.faults.before("merge", attempt)
    tenant = run["tenant_id"]
    planned = [p.get("name") for p in event.get("planned", []) if isinstance(p, dict)]
    skipped = [p.get("name") for p in event.get("skipped", []) if isinstance(p, dict)]
    checks = {c.get("detector"): c for c in event.get("checks", []) if isinstance(c, dict)}
    material = {"planned": planned, "skipped": skipped, "checks": event.get("checks", [])}
    summary_key = _artifact(run, "merge", material)
    existing = context.state.get_checkpoint(tenant, summary_key)
    if existing is not None:
        context.faults.after_write("merge", attempt)
        return existing

    coverage, findings = [], {}
    for name in planned:
        detector = context.detectors.get(name)
        if detector is None:
            raise PipelineDefect("unknown_detector")
        check = checks.get(name)
        entry = {"check": name, "categories": [str(c) for c in detector.categories]}
        body = None
        if check is not None and check.get("checkpoint"):
            body = context.state.get_checkpoint(tenant, check["checkpoint"])
            valid = (
                body is not None
                and body.get("detector") == name
                and body.get("content_hash") == run["content_hash"]
            )
            if not valid:
                body = None
                item = record_review(
                    context, run, step=name, error="PipelineDefect", reason="checkpoint_missing"
                )
                check = {**item, "status": "incomplete", "reason": "checkpoint_missing"}
        if check is None:
            item = record_review(
                context, run, step=name, error="PipelineDefect", reason="missing_result"
            )
            check = {**item, "status": "incomplete", "reason": "missing_result"}
        status = check.get("status") if check.get("status") in {"succeeded", "incomplete"} else None
        entry["status"] = status or "incomplete"
        if body is not None:
            for item in body.get("findings", []):
                findings[item["finding_id"]] = item
            entry.update(findings=len(body.get("findings", [])), cached=bool(check.get("cached")))
        if entry["status"] != "succeeded":
            entry.update(
                reason=safe_code(check.get("reason"), "unexpected_error"),
                disposition=check.get("disposition")
                if check.get("disposition") in DISPOSITION_TEXT
                else "human_review",
                review_id=check.get("review_id"),
            )
        coverage.append(entry)
    for name in skipped:
        detector = context.detectors.get(name)
        if detector is not None:
            coverage.append(
                {
                    "check": name,
                    "status": "not_applicable",
                    "categories": [str(c) for c in detector.categories],
                }
            )

    # A successful resumed check closes only its own older dead-letter records. The records
    # remain stored as an audit trail, but no longer appear as work awaiting a person.
    generation = run.get("generation", 0)
    if generation:
        for check in coverage:
            if check["status"] == "succeeded":
                context.state.resolve_reviews(tenant, run["run_id"], check["check"], generation)

    try:
        parsed = sorted(
            (finding_from_dict(item) for item in findings.values()),
            key=lambda f: (f.location.path, f.location.start_line or 0, f.finding_id),
        )
    except (KeyError, TypeError, ValueError):
        raise PipelineDefect("checkpoint_invalid") from None
    errors = tuple(
        sorted(f"{c['check']}: {c['reason']}" for c in coverage if c["status"] == "incomplete")
    )
    report = ScanReport(
        SCHEMA_VERSION, run["source"]["label"] or "", run["content_hash"], tuple(parsed), errors
    )
    now = int(context.clock())
    try:
        scan_status = record_scan_report(context.store, tenant, run["scan_id"], report, now)
    except ValueError:
        raise PipelineDefect("scan_record_mismatch") from None
    policy = context.policy().evaluate(
        report,
        PolicyContext(
            tenant, run["user_id"], tenant, tuple(run["environments"]), run["content_hash"]
        ),
    )
    if policy["status"] == "error" and attempt == 0:
        raise TransientStepError("policy_unavailable")  # Engine errors are never cached.
    report_ref = _artifact(run, "report", material)
    policy_ref = _artifact(run, "policy", material)
    _write_once(context, tenant, report_ref, report.to_dict())
    _write_once(context, tenant, policy_ref, policy)
    summary = {
        "outcome": "merged",
        "complete": report.complete,
        "scan_status": str(scan_status),
        "report_ref": report_ref,
        "policy_ref": policy_ref,
        "policy_status": policy["status"],
        "coverage": coverage,
        "counts": {
            "findings": len(parsed),
            "by_severity": dict(sorted(Counter(str(f.severity) for f in parsed).items())),
            "decisions": dict(
                sorted(Counter(d["outcome"] for d in policy.get("decisions", [])).items())
            ),
        },
    }
    summary = _write_once(context, tenant, summary_key, summary)
    context.faults.after_write("merge", attempt)
    return summary


# ---------------------------------------------------------------------------------- explain
@step("explain")
def explain(event: dict, context: StepContext) -> dict:
    run, attempt = _run(event), _attempt(event)
    merged = event.get("merge") if isinstance(event.get("merge"), dict) else {}
    context.faults.before("explain", attempt)
    tenant = run["tenant_id"]
    key = _artifact(run, "explanation", [merged.get("report_ref"), merged.get("policy_ref")])
    stored = context.state.get_checkpoint(tenant, key)
    if stored is None:
        try:
            report = report_from_dict(_load(context, tenant, merged.get("report_ref")))
        except (KeyError, TypeError, ValueError):
            raise PipelineDefect("checkpoint_invalid") from None
        policy = _load(context, tenant, merged.get("policy_ref"))
        try:
            provider = context.provider_factory()
            result = ReasoningService(provider, context.explanations, context.reasoning).explain(
                report, policy, ReasoningContext(tenant, run["user_id"], run["audience"])
            )
        except ProviderError as error:
            kind = TransientStepError if error.kind in PROVIDER_TRANSIENT else ToolUnavailable
            raise kind(f"provider_{safe_code(error.kind, 'error')}") from None
        usage = result.get("usage", {})
        if (
            result.get("status") != "complete"
            and usage.get("circuit_open") == "provider_unavailable"
            and attempt == 0
        ):
            # One delayed retry: units already accepted are cached, so it is not re-billed.
            raise TransientStepError("provider_unavailable")
        stored = _write_once(context, tenant, key, result)
    context.faults.after_write("explain", attempt)
    usage = stored.get("usage", {})
    return {
        "status": stored.get("status"),
        "explanation_ref": key,
        "model_calls": usage.get("model_calls", 0),
        "estimated_cost_usd": usage.get("estimated_cost_usd", 0.0),
        "requires_human_review": len(stored.get("summary", {}).get("requires_human_review", [])),
    }


# --------------------------------------------------------------------------------- finalize
def _labels(categories) -> list[str]:
    return [PLAYBOOKS[c].label if c in PLAYBOOKS else c for c in sorted(set(categories))]


def notice(coverage: list[dict], policy_status: str | None) -> str:
    planned = [c for c in coverage if c["status"] != "not_applicable"]
    incomplete = [c for c in planned if c["status"] != "succeeded"]
    skipped = len(coverage) - len(planned)
    text = (
        f"All {len(planned)} applicable checks completed."
        if not incomplete
        else f"{len(planned) - len(incomplete)} of {len(planned)} checks completed. "
        + " ".join(
            f"{c['check']} {DISPOSITION_TEXT.get(c.get('disposition'), 'did not complete')} "
            f"({c.get('reason')})."
            for c in incomplete
        )
        + " The findings shown are real, but these kinds of issue may be missing: "
        + ", ".join(_labels(cat for c in incomplete for cat in c["categories"]))
        + ". Processing stays denied until a complete scan; resume the run once the cause"
        " is fixed."
    )
    if skipped:
        text += f" {skipped} check(s) did not apply to the files in this repository."
    if policy_status == "error":
        text += " Policy decisions were unavailable, so nothing is authorized."
    return text


def _failed(run, *, reason, error, step=None, review_id=None, resumable) -> dict:
    return {
        "status": "failed",
        "reason": reason,
        "error": error,
        "failed_step": step,
        "review_items": [review_id] if review_id else [],
        "resumable": resumable,
        "source": run.get("source") if run else None,
        "content_hash": run.get("content_hash") if run else None,
        "scan_id": run.get("scan_id") if run else None,
        "coverage": None,
        "findings": [],
        "policy": None,
        "explanation": None,
        "usage": {"model_calls": 0, "detectors_run": 0, "detectors_reused": 0},
    }


def _assemble(state: dict, run: dict, context: StepContext) -> dict:
    tenant = run["tenant_id"]
    merged = state["merge"]
    report = _load(context, tenant, merged["report_ref"])
    policy = _load(context, tenant, merged["policy_ref"])
    coverage = merged["coverage"]
    planned = [c for c in coverage if c["status"] != "not_applicable"]
    completed = [c for c in planned if c["status"] == "succeeded"]
    incomplete = [c for c in planned if c["status"] != "succeeded"]
    explained = state.get("explain") if isinstance(state.get("explain"), dict) else {}
    explanation, explanation_status = None, explained.get("status")
    if explained.get("explanation_ref"):
        explanation = context.state.get_checkpoint(tenant, explained["explanation_ref"])
    if explanation is None and report["findings"]:
        # The explain step failed or was skipped: vetted templates, never a model call.
        explanation = ReasoningService(None, context.explanations, context.reasoning).explain(
            report_from_dict(report),
            policy,
            ReasoningContext(tenant, run["user_id"], run["audience"]),
        )
        explanation_status = "template_fallback"
    if planned and not completed:
        status, reason = "failed", "no_checks_completed"
    elif incomplete or policy.get("status") == "error":
        status, reason = "partial", "incomplete_checks" if incomplete else "policy_unavailable"
    else:
        status, reason = "completed", None
    usage = (explanation or {}).get("usage", {})
    return {
        "status": status,
        "reason": reason,
        "error": "ScanFailed" if status == "failed" else None,
        "failed_step": None,
        "review_items": sorted({c["review_id"] for c in incomplete if c.get("review_id")}),
        "resumable": status != "completed",
        "source": run["source"],
        "content_hash": run["content_hash"],
        "scan_id": run["scan_id"],
        "coverage": {
            "complete": not incomplete,
            "planned": len(planned),
            "completed": len(completed),
            "incomplete": [
                {k: c.get(k) for k in ("check", "reason", "disposition", "review_id")}
                for c in incomplete
            ],
            "not_applicable": [c["check"] for c in coverage if c["status"] == "not_applicable"],
            "missing_categories": sorted({cat for c in incomplete for cat in c["categories"]}),
            "checks": coverage,
            "notice": notice(coverage, policy.get("status")),
        },
        "findings": report["findings"],
        "artifacts": {
            "report_ref": merged["report_ref"],
            "policy_ref": merged["policy_ref"],
            "explanation_ref": explained.get("explanation_ref"),
        },
        "policy": {
            key: policy.get(key)
            for key in ("status", "reason", "processing", "policy_version", "decisions")
        },
        "explanation": {"status": explanation_status or "skipped", "report": explanation},
        "usage": {
            "detectors_run": sum(1 for c in completed if not c.get("cached")),
            "detectors_reused": sum(1 for c in completed if c.get("cached")),
            "model_calls": usage.get("model_calls", 0),
            "estimated_model_cost_usd": usage.get("estimated_cost_usd", 0.0),
        },
    }


@step("finalize")
def finalize(event: dict, context: StepContext) -> dict:
    state = event.get("state") if isinstance(event.get("state"), dict) else {}
    attempt = _attempt(event)
    context.faults.before("finalize", attempt)
    prepared = state.get("prepare") if isinstance(state.get("prepare"), dict) else {}
    run = prepared.get("run") or _request_as_run(state)
    if run is None:
        return {"status": "failed", "reason": prepared.get("reason") or "invalid_request"}
    tenant = run["tenant_id"]
    if prepared.get("outcome") == "rejected":
        result = _failed(run, reason=prepared["reason"], error="ScanRejected", resumable=False)
    elif isinstance(state.get("failure"), dict) and state["failure"]:
        incident_result = state.get("incident") if isinstance(state.get("incident"), dict) else {}
        failed_step, failure = next(iter(state["failure"].items()))
        reason = incident_result.get("reason") or reason_from_error(failure)[1]
        result = _failed(
            run,
            reason=reason,
            error="PipelineStepFailed",
            step=safe_code(failed_step),
            review_id=incident_result.get("review_id"),
            resumable=True,
        )
    elif prepared.get("outcome") == "reused":
        pointer = context.state.get_checkpoint(tenant, f"completed/{run['reuse_key']}") or {}
        previous = context.state.get_checkpoint(tenant, pointer.get("result_ref") or "")
        if previous is None:
            result = _failed(
                run, reason="reused_result_missing", error="ScanFailed", resumable=True
            )
        else:
            result = {
                **{k: v for k, v in previous.items() if k not in {"run_id", "generation"}},
                "reused_from": previous.get("run_id"),
                "usage": {
                    "detectors_run": 0,
                    "detectors_reused": 0,
                    "model_calls": 0,
                    "estimated_model_cost_usd": 0.0,
                    "reused_result": True,
                },
            }
    else:
        result = _assemble(state, run, context)

    result = {
        "schema_version": RESULT_SCHEMA,
        "pipeline_version": PIPELINE_VERSION,
        **result,
        "run_id": run["run_id"],
        "generation": run.get("generation", 0),
        "completed_at": int(context.clock()),
    }
    result_ref = _artifact(run, "result", [state.get(k) for k in ("merge", "explain", "failure")])
    result = _write_once(context, tenant, result_ref, result)
    if result["status"] == "completed" and run.get("reuse_key") and not result.get("reused_from"):
        context.state.put_checkpoint(
            tenant,
            f"completed/{run['reuse_key']}",
            {"result_ref": result_ref, "run_id": run["run_id"]},
        )
    coverage = result.get("coverage") or {}
    compact = {
        "status": result["status"],
        "reason": result.get("reason"),
        "error": result.get("error"),
        "failed_step": result.get("failed_step"),
        "run_id": run["run_id"],
        "generation": run.get("generation", 0),
        "scan_id": result.get("scan_id"),
        "result_ref": result_ref,
        "resumable": result.get("resumable", False),
        "coverage": {
            "complete": coverage.get("complete", False),
            "planned": coverage.get("planned", 0),
            "completed": coverage.get("completed", 0),
            "incomplete": [c["check"] for c in coverage.get("incomplete", [])],
            "notice": coverage.get("notice"),
        },
        "counts": {
            "findings": len(result.get("findings", [])),
            "review_items": len(result.get("review_items", [])),
            "model_calls": result.get("usage", {}).get("model_calls", 0),
        },
    }
    context.state.update_run(
        tenant,
        run["run_id"],
        {
            **{k: v for k, v in compact.items() if k not in {"run_id"}},
            "content_hash": result.get("content_hash"),
            "updated_at": int(context.clock()),
        },
    )
    if result["status"] == "failed" and result.get("scan_id"):
        context.store.set_scan_status(
            tenant, result["scan_id"], ScanStatus.FAILED, int(context.clock())
        )
    context.faults.after_write("finalize", attempt)
    return compact


HANDLERS: dict[str, Callable[[dict, StepContext], dict]] = {
    "prepare": prepare,
    "detect": detect,
    "incident": incident,
    "merge": merge,
    "explain": explain,
    "finalize": finalize,
}
