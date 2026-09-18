"""AWS Lambda-compatible handlers. No scanner executes in the HTTP request."""

from __future__ import annotations

import json
import os
import re

from agent.adapters import load_adapters


def _response(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _claims(event):
    return event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {})


def _hosted():
    return os.getenv("FIRST_COMMIT_MODE") == "aws"


def _tenant(event):
    # Hosted identity comes only from the verified JWT; the header exists for local development.
    if _hosted():
        return _claims(event).get("sub")
    return _claims(event).get("sub") or (event.get("headers") or {}).get("x-first-commit-tenant")


def _user(event):
    if _hosted():
        return _claims(event).get("sub")
    headers = event.get("headers") or {}
    return _claims(event).get("sub") or headers.get("x-first-commit-user") or _tenant(event)


def _pipeline():
    from agent.orchestration.pipeline import LocalPipeline, StepFunctionsPipeline

    if _hosted():
        return StepFunctionsPipeline(
            load_adapters("aws").pipeline, os.environ["FIRST_COMMIT_WORKFLOW_ARN"]
        )
    # Local development runs the same state machine inline; hosted mode never blocks on it.
    return LocalPipeline(_step_context())


def start_scan_handler(event, context):
    from agent.orchestration.contracts import InvalidRequest, new_run_id

    try:
        tenant = _tenant(event)
        body = json.loads(event.get("body") or "{}")
        if not isinstance(body, dict) or not isinstance(tenant, str):
            raise InvalidRequest("invalid_scan_request")
        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        run = _pipeline().submit(
            {
                "tenant_id": tenant,
                "user_id": _user(event),
                "run_id": new_run_id(tenant, headers.get("idempotency-key")),
                "source_ref": body.get("source_ref"),
                "environments": body.get("environments", []),
                "audience": body.get("audience", "beginner"),
            }
        )
        return _response(202, _run_view(run))
    except InvalidRequest as error:
        return _response(400, {"error": str(error)})
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return _response(400, {"error": "invalid_scan_request"})


def _run_view(run):
    keys = (
        "run_id",
        "status",
        "reason",
        "generation",
        "scan_id",
        "coverage",
        "counts",
        "resumable",
        "created_at",
        "updated_at",
    )
    return {key: run.get(key) for key in keys}


def run_status_handler(event, context):
    from agent.orchestration.contracts import RUN_ID

    run_id = (event.get("pathParameters") or {}).get("run_id", "")
    if not RUN_ID.fullmatch(run_id or ""):
        return _response(400, {"error": "invalid_run_id"})
    run = _pipeline().status(_tenant(event), run_id)
    return _response(200, _run_view(run)) if run else _response(404, {"error": "run_not_found"})


def resume_run_handler(event, context):
    from agent.orchestration.contracts import RUN_ID, InvalidRequest

    run_id = (event.get("pathParameters") or {}).get("run_id", "")
    if not RUN_ID.fullmatch(run_id or ""):
        return _response(400, {"error": "invalid_run_id"})
    try:
        return _response(202, _run_view(_pipeline().resume(_tenant(event), run_id)))
    except InvalidRequest as error:
        code = str(error)
        return _response(404 if code == "run_not_found" else 409, {"error": code})


def review_items_handler(event, context):
    from agent.orchestration.contracts import RUN_ID

    run_id = (event.get("pathParameters") or {}).get("run_id", "")
    if not RUN_ID.fullmatch(run_id or ""):
        return _response(400, {"error": "invalid_run_id"})
    items = [
        item
        for item in load_adapters().pipeline.list_reviews(_tenant(event), run_id)
        if item.get("status") == "open"
    ]
    return _response(200, {"run_id": run_id, "items": items})


def scan_status_handler(event, context):
    try:
        tenant = _tenant(event)
        scan_id = event["pathParameters"]["scan_id"]
        scan = load_adapters().store.get_scan(tenant, scan_id)
        return (
            _response(200, scan.to_dict()) if scan else _response(404, {"error": "scan_not_found"})
        )
    except (KeyError, TypeError, ValueError):
        return _response(400, {"error": "invalid_scan_request"})


ROUTES = (
    ("POST", re.compile(r"/scans"), start_scan_handler),
    ("GET", re.compile(r"/scans/[^/]+"), scan_status_handler),
    ("GET", re.compile(r"/runs/[^/]+"), run_status_handler),
    ("POST", re.compile(r"/runs/[^/]+/resume"), resume_run_handler),
    ("GET", re.compile(r"/runs/[^/]+/review-items"), review_items_handler),
)


def router_handler(event, context):
    request = event.get("requestContext", {}).get("http", {})
    if not _tenant(event):
        return _response(401, {"error": "unauthenticated"})
    for method, path, handler in ROUTES:
        if request.get("method") == method and path.fullmatch(request.get("path", "")):
            return handler(event, context)
    return _response(404, {"error": "route_not_found"})


# ----------------------------------------------------------------- Step Functions task handlers
_CONTEXT = None


def _step_context():
    """One context per Lambda container (or local process): clients and caches are reused."""
    global _CONTEXT
    if _CONTEXT is None:
        from agent.orchestration.faults import FaultPlan
        from agent.orchestration.pipeline import STEP_NAMES, step_context

        adapters = load_adapters()
        _CONTEXT = step_context(
            mode=adapters.mode,
            state=adapters.pipeline,
            store=adapters.store,
            explanations=adapters.explanations,
            workspace_root=adapters.workspace,
            faults=FaultPlan.from_environment(STEP_NAMES),
            external_detectors=os.getenv("FIRST_COMMIT_EXTERNAL_DETECTORS", "on") != "off",
        )
    return _CONTEXT


def _task(step):
    def handler(event, context):
        from agent.orchestration.steps import HANDLERS

        return HANDLERS[step](event, _step_context())

    handler.__name__ = f"pipeline_{step}_handler"
    return handler


pipeline_prepare_handler = _task("prepare")
pipeline_detect_handler = _task("detect")
pipeline_incident_handler = _task("incident")
pipeline_merge_handler = _task("merge")
pipeline_explain_handler = _task("explain")
pipeline_finalize_handler = _task("finalize")


def execution_status_handler(event, context):
    """EventBridge: an execution that ended abnormally never leaves its run marked running."""
    from agent.orchestration.contracts import RUN_ID
    from agent.orchestration.state import FINAL

    detail = event.get("detail") or {}
    status = detail.get("status")
    if status not in {"FAILED", "TIMED_OUT", "ABORTED"}:
        return {"updated": False}
    encoded = detail.get("input")
    if not isinstance(encoded, str) or (detail.get("inputDetails") or {}).get("included") is False:
        execution_arn = detail.get("executionArn")
        if not isinstance(execution_arn, str) or not execution_arn.startswith("arn:"):
            return {"updated": False}
        # EventBridge can omit large inputs. Standard workflows retain the complete request.
        import boto3

        encoded = (
            boto3.client("stepfunctions")
            .describe_execution(executionArn=execution_arn)
            .get("input")
        )
    try:
        request = json.loads(encoded or "{}")
    except ValueError:
        return {"updated": False}
    tenant, run_id = request.get("tenant_id"), request.get("run_id")
    if not isinstance(tenant, str) or not RUN_ID.fullmatch(str(run_id)):
        return {"updated": False}
    state = load_adapters().pipeline
    run = state.get_run(tenant, run_id)
    if (
        not run
        or run["status"] in FINAL
        or run.get("generation", 0) != request.get("generation", 0)
    ):
        return {"updated": False}
    updated = state.update_run(
        tenant,
        run_id,
        {
            "status": "failed",
            "reason": f"execution_{status.lower()}",
            "resumable": True,
            "generation": run.get("generation", 0),
        },
    )
    return {"updated": updated is not None}


def explain_worker_handler(event, context):
    """Explain a policy-evaluated scan with the configured model provider (Phase 5)."""
    from agent.cache import report_from_dict
    from agent.reasoning import ReasoningContext, ReasoningService
    from agent.reasoning.providers import ProviderError, build_provider

    execution_id = event.get("execution_id") if isinstance(event, dict) else None
    try:
        if len(json.dumps(event)) > 1024 * 1024:
            raise ValueError("explain request exceeds 1 MiB")
        service = ReasoningService(build_provider(), load_adapters().explanations)
        result = service.explain(
            report_from_dict(event["report"]),
            event["policy"],
            ReasoningContext(
                event["tenant_id"], event["user_id"], event.get("audience", "beginner")
            ),
        )
        return {"status": result["status"], "execution_id": execution_id, "report": result}
    except ProviderError as error:
        return {"status": "error", "reason": f"provider_{error.kind}", "execution_id": execution_id}
    except (KeyError, TypeError, ValueError):
        return {
            "status": "error",
            "reason": "invalid_explain_request",
            "execution_id": execution_id,
        }


def deploy_worker_handler(event, context):
    return {"status": "not_implemented", "execution_id": event.get("execution_id")}
