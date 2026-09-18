"""AWS Lambda-compatible handlers. No scanner executes in the HTTP request."""

from __future__ import annotations

import hashlib
import json
import os
import uuid

from agent.adapters import load_adapters
from agent.workflow import start_scan


def _response(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _tenant(event):
    claims = event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {})
    return claims.get("sub") or event.get("headers", {}).get("x-first-commit-tenant")


def start_scan_handler(event, context):
    try:
        tenant = _tenant(event)
        body = json.loads(event.get("body") or "{}")
        source_ref = body["source_ref"]
        content_hash = body.get("content_hash")
        if not content_hash:
            # This is an ingestion request fingerprint; the worker hashes content.
            content_hash = hashlib.sha256(source_ref.encode()).hexdigest()
        if os.getenv("FIRST_COMMIT_MODE") == "aws":
            import boto3

            execution = boto3.client("stepfunctions").start_execution(
                stateMachineArn=os.environ["FIRST_COMMIT_WORKFLOW_ARN"],
                name=f"scan-{uuid.uuid4().hex}",
                input=json.dumps(
                    {"tenant_id": tenant, "content_hash": content_hash, "source_ref": source_ref}
                ),
            )
            execution_id = execution["executionArn"]
        else:
            execution_id = f"local-{uuid.uuid4()}"
        result = start_scan(
            load_adapters().store,
            tenant_id=tenant,
            content_hash=content_hash,
            source_ref=source_ref,
            execution_id=execution_id,
        )
        return _response(
            202,
            {
                "scan_id": result.scan.scan_id,
                "execution_id": execution_id,
                "status": result.scan.status,
                "created": result.created,
            },
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return _response(400, {"error": "invalid_scan_request"})


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


def router_handler(event, context):
    request = event.get("requestContext", {}).get("http", {})
    if request.get("method") == "POST" and request.get("path") == "/scans":
        return start_scan_handler(event, context)
    if request.get("method") == "GET" and request.get("path", "").startswith("/scans/"):
        return scan_status_handler(event, context)
    return _response(404, {"error": "route_not_found"})


def scan_worker_handler(event, context):
    """Phase 6 will invoke scanners; Foundation establishes a safe async contract."""
    return {"status": "not_implemented", "execution_id": event.get("execution_id")}


def explain_worker_handler(event, context):
    return {"status": "not_implemented", "execution_id": event.get("execution_id")}


def deploy_worker_handler(event, context):
    return {"status": "not_implemented", "execution_id": event.get("execution_id")}
