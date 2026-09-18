"""Run request contract, identifiers and stable digests shared by every pipeline entry point."""

from __future__ import annotations

import hashlib
import json
import re
import uuid

from agent.reasoning.knowledge import AUDIENCES

PIPELINE_VERSION = "pipeline-1"
RUN_SCHEMA = "pipeline-run-1"
RESULT_SCHEMA = "pipeline-result-1"
ENVIRONMENTS = ("development", "staging", "production")
RUN_ID = re.compile(r"run-[0-9a-f]{32}")
PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@:+-]{0,127}")
UPLOAD_KEY = re.compile(r"upload:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.zip")
MAX_GENERATIONS = 5  # Resumes per run; each one is operator-visible and bounded.


class InvalidRequest(ValueError):
    """A request that never becomes a run. The message is a safe reason code."""


def stable(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value, length: int = 32) -> str:
    return hashlib.sha256(stable(value).encode()).hexdigest()[:length]


def tenant_key(tenant: str) -> str:
    """Storage path segment. Raw tenant identifiers never become object keys."""
    return hashlib.sha256(f"tenant\0{tenant}".encode()).hexdigest()[:32]


def new_run_id(tenant: str, idempotency_key: str | None = None) -> str:
    if idempotency_key is None:
        return f"run-{uuid.uuid4().hex}"
    if not 8 <= len(idempotency_key) <= 128 or not idempotency_key.isprintable():
        raise InvalidRequest("invalid_idempotency_key")
    # The same client key within a tenant always names the same run: retries cannot fork it.
    return f"run-{digest(['idempotency', tenant, idempotency_key])}"


def execution_name(run_id: str, generation: int) -> str:
    return run_id if generation == 0 else f"{run_id}-g{generation}"


def validate_request(request: dict, *, mode: str) -> dict:
    """Normalize a run request. Raises InvalidRequest with a code; never echoes input."""
    if not isinstance(request, dict):
        raise InvalidRequest("invalid_request")
    tenant, user = request.get("tenant_id"), request.get("user_id")
    if not all(isinstance(v, str) and PRINCIPAL.fullmatch(v) for v in (tenant, user)):
        raise InvalidRequest("invalid_principal")
    run_id = request.get("run_id")
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise InvalidRequest("invalid_run_id")
    source = request.get("source_ref")
    if not isinstance(source, str) or not 1 <= len(source) <= 2048 or not source.isprintable():
        raise InvalidRequest("invalid_source_ref")
    if mode == "aws" and not (source.startswith("https://") or UPLOAD_KEY.fullmatch(source)):
        # A hosted worker must never read its own file system on a tenant's behalf.
        raise InvalidRequest("unsupported_source_ref")
    environments = request.get("environments", [])
    if (
        not isinstance(environments, list)
        or len(environments) > len(ENVIRONMENTS)
        or not set(environments) <= set(ENVIRONMENTS)
    ):
        raise InvalidRequest("invalid_environments")
    audience = request.get("audience", "beginner")
    if audience not in AUDIENCES:
        raise InvalidRequest("invalid_audience")
    generation = request.get("generation", 0)
    if not isinstance(generation, int) or not 0 <= generation <= MAX_GENERATIONS:
        raise InvalidRequest("invalid_generation")
    return {
        "tenant_id": tenant,
        "user_id": user,
        "run_id": run_id,
        "source_ref": source,
        "environments": sorted(set(environments)),
        "audience": audience,
        "generation": generation,
        "refresh": request.get("refresh") is True,
    }
