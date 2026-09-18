"""Pipeline entry points: submit, resume, status and results, locally or on Step Functions.

Local mode executes the deployed state-machine definition in-process (agent/orchestration/asl.py)
against the same step functions the Lambda tasks call. AWS mode starts a Standard workflow whose
execution name is the run ID, so a retried submit can never start a second execution.
"""

from __future__ import annotations

import json
import os
import random
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from agent.config import Settings
from agent.detectors import DETECTORS
from agent.orchestration.asl import Execution, StateMachine
from agent.orchestration.contracts import (
    MAX_GENERATIONS,
    RUN_SCHEMA,
    InvalidRequest,
    execution_name,
    validate_request,
)
from agent.orchestration.faults import FaultPlan
from agent.orchestration.snapshots import SnapshotWorkspace
from agent.orchestration.state import FINAL, PipelineState
from agent.orchestration.steps import HANDLERS, StepContext
from agent.reasoning.cache import ExplanationCache
from agent.store import ScanStore

DEFINITION = Path(__file__).with_name("scan-pipeline.asl.json")
RESOURCES = {
    "PrepareFunctionArn": "prepare",
    "DetectFunctionArn": "detect",
    "IncidentFunctionArn": "incident",
    "MergeFunctionArn": "merge",
    "ExplainFunctionArn": "explain",
    "FinalizeFunctionArn": "finalize",
}
STEP_NAMES = ("prepare", *DETECTORS, "merge", "explain", "finalize")


def load_definition() -> dict:
    return json.loads(DEFINITION.read_text(encoding="utf-8"))


def new_run(request: dict, now: int) -> dict:
    return {
        "schema_version": RUN_SCHEMA,
        "tenant_id": request["tenant_id"],
        "user_id": request["user_id"],
        "run_id": request["run_id"],
        "request": {
            "source_ref": request["source_ref"],
            "environments": request["environments"],
            "audience": request["audience"],
        },
        "status": "queued",
        "reason": None,
        "generation": 0,
        "version": 0,
        "created_at": now,
        "updated_at": now,
    }


def provider_identity() -> str:
    names = (
        "FIRST_COMMIT_MODEL_PROVIDER",
        "FIRST_COMMIT_SMALL_MODEL",
        "FIRST_COMMIT_LARGE_MODEL",
        "FIRST_COMMIT_OLLAMA_PROFILE",
    )
    return "|".join(os.getenv(name, "") for name in names)


def step_context(
    *,
    mode: str,
    state: PipelineState,
    store: ScanStore,
    explanations: ExplanationCache,
    workspace_root: Path,
    settings: Settings | None = None,
    faults: FaultPlan | None = None,
    provider_factory: Callable[[], object] | None = None,
    **options,
) -> StepContext:
    settings = settings or Settings.from_env()
    if provider_factory is None:
        from agent.reasoning.providers import build_provider

        provider_factory = build_provider
        options.setdefault("provider_identity", provider_identity())
    return StepContext(
        mode=mode,
        state=state,
        store=store,
        explanations=explanations,
        settings=settings,
        workspace=SnapshotWorkspace(workspace_root, state, settings.limits),
        faults=faults or FaultPlan(),
        provider_factory=provider_factory,
        **options,
    )


def resume_request(run: dict) -> dict:
    if run["status"] not in {"partial", "failed"} or not run.get("resumable"):
        raise InvalidRequest("run_not_resumable")
    generation = run.get("generation", 0) + 1
    if generation > MAX_GENERATIONS:
        raise InvalidRequest("resume_limit_reached")
    return {
        "tenant_id": run["tenant_id"],
        "user_id": run["user_id"],
        "run_id": run["run_id"],
        **run["request"],
        "generation": generation,
    }


class LocalPipeline:
    def __init__(
        self,
        context: StepContext,
        *,
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
    ):
        self.context = context
        resources = {
            placeholder: (lambda payload, handler=HANDLERS[name]: handler(payload, context))
            for placeholder, name in RESOURCES.items()
        }
        self.machine = StateMachine(load_definition(), resources, sleep=sleep, random=rng)
        self.last_execution: Execution | None = None

    @property
    def state(self) -> PipelineState:
        return self.context.state

    def submit(self, request: dict) -> dict:
        request = validate_request(request, mode=self.context.mode)
        state, now = self.context.state, int(self.context.clock())
        if not state.create_run(new_run(request, now)):
            existing = state.get_run(request["tenant_id"], request["run_id"])
            if existing and existing["status"] in FINAL:
                return existing  # An idempotent replay returns the recorded outcome.
        return self._execute(request)

    def resume(self, tenant: str, run_id: str) -> dict:
        run = self.status(tenant, run_id)
        if run is None:
            raise InvalidRequest("run_not_found")
        request = resume_request(run)
        updated = self.context.state.update_run(
            tenant, run_id, {"generation": request["generation"], "status": "queued"}
        )
        if updated is None:
            raise InvalidRequest("run_not_resumable")
        return self._execute(request)

    def _execute(self, request: dict) -> dict:
        name = execution_name(request["run_id"], request["generation"])
        self.last_execution = self.machine.execute(request, name=name)
        run = self.context.state.get_run(request["tenant_id"], request["run_id"])
        if self.last_execution.error == "FinalizeFailed" and run and run["status"] not in FINAL:
            # Mirrors the AWS execution-status rule: an execution never leaves a run "running".
            run = self.context.state.update_run(
                request["tenant_id"],
                request["run_id"],
                {"status": "failed", "reason": "finalize_failed", "resumable": True},
            )
        return run

    def status(self, tenant: str, run_id: str) -> dict | None:
        return self.context.state.get_run(tenant, run_id)

    def result(self, tenant: str, run_id: str) -> dict | None:
        run = self.status(tenant, run_id)
        if not run or not run.get("result_ref"):
            return None
        return self.context.state.get_checkpoint(tenant, run["result_ref"])

    def reviews(self, tenant: str, run_id: str | None = None) -> list[dict]:
        return [
            item
            for item in self.context.state.list_reviews(tenant, run_id)
            if item.get("status") == "open"
        ]


class StepFunctionsPipeline:
    """Starts and resumes executions; the steps themselves run in Lambda."""

    def __init__(self, state: PipelineState, state_machine_arn: str, client=None, clock=time.time):
        if client is None:
            import boto3

            client = boto3.client("stepfunctions")
        self.state, self.arn, self.client, self.clock = state, state_machine_arn, client, clock

    def _start(self, request: dict) -> None:
        name = execution_name(request["run_id"], request["generation"])
        try:
            self.client.start_execution(
                stateMachineArn=self.arn, name=name, input=json.dumps(request, sort_keys=True)
            )
        except Exception as error:
            if type(error).__name__ == "ExecutionAlreadyExists" or (
                getattr(error, "response", {}).get("Error", {}).get("Code")
                == "ExecutionAlreadyExists"
            ):
                return  # Same name, same run: the earlier start already owns it.
            self.state.update_run(
                request["tenant_id"],
                request["run_id"],
                {
                    "status": "failed",
                    "reason": "workflow_start_failed",
                    "resumable": True,
                    "generation": request["generation"],
                },
            )
            raise

    def submit(self, request: dict) -> dict:
        request = validate_request(request, mode="aws")
        created = self.state.create_run(new_run(request, int(self.clock())))
        run = self.state.get_run(request["tenant_id"], request["run_id"])
        if created or (run and run["status"] == "queued"):
            self._start(request)
        return self.state.get_run(request["tenant_id"], request["run_id"])

    def resume(self, tenant: str, run_id: str) -> dict:
        run = self.state.get_run(tenant, run_id)
        if run is None:
            raise InvalidRequest("run_not_found")
        request = resume_request(run)
        if self.state.update_run(
            tenant, run_id, {"generation": request["generation"], "status": "queued"}
        ):
            self._start(request)
        return self.state.get_run(tenant, run_id)

    def status(self, tenant: str, run_id: str) -> dict | None:
        return self.state.get_run(tenant, run_id)

    def result(self, tenant: str, run_id: str) -> dict | None:
        run = self.status(tenant, run_id)
        if not run or not run.get("result_ref"):
            return None
        return self.state.get_checkpoint(tenant, run["result_ref"])

    def reviews(self, tenant: str, run_id: str | None = None) -> list[dict]:
        return [
            item for item in self.state.list_reviews(tenant, run_id) if item.get("status") == "open"
        ]


def local_pipeline(
    root: Path = Path(".first-commit-cache"),
    *,
    faults: FaultPlan | None = None,
    external_detectors: bool = True,
    settings: Settings | None = None,
    provider_factory: Callable[[], object] | None = None,
    **options,
) -> LocalPipeline:
    from agent.orchestration.state import LocalPipelineState
    from agent.reasoning.cache import SqliteExplanationCache
    from agent.store import LocalScanStore

    state_file = root / "state.sqlite3"
    context = step_context(
        mode="local",
        state=LocalPipelineState(root / "pipeline"),
        store=LocalScanStore(state_file),
        explanations=SqliteExplanationCache(state_file),
        workspace_root=root / "pipeline" / "workspace",
        settings=settings,
        faults=faults,
        provider_factory=provider_factory,
        external_detectors=external_detectors,
        **options,
    )
    return LocalPipeline(context)


def with_faults(pipeline: LocalPipeline, faults: FaultPlan) -> LocalPipeline:
    return LocalPipeline(replace(pipeline.context, faults=faults))
