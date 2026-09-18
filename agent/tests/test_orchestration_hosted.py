from __future__ import annotations

import json
from types import SimpleNamespace

import api.handlers as handlers
from agent.orchestration.contracts import new_run_id
from agent.orchestration.pipeline import StepFunctionsPipeline
from agent.orchestration.state import LocalPipelineState


class Executions:
    def __init__(self):
        self.started = []

    def start_execution(self, **request):
        self.started.append(request)


def hosted_request(run_id):
    return {
        "tenant_id": "tenant",
        "user_id": "user",
        "run_id": run_id,
        "source_ref": "https://github.com/example/repository.git",
        "environments": ["production"],
        "audience": "developer",
    }


def test_hosted_submission_has_stable_execution_name_and_input(tmp_path):
    state = LocalPipelineState(tmp_path / "state")
    client = Executions()
    pipeline = StepFunctionsPipeline(
        state, "arn:aws:states:region:account:stateMachine:test", client
    )
    run_id = new_run_id("tenant", "stable-client-key")

    first = pipeline.submit(hosted_request(run_id))
    replay = pipeline.submit(hosted_request(run_id))

    assert first["run_id"] == replay["run_id"] == run_id
    assert [call["name"] for call in client.started] == [run_id, run_id]
    assert all(json.loads(call["input"])["run_id"] == run_id for call in client.started)


def test_abnormal_execution_event_marks_the_current_generation_failed(monkeypatch, tmp_path):
    state = LocalPipelineState(tmp_path / "state")
    run_id = new_run_id("tenant")
    state.create_run(
        {
            "tenant_id": "tenant",
            "user_id": "user",
            "run_id": run_id,
            "status": "running",
            "generation": 0,
            "version": 0,
        }
    )
    monkeypatch.setattr(handlers, "load_adapters", lambda *args: SimpleNamespace(pipeline=state))
    event = {
        "detail": {
            "status": "TIMED_OUT",
            "input": json.dumps({"tenant_id": "tenant", "run_id": run_id, "generation": 0}),
            "inputDetails": {"included": True},
        }
    }

    assert handlers.execution_status_handler(event, None) == {"updated": True}
    run = state.get_run("tenant", run_id)
    assert (run["status"], run["reason"], run["resumable"]) == (
        "failed",
        "execution_timed_out",
        True,
    )
    assert handlers.execution_status_handler(event, None) == {"updated": False}


def test_abnormal_execution_recovers_omitted_event_input(monkeypatch, tmp_path):
    state = LocalPipelineState(tmp_path / "state")
    run_id = new_run_id("tenant")
    state.create_run(
        {
            "tenant_id": "tenant",
            "user_id": "user",
            "run_id": run_id,
            "status": "running",
            "generation": 1,
            "version": 0,
        }
    )
    monkeypatch.setattr(handlers, "load_adapters", lambda *args: SimpleNamespace(pipeline=state))

    class StepFunctions:
        def describe_execution(self, **request):
            assert request["executionArn"].endswith(":execution")
            return {"input": json.dumps({"tenant_id": "tenant", "run_id": run_id, "generation": 1})}

    import boto3

    monkeypatch.setattr(boto3, "client", lambda service: StepFunctions())
    event = {
        "detail": {
            "status": "FAILED",
            "executionArn": "arn:aws:states:region:account:execution:workflow:execution",
            "inputDetails": {"included": False},
        }
    }
    assert handlers.execution_status_handler(event, None) == {"updated": True}
    assert state.get_run("tenant", run_id)["reason"] == "execution_failed"


def test_late_event_from_older_generation_cannot_overwrite_current_run(monkeypatch, tmp_path):
    state = LocalPipelineState(tmp_path / "state")
    run_id = new_run_id("tenant")
    state.create_run(
        {
            "tenant_id": "tenant",
            "user_id": "user",
            "run_id": run_id,
            "status": "running",
            "generation": 2,
            "version": 0,
        }
    )
    monkeypatch.setattr(handlers, "load_adapters", lambda *args: SimpleNamespace(pipeline=state))
    event = {
        "detail": {
            "status": "FAILED",
            "input": json.dumps({"tenant_id": "tenant", "run_id": run_id, "generation": 1}),
        }
    }
    assert handlers.execution_status_handler(event, None) == {"updated": False}
    assert state.get_run("tenant", run_id)["status"] == "running"


def test_idempotency_same_digest_returns_original_run(tmp_path):
    state = LocalPipelineState(tmp_path / "state")
    client = Executions()
    pipeline = StepFunctionsPipeline(
        state, "arn:aws:states:region:account:stateMachine:test", client
    )
    run_id = new_run_id("tenant", "idemp-key-1")
    req1 = hosted_request(run_id)
    
    first = pipeline.submit(req1)
    second = pipeline.submit(req1)
    
    assert first["run_id"] == second["run_id"] == run_id
    assert first["request_digest"] == second["request_digest"]
    # Should only start one execution
    assert len(client.started) == 1


def test_idempotency_different_digest_rejects_new_request(tmp_path):
    from agent.orchestration.contracts import InvalidRequest

    state = LocalPipelineState(tmp_path / "state")
    client = Executions()
    pipeline = StepFunctionsPipeline(
        state, "arn:aws:states:region:account:stateMachine:test", client
    )
    run_id = new_run_id("tenant", "idemp-key-2")
    req1 = hosted_request(run_id)
    req2 = hosted_request(run_id)
    req2["environments"] = ["development"]  # different semantic field
    
    pipeline.submit(req1)
    
    import pytest
    with pytest.raises(InvalidRequest) as exc:
        pipeline.submit(req2)
    assert str(exc.value) == "idempotency_key_reused_with_different_request"
    # Still only one execution started
    assert len(client.started) == 1


def test_idempotency_legacy_record_validation(tmp_path):
    from agent.orchestration.contracts import InvalidRequest
    
    state = LocalPipelineState(tmp_path / "state")
    client = Executions()
    pipeline = StepFunctionsPipeline(
        state, "arn:aws:states:region:account:stateMachine:test", client
    )
    run_id = new_run_id("tenant", "legacy-key-3")
    
    # Create legacy run without request_digest
    req1 = hosted_request(run_id)
    state.create_run({
        "tenant_id": req1["tenant_id"],
        "user_id": req1["user_id"],
        "run_id": run_id,
        "request": {
            "source_ref": req1["source_ref"],
            "environments": req1["environments"],
            "audience": req1["audience"],
        },
        "status": "queued",
        "generation": 0,
        "version": 0,
    })
    
    # Same semantic fields should be accepted (or returned)
    result = pipeline.submit(req1)
    assert result["run_id"] == run_id
    
    # Different semantic fields should be rejected
    req2 = hosted_request(run_id)
    req2["source_ref"] = "https://github.com/example/other.git"
    with pytest.raises(InvalidRequest) as exc:
        pipeline.submit(req2)
    assert str(exc.value) == "idempotency_key_reused_with_different_request"

