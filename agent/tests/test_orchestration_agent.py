from __future__ import annotations

from agent.orchestration.agent import OrchestratorAgent, OrchestratorGuard, plan_request
from agent.orchestration.pipeline import local_pipeline


def test_planner_maps_clear_requests_without_a_model():
    run_id = "run-" + "a" * 32
    assert plan_request("scan https://github.com/example/repo").tool == "start_scan"
    assert plan_request(f"resume {run_id}").tool == "resume_run"
    assert plan_request(f"why was {run_id} denied?").tool == "ask_about_run"
    assert plan_request("what should I do?", model_available=False).route == "clarify"
    assert plan_request("what should I do?", model_available=True).route == "model"


def test_orchestrator_binds_identity_and_direct_tool_calls_cost_zero(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.txt").write_text("data", encoding="utf-8")
    pipeline = local_pipeline(
        tmp_path / "state", external_detectors=False, provider_factory=lambda: None
    )
    agent = OrchestratorAgent(
        pipeline,
        tenant="tenant-a",
        user="user-a",
        explanations=pipeline.context.explanations,
    )

    reply = agent.handle(f"scan {source}")
    assert reply["route"] == "planner"
    assert reply["tool_calls"] == ["start_scan"]
    assert reply["model_calls"] == 0
    run_id = reply["result"]["run_id"]
    assert pipeline.status("tenant-a", run_id) is not None
    assert pipeline.status("tenant-b", run_id) is None


def test_guard_hard_caps_model_calls_and_state_changes():
    guard = OrchestratorGuard()

    class Event:
        cancel = None

    first_model, second_model = Event(), Event()
    guard.before_model(first_model)
    guard.before_model(second_model)
    assert first_model.cancel is None
    assert second_model.cancel == "model call budget exhausted"

    class ToolEvent:
        def __init__(self, name, payload):
            self.tool_use = {"name": name, "input": payload}
            self.cancel_tool = None

    first = ToolEvent("start_scan", {"source": "one"})
    duplicate = ToolEvent("start_scan", {"source": "one"})
    second_mutation = ToolEvent("resume_run", {"run_id": "run-" + "a" * 32})
    guard.before_tool(first)
    guard.before_tool(duplicate)
    guard.before_tool(second_mutation)
    assert first.cancel_tool is None
    assert duplicate.cancel_tool == "duplicate_call"
    assert second_mutation.cancel_tool == "one_state_change_per_request"
