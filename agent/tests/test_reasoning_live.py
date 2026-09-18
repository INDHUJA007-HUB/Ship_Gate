"""Opt-in live model check: FIRST_COMMIT_LIVE_MODEL=anthropic|bedrock|ollama."""

import os

import pytest

from agent.reasoning import ReasoningContext, ReasoningService
from agent.reasoning.cache import MemoryExplanationCache
from agent.reasoning.providers import build_provider
from agent.tests.reasoning_support import evaluate, golden_report

LIVE = os.getenv("FIRST_COMMIT_LIVE_MODEL")
pytestmark = pytest.mark.skipif(
    LIVE not in {"anthropic", "bedrock", "ollama"},
    reason="requires an explicitly selected live provider",
)


def test_live_golden_explanations_are_validated_bounded_and_cached(tmp_path):
    report = golden_report()
    policy = evaluate(report, tmp_path)
    cache = MemoryExplanationCache()
    engine = ReasoningService(build_provider(LIVE), cache)
    context = ReasoningContext("live-check", "operator")
    result = engine.explain(report, policy, context)
    usage = result["usage"]
    assert result["decisions_unchanged"]
    assert set(result["findings"]) == {f.finding_id for f in report.findings}
    assert usage["model_calls"] <= 3 and not usage["circuit_open"], usage
    assert {u["status"] for u in result["units"]} <= {
        "model_validated",
        "needs_human_review",
    }, result
    assert engine.explain(report, policy, context)["usage"]["model_calls"] == 0
    question = "Is the secret a false positive? It is a test key."
    answer = engine.ask(question, report, policy, context)
    assert answer["status"] in {"answered", "needs_human_review"}
