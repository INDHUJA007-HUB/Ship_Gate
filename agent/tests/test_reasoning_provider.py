"""The Anthropic provider exercised through the real SDK over a mock HTTP transport (no network)."""

import json
from types import SimpleNamespace

import pytest

from agent.reasoning import ReasoningContext, ReasoningService
from agent.reasoning.cache import MemoryExplanationCache
from agent.reasoning.providers import (
    BEDROCK_REFUSAL_FALLBACK,
    AnthropicProvider,
    ModelRequest,
    ProviderError,
    build_provider,
)
from agent.reasoning.routing import Tier
from agent.reasoning.schemas import EXPLAIN_TOOL
from agent.tests.reasoning_support import GroundedModel, evaluate, golden_report

anthropic = pytest.importorskip("anthropic")
httpx2 = pytest.importorskip("httpx2")


def message(content, stop="tool_use", model="claude-opus-5", **extra):
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": {
            "input_tokens": 900,
            "output_tokens": 300,
            "cache_read_input_tokens": 700,
            "cache_creation_input_tokens": 0,
        },
        **extra,
    }


class Recorder:
    def __init__(self, respond):
        self.respond = respond
        self.requests = []

    def __call__(self, request):
        body = json.loads(request.content)
        self.requests.append(
            SimpleNamespace(url=str(request.url), headers=request.headers, body=body)
        )
        status, payload = self.respond(body)
        return httpx2.Response(status, json=payload, headers={"request-id": "req_test"})


def client(platform, recorder):
    http = anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(recorder))
    if platform == "anthropic":
        return anthropic.Anthropic(api_key="test-key", max_retries=0, http_client=http)
    return anthropic.AnthropicBedrockMantle(
        aws_region="us-east-1",
        aws_access_key="AKIDTESTONLY",
        aws_secret_key="test-secret",
        max_retries=0,
        http_client=http,
        middleware=[anthropic.BetaRefusalFallbackMiddleware([{"model": BEDROCK_REFUSAL_FALLBACK}])],
    )


def request(tier, model, tool=EXPLAIN_TOOL, effort="medium"):
    return ModelRequest(
        tier, model, "system prompt", "<evidence>\n{}\n</evidence>", tool, 2000, effort, "explain"
    )


def tool_use(payload):
    return [{"type": "tool_use", "id": "toolu_1", "name": "submit_explanations", "input": payload}]


def test_claude_api_large_tier_request_shape_and_normalized_response():
    recorder = Recorder(
        lambda body: (200, message(tool_use({"explanations": [], "synthesis": None})))
    )
    provider = AnthropicProvider("anthropic", client=client("anthropic", recorder))
    response = provider.complete(request(Tier.LARGE, "claude-opus-5"))
    sent = recorder.requests[0]
    body = sent.body
    assert body["model"] == "claude-opus-5"
    assert body["tool_choice"] == {"type": "tool", "name": "submit_explanations"}
    assert body["tools"][0]["strict"] is True
    assert "maxLength" not in json.dumps(body["tools"]) and "pattern" not in json.dumps(
        body["tools"]
    )
    assert body["thinking"] == {"type": "adaptive"} and body["output_config"] == {
        "effort": "medium"
    }
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert body["fallbacks"] == "default" and "temperature" not in body
    assert "server-side-fallback-2026-07-01" in sent.headers["anthropic-beta"]
    assert response.tool_input == {"explanations": [], "synthesis": None}
    assert (response.input_tokens, response.output_tokens, response.cache_read_tokens) == (
        900,
        300,
        700,
    )
    assert response.request_id == "req_test" and response.tool_calls == 1


def test_small_tier_uses_haiku_without_thinking_effort_or_fallback():
    recorder = Recorder(
        lambda body: (
            200,
            message(tool_use({"explanations": [], "synthesis": None}), model="claude-haiku-4-5"),
        )
    )
    provider = AnthropicProvider("anthropic", client=client("anthropic", recorder))
    provider.complete(request(Tier.SMALL, "claude-haiku-4-5", effort=None))
    body = recorder.requests[0].body
    assert body["model"] == "claude-haiku-4-5"
    assert not {"thinking", "output_config", "fallbacks"} & set(body)
    assert "server-side-fallback" not in recorder.requests[0].headers.get("anthropic-beta", "")


def test_bedrock_mantle_request_shape():
    recorder = Recorder(
        lambda body: (
            200,
            message(tool_use({"explanations": [], "synthesis": None}), model=body["model"]),
        )
    )
    provider = AnthropicProvider("bedrock", client=client("bedrock", recorder))
    assert provider.models == {
        Tier.SMALL: "anthropic.claude-haiku-4-5",
        Tier.LARGE: "anthropic.claude-opus-5",
    }
    provider.complete(request(Tier.LARGE, provider.models[Tier.LARGE]))
    sent = recorder.requests[0]
    assert sent.url.startswith("https://bedrock-mantle.us-east-1.api.aws/anthropic/v1/messages")
    assert sent.headers["authorization"].startswith("AWS4-HMAC-SHA256")
    body = sent.body
    assert body["model"] == "anthropic.claude-opus-5"
    # Bedrock: no structured outputs, and forced tool_choice requires thinking disabled.
    assert "strict" not in body["tools"][0] and body["thinking"] == {"type": "disabled"}
    assert "fallbacks" not in body and "fallback-credit" in sent.headers["anthropic-beta"]


def test_text_and_refusal_responses_are_normalized():
    recorder = Recorder(
        lambda body: (
            200,
            message([{"type": "text", "text": "I think it is fine."}], stop="end_turn"),
        )
    )
    provider = AnthropicProvider("anthropic", client=client("anthropic", recorder))
    response = provider.complete(request(Tier.LARGE, "claude-opus-5"))
    assert (
        response.tool_input is None and response.text_sha256 and response.stop_reason == "end_turn"
    )

    refusal = message(
        [],
        stop="refusal",
        stop_details={"type": "refusal", "category": "cyber", "explanation": None},
    )
    provider = AnthropicProvider(
        "anthropic", client=client("anthropic", Recorder(lambda body: (200, refusal)))
    )
    response = provider.complete(request(Tier.LARGE, "claude-opus-5"))
    assert response.stop_reason == "refusal" and response.refusal_category == "cyber"


@pytest.mark.parametrize(
    "status,error_type,kind",
    [
        (429, "rate_limit_error", "throttled"),
        (529, "overloaded_error", "overloaded"),
        (503, "api_error", "unavailable"),
        (500, "api_error", "unavailable"),
        (401, "authentication_error", "auth"),
        (403, "permission_error", "auth"),
        (404, "not_found_error", "configuration"),
        (400, "invalid_request_error", "bad_request"),
    ],
)
def test_provider_errors_are_classified(status, error_type, kind):
    error = {"type": "error", "error": {"type": error_type, "message": "test"}}
    provider = AnthropicProvider(
        "anthropic", client=client("anthropic", Recorder(lambda body: (status, error)))
    )
    with pytest.raises(ProviderError) as raised:
        provider.complete(request(Tier.LARGE, "claude-opus-5"))
    assert raised.value.kind == kind


def test_unknown_models_and_providers_are_rejected_not_guessed(monkeypatch):
    with pytest.raises(ProviderError, match="configuration"):
        AnthropicProvider("anthropic", client=object(), models={Tier.LARGE: "claude-fable-5-1"})
    with pytest.raises(ProviderError, match="configuration"):
        build_provider("openai")
    monkeypatch.delenv("FIRST_COMMIT_MODEL_PROVIDER", raising=False)
    assert build_provider() is None and build_provider("none") is None


def test_full_explanation_run_through_the_real_sdk(tmp_path):
    report = golden_report()
    policy = evaluate(report, tmp_path)
    grounded = GroundedModel(report, policy)

    def respond(body):
        tier = Tier.LARGE if "opus" in body["model"] else Tier.SMALL
        fake = SimpleNamespace(
            user=body["messages"][0]["content"],
            tool={"name": body["tools"][0]["name"]},
            model=body["model"],
            tier=tier,
        )
        result = grounded(fake)
        content = [
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": body["tools"][0]["name"],
                "input": result.tool_input,
            }
        ]
        return 200, message(content, model=body["model"])

    recorder = Recorder(respond)
    provider = AnthropicProvider("anthropic", client=client("anthropic", recorder))
    result = ReasoningService(provider, MemoryExplanationCache()).explain(
        report, policy, ReasoningContext("tenant-a", "alice")
    )
    assert result["status"] == "complete"
    assert [r.body["model"] for r in recorder.requests] == ["claude-haiku-4-5", "claude-opus-5"]
    assert result["usage"]["cache_read_input_tokens"] == 1400
    assert result["usage"]["estimated_cost_usd"] > 0
