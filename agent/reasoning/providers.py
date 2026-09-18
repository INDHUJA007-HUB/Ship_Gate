"""Model providers behind one interface: cloud Claude, local Ollama, or scripted.

Every request forces the output tool. The Claude API also receives `strict: true` and adaptive
thinking with an effort level; Bedrock does not support structured outputs and requires thinking
disabled with a forced tool, so it relies on local validation alone. Large-tier requests opt into
refusal fallbacks: server-side `fallbacks: "default"` on the Claude API, the SDK's client-side
middleware on Bedrock. Transport failures are classified so throttling, outages and
misconfiguration are reported separately from invalid output.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from agent.reasoning.routing import Tier
from agent.reasoning.schemas import tool_definition

DEFAULT_MODELS = {
    "anthropic": {Tier.SMALL: "claude-haiku-4-5", Tier.LARGE: "claude-opus-5"},
    "bedrock": {Tier.SMALL: "anthropic.claude-haiku-4-5", Tier.LARGE: "anthropic.claude-opus-5"},
}
BEDROCK_REFUSAL_FALLBACK = "anthropic.claude-opus-4-8"
SERVER_FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Capabilities are listed explicitly; unknown models are rejected instead of guessed at.
# Claude Fable 5.1 is excluded because it rejects forced tool_choice.
MODEL_CAPABILITIES = {
    "claude-haiku-4-5": {"effort": False, "adaptive_thinking": False},
    "claude-sonnet-5": {"effort": True, "adaptive_thinking": True},
    "claude-opus-5": {"effort": True, "adaptive_thinking": True},
    "claude-opus-4-8": {"effort": True, "adaptive_thinking": True},
}


class ProviderError(RuntimeError):
    def __init__(self, kind: str, detail: str = ""):
        super().__init__(kind)
        self.kind = kind
        self.detail = detail[:200]


@dataclass(frozen=True)
class ModelRequest:
    tier: Tier
    model: str
    system: str
    user: str
    tool: dict
    max_tokens: int
    effort: str | None
    purpose: str


@dataclass(frozen=True)
class ModelResponse:
    tool_input: object | None
    stop_reason: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    refusal_category: str | None = None
    fallback_used: bool = False
    request_id: str | None = None
    text_sha256: str | None = None
    tool_calls: int = 1


class ModelProvider(Protocol):
    name: str
    models: dict[Tier, str]

    def complete(self, request: ModelRequest) -> ModelResponse: ...


def capabilities(model: str) -> dict:
    base = model.removeprefix("anthropic.")
    if base not in MODEL_CAPABILITIES:
        raise ProviderError("configuration", f"unsupported model {base}")
    return MODEL_CAPABILITIES[base]


class AnthropicProvider:
    """Claude API (`platform="anthropic"`) or Claude in Amazon Bedrock (`platform="bedrock"`)."""

    def __init__(
        self,
        platform: str = "anthropic",
        *,
        client=None,
        models: dict[Tier, str] | None = None,
        region: str | None = None,
        refusal_fallback: bool = True,
        timeout: float = 90.0,
        max_retries: int = 2,
    ):
        if platform not in DEFAULT_MODELS:
            raise ProviderError("configuration", "platform must be anthropic or bedrock")
        self.platform = platform
        self.name = platform
        self.models = {**DEFAULT_MODELS[platform], **(models or {})}
        for model in self.models.values():
            capabilities(model)
        self.refusal_fallback = refusal_fallback
        self.client = client or self._client(region, timeout, max_retries)

    def _client(self, region, timeout, max_retries):
        try:
            import anthropic
        except ImportError as error:
            raise ProviderError("configuration", "install first-commit[ai]") from error
        try:
            if self.platform == "bedrock":
                middleware = (
                    [anthropic.BetaRefusalFallbackMiddleware([{"model": BEDROCK_REFUSAL_FALLBACK}])]
                    if self.refusal_fallback
                    else None
                )
                return anthropic.AnthropicBedrockMantle(
                    aws_region=region,
                    timeout=timeout,
                    max_retries=max_retries,
                    middleware=middleware,
                )
            return anthropic.Anthropic(timeout=timeout, max_retries=max_retries)
        except (ValueError, anthropic.AnthropicError) as error:
            raise ProviderError("configuration", type(error).__name__) from error

    def params(self, request: ModelRequest) -> dict:
        caps = capabilities(request.model)
        params = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            # The frozen system prompt plus tool schema form the cacheable prefix.
            "system": [
                {"type": "text", "text": request.system, "cache_control": {"type": "ephemeral"}}
            ],
            "messages": [{"role": "user", "content": request.user}],
            "tools": [tool_definition(request.tool, strict=self.platform == "anthropic")],
            "tool_choice": {"type": "tool", "name": request.tool["name"]},
        }
        if caps["adaptive_thinking"]:
            # Bedrock requires thinking disabled with a forced tool_choice.
            params["thinking"] = (
                {"type": "disabled"} if self.platform == "bedrock" else {"type": "adaptive"}
            )
        if caps["effort"] and request.effort:
            params["output_config"] = {"effort": request.effort}
        if self.platform == "anthropic" and self.refusal_fallback and request.tier == Tier.LARGE:
            params["betas"] = [SERVER_FALLBACK_BETA]
            params["fallbacks"] = "default"
        return params

    def complete(self, request: ModelRequest) -> ModelResponse:
        import anthropic

        try:
            response = self.client.beta.messages.create(**self.params(request))
        except anthropic.RateLimitError as error:
            raise ProviderError("throttled", str(error.status_code)) from error
        except anthropic.OverloadedError as error:
            raise ProviderError("overloaded", str(error.status_code)) from error
        except (anthropic.ServiceUnavailableError, anthropic.InternalServerError) as error:
            raise ProviderError("unavailable", str(error.status_code)) from error
        except anthropic.APITimeoutError as error:
            raise ProviderError("timeout") from error
        except anthropic.APIConnectionError as error:
            raise ProviderError("unavailable", "connection") from error
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as error:
            raise ProviderError("auth", str(error.status_code)) from error
        except anthropic.NotFoundError as error:
            raise ProviderError("configuration", "model_not_found") from error
        except anthropic.BadRequestError as error:
            raise ProviderError("bad_request", getattr(error, "type", "") or "") from error
        except anthropic.APIStatusError as error:
            kind = "quota" if error.status_code == 402 else "unavailable"
            raise ProviderError(kind, str(error.status_code)) from error
        return normalize(response, request)


def normalize(response, request: ModelRequest) -> ModelResponse:
    tool_blocks, texts, fallback = [], [], False
    for block in response.content or []:
        kind = getattr(block, "type", "")
        if kind == "tool_use" and getattr(block, "name", None) == request.tool["name"]:
            tool_blocks.append(block.input)
        elif kind == "text":
            texts.append(block.text)
        elif kind == "fallback":
            fallback = True
    usage = response.usage
    details = getattr(response, "stop_details", None)
    text = "".join(texts)
    return ModelResponse(
        tool_input=tool_blocks[0] if tool_blocks else None,
        stop_reason=str(response.stop_reason),
        model=str(response.model),
        input_tokens=getattr(usage, "input_tokens", 0) or 0,
        output_tokens=getattr(usage, "output_tokens", 0) or 0,
        cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
        cache_write_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
        refusal_category=getattr(details, "category", None)
        if response.stop_reason == "refusal"
        else None,
        fallback_used=fallback,
        request_id=getattr(response, "_request_id", None),
        text_sha256=hashlib.sha256(text.encode()).hexdigest() if text else None,
        tool_calls=len(tool_blocks),
    )


@dataclass
class ScriptedProvider:
    """Deterministic provider for tests and offline evaluation; never contacts a network."""

    responder: Callable[[ModelRequest], ModelResponse]
    name: str = "scripted"
    models: dict[Tier, str] = field(default_factory=lambda: dict(DEFAULT_MODELS["anthropic"]))
    requests: list[ModelRequest] = field(default_factory=list)

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        result = self.responder(request)
        if isinstance(result, Exception):
            raise result
        return result


def build_provider(
    name: str | None = None,
    *,
    region: str | None = None,
    small_model: str | None = None,
    large_model: str | None = None,
    ollama_profile: str | None = None,
    ollama_url: str | None = None,
    ollama_max_context: int | None = None,
    ollama_timeout: float | None = None,
) -> ModelProvider | None:
    selected = (name or os.getenv("FIRST_COMMIT_MODEL_PROVIDER") or "none").lower()
    if selected == "none":
        return None
    if selected == "ollama":
        from agent.reasoning.ollama import DEFAULT_ENDPOINT, OllamaProvider

        overrides = {
            tier: value
            for tier, value in (
                (Tier.SMALL, os.getenv("FIRST_COMMIT_SMALL_MODEL")),
                (Tier.LARGE, large_model or os.getenv("FIRST_COMMIT_LARGE_MODEL")),
            )
            if value
        }
        if small_model:
            overrides[Tier.SMALL] = small_model
        try:
            max_context = (
                ollama_max_context
                if ollama_max_context is not None
                else int(os.getenv("FIRST_COMMIT_OLLAMA_MAX_CONTEXT", "131072"))
            )
            timeout = (
                ollama_timeout
                if ollama_timeout is not None
                else float(os.getenv("FIRST_COMMIT_OLLAMA_TIMEOUT_SECONDS", "600"))
            )
        except ValueError as error:
            raise ProviderError("configuration", "invalid Ollama limit") from error
        if timeout <= 0:
            raise ProviderError("configuration", "invalid Ollama timeout")
        return OllamaProvider(
            endpoint=ollama_url or os.getenv("FIRST_COMMIT_OLLAMA_URL", DEFAULT_ENDPOINT),
            profile_name=ollama_profile or os.getenv("FIRST_COMMIT_OLLAMA_PROFILE", "qwen3"),
            models=overrides,
            max_context=max_context,
            timeout=timeout,
        )
    if selected not in DEFAULT_MODELS:
        raise ProviderError("configuration", "provider must be none, anthropic, bedrock or ollama")
    overrides = {
        tier: value
        for tier, value in (
            (Tier.SMALL, small_model or os.getenv("FIRST_COMMIT_SMALL_MODEL")),
            (Tier.LARGE, large_model or os.getenv("FIRST_COMMIT_LARGE_MODEL")),
        )
        if value
    }
    fallback = os.getenv("FIRST_COMMIT_REFUSAL_FALLBACK", "on").lower() != "off"
    return AnthropicProvider(
        selected,
        models=overrides,
        region=region or os.getenv("AWS_REGION"),
        refusal_fallback=fallback,
    )
