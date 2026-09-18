"""Strands model provider over the Anthropic Python SDK 1.x: Claude API or Claude in Bedrock.

Strands' bundled Anthropic provider pins `anthropic<1`, which conflicts with the SDK Phase 5
already uses, and its Bedrock provider calls a different Bedrock API with different IAM actions.
This adapter reuses Phase 5's client construction, credentials, model allowlist and IAM action.

Orchestration is classification-shaped (pick a tool and its arguments), so the default is the
small tier with a short output cap, no extended thinking, and a cached system prompt.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncGenerator, AsyncIterable
from typing import Any

from strands.models.model import Model
from strands.types.exceptions import ModelThrottledException

from agent.reasoning.providers import DEFAULT_MODELS, AnthropicProvider, ProviderError, capabilities
from agent.reasoning.routing import Tier

STOP_REASONS = {
    "tool_use": "tool_use",
    "end_turn": "end_turn",
    "max_tokens": "max_tokens",
    "stop_sequence": "stop_sequence",
    "refusal": "guardrail_intervened",
}


class ClaudeModel(Model):
    def __init__(
        self,
        platform: str = "anthropic",
        *,
        model: str | None = None,
        client=None,
        region: str | None = None,
        max_tokens: int = 1024,
    ):
        if platform not in DEFAULT_MODELS:
            raise ProviderError("configuration", "platform must be anthropic or bedrock")
        model = model or DEFAULT_MODELS[platform][Tier.SMALL]
        if capabilities(model)["adaptive_thinking"]:
            # Tool selection does not need thinking; the small tier keeps each decision cheap.
            raise ProviderError("configuration", "orchestration uses a small, non-thinking model")
        self.config: dict[str, Any] = {
            "platform": platform,
            "model_id": model,
            "max_tokens": max_tokens,
        }
        self.client = (
            client or AnthropicProvider(platform, region=region, refusal_fallback=False).client
        )

    def update_config(self, **model_config: Any) -> None:
        self.config.update(model_config)

    def get_config(self) -> dict[str, Any]:
        return dict(self.config)

    async def structured_output(
        self, output_model, prompt, system_prompt=None, **kwargs
    ) -> AsyncGenerator[dict[str, Any], None]:
        raise NotImplementedError("the orchestrator does not use structured output")
        yield {}  # pragma: no cover

    def request(self, messages, tool_specs=None, system_prompt=None, tool_choice=None) -> dict:
        params: dict[str, Any] = {
            "model": self.config["model_id"],
            "max_tokens": self.config["max_tokens"],
            "messages": [_message(message) for message in messages],
        }
        if system_prompt:
            params["system"] = [
                {"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}
            ]
        if tool_specs:
            params["tools"] = [
                {
                    "name": spec["name"],
                    "description": spec.get("description", ""),
                    "input_schema": spec["inputSchema"]["json"],
                }
                for spec in tool_specs
            ]
            params["tool_choice"] = _tool_choice(tool_choice)
        return params

    async def stream(
        self,
        messages,
        tool_specs=None,
        system_prompt=None,
        *,
        tool_choice=None,
        system_prompt_content=None,
        invocation_state=None,
        cancel_signal=None,
        **kwargs,
    ) -> AsyncIterable[dict]:
        import anthropic

        params = self.request(messages, tool_specs, system_prompt, tool_choice)
        started = time.monotonic()
        try:
            response = await asyncio.to_thread(self.client.beta.messages.create, **params)
        except (anthropic.RateLimitError, anthropic.OverloadedError) as error:
            raise ModelThrottledException(type(error).__name__) from error
        yield {"messageStart": {"role": "assistant"}}
        for block in response.content or []:
            kind = getattr(block, "type", "")
            if kind == "text":
                yield {"contentBlockStart": {"start": {}}}
                yield {"contentBlockDelta": {"delta": {"text": block.text}}}
                yield {"contentBlockStop": {}}
            elif kind == "tool_use":
                start = {"toolUse": {"toolUseId": block.id, "name": block.name}}
                yield {"contentBlockStart": {"start": start}}
                yield {
                    "contentBlockDelta": {"delta": {"toolUse": {"input": json.dumps(block.input)}}}
                }
                yield {"contentBlockStop": {}}
        yield {
            "messageStop": {"stopReason": STOP_REASONS.get(str(response.stop_reason), "end_turn")}
        }
        usage = response.usage
        tokens_in = getattr(usage, "input_tokens", 0) or 0
        tokens_out = getattr(usage, "output_tokens", 0) or 0
        yield {
            "metadata": {
                "usage": {
                    "inputTokens": tokens_in,
                    "outputTokens": tokens_out,
                    "totalTokens": tokens_in + tokens_out,
                    "cacheReadInputTokens": getattr(usage, "cache_read_input_tokens", 0) or 0,
                    "cacheWriteInputTokens": getattr(usage, "cache_creation_input_tokens", 0) or 0,
                },
                "metrics": {"latencyMs": int((time.monotonic() - started) * 1000)},
            }
        }


def _tool_choice(choice) -> dict:
    if isinstance(choice, dict) and "tool" in choice:
        return {"type": "tool", "name": choice["tool"]["name"]}
    if isinstance(choice, dict) and "any" in choice:
        return {"type": "any"}
    return {"type": "auto"}


def _message(message: dict) -> dict:
    blocks = []
    for block in message["content"]:
        if "text" in block:
            blocks.append({"type": "text", "text": block["text"]})
        elif "toolUse" in block:
            use = block["toolUse"]
            blocks.append(
                {
                    "type": "tool_use",
                    "id": use["toolUseId"],
                    "name": use["name"],
                    "input": use["input"],
                }
            )
        elif "toolResult" in block:
            result = block["toolResult"]
            content = [
                {
                    "type": "text",
                    "text": part["text"] if "text" in part else json.dumps(part["json"]),
                }
                for part in result.get("content", [])
                if "text" in part or "json" in part
            ]
            blocks.append(
                {
                    "type": "tool_result",
                    "tool_use_id": result["toolUseId"],
                    "content": content,
                    "is_error": result.get("status") == "error",
                }
            )
        else:
            raise ValueError("unsupported content block for the orchestrator model")
    return {"role": message["role"], "content": blocks}
