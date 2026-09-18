"""Strictly local Ollama adapter for Phase 5 structured reasoning.

The adapter talks only to a loopback HTTP daemon, never pulls a model, never accepts an Ollama
Cloud tag, and uses Ollama's JSON-schema output mode.  Phase 5 still performs its independent
schema and grounding validation after this provider returns.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from agent.reasoning.open_models import DEFAULT_OPEN_MODEL_PROFILE, profile
from agent.reasoning.providers import ModelRequest, ModelResponse, ProviderError
from agent.reasoning.routing import Tier

DEFAULT_ENDPOINT = "http://127.0.0.1:11434"
MAX_HTTP_RESPONSE = 8 * 1024 * 1024
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def local_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ProviderError("configuration", "Ollama endpoint must be loopback HTTP")
    try:
        _ = parsed.port
    except ValueError as error:
        raise ProviderError("configuration", "invalid Ollama port") from error
    return value.rstrip("/")


def local_model(value: str) -> str:
    model = value.strip()
    if not model or len(model) > 200 or model.lower().endswith(":cloud"):
        raise ProviderError("configuration", "Ollama model must be local and not use :cloud")
    return model


class OllamaTransport:
    def __init__(self, endpoint: str, timeout: float):
        self.endpoint = local_endpoint(endpoint)
        self.timeout = timeout
        # A loopback request must not honor proxy variables or follow a redirect off-host.
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    def __call__(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request(
            f"{self.endpoint}{path}",
            data=data,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_HTTP_RESPONSE + 1)
        except HTTPError as error:
            kind = (
                "throttled"
                if error.code == 429
                else ("configuration" if error.code == 404 else "unavailable")
            )
            raise ProviderError(kind, f"ollama_http_{error.code}") from error
        except TimeoutError as error:
            raise ProviderError("timeout", "ollama") from error
        except URLError as error:
            raise ProviderError("unavailable", "ollama_connection") from error
        if len(raw) > MAX_HTTP_RESPONSE:
            raise ProviderError("bad_response", "ollama response exceeds 8 MiB")
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProviderError("bad_response", "ollama returned invalid JSON") from error
        if not isinstance(body, dict):
            raise ProviderError("bad_response", "ollama response is not an object")
        if body.get("error"):
            detail = str(body["error"])
            kind = "configuration" if "not found" in detail.lower() else "bad_request"
            raise ProviderError(kind, detail)
        return body


class OllamaProvider:
    """Ollama provider using a small/large profile and JSON-schema constrained output."""

    name = "ollama"
    cost_basis = "local_compute_no_api_charge"

    def __init__(
        self,
        *,
        endpoint: str = DEFAULT_ENDPOINT,
        profile_name: str = DEFAULT_OPEN_MODEL_PROFILE,
        models: dict[Tier, str] | None = None,
        timeout: float = 600.0,
        transport: Callable[[str, str, dict | None], dict] | None = None,
        max_context: int = 131_072,
    ):
        self.endpoint = local_endpoint(endpoint)
        try:
            defaults = profile(profile_name)
        except ValueError as error:
            raise ProviderError("configuration", str(error)) from error
        self.profile = defaults.name
        self.models = {tier: local_model(model) for tier, model in defaults.models.items()}
        self.models.update({tier: local_model(model) for tier, model in (models or {}).items()})
        if max_context < 4096:
            raise ProviderError("configuration", "Ollama context cap must be at least 4096")
        self.max_context = max_context
        self.transport = transport or OllamaTransport(self.endpoint, timeout)
        self._contexts: dict[str, int] = {}

    def _context_length(self, model: str) -> int:
        if model in self._contexts:
            return self._contexts[model]
        body = self.transport("POST", "/api/show", {"model": model})
        info = body.get("model_info", {})
        values = (
            [
                value
                for key, value in info.items()
                if key.endswith(".context_length") and isinstance(value, int) and value > 0
            ]
            if isinstance(info, dict)
            else []
        )
        if not values:
            raise ProviderError("configuration", f"cannot determine context length for {model}")
        self._contexts[model] = max(values)
        return self._contexts[model]

    def complete(self, request: ModelRequest) -> ModelResponse:
        model = local_model(request.model)
        context_length = min(self._context_length(model), self.max_context)
        contract = json.dumps(request.tool["input_schema"], sort_keys=True, separators=(",", ":"))
        required = request.max_tokens + len(request.system + request.user + contract) // 3 + 512
        if required > context_length:
            raise ProviderError(
                "context_limit", f"{model} needs {required} tokens but supports {context_length}"
            )
        # Allocating the model's entire advertised window can consume many extra GB and make a
        # laptop spill to CPU. Reserve only what this bounded request needs, rounded to 1K tokens.
        allocated_context = max(4096, ((required + 1023) // 1024) * 1024)
        user = (
            f"{request.user}\n<output_contract>\nReturn one JSON object matching this schema; "
            f"it is the input to {request.tool['name']}. No markdown.\n"
            f"{contract}\n</output_contract>"
        )
        body = self.transport(
            "POST",
            "/api/chat",
            {
                "model": model,
                "messages": [
                    {"role": "system", "content": request.system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "format": request.tool["input_schema"],
                "think": False,
                "options": {
                    "temperature": 0,
                    "seed": 0,
                    "num_ctx": allocated_context,
                    "num_predict": request.max_tokens,
                },
            },
        )
        message = body.get("message")
        content = message.get("content", "") if isinstance(message, dict) else ""
        tool_input: Any = None
        if isinstance(content, str) and content:
            try:
                tool_input = json.loads(content)
            except json.JSONDecodeError:
                pass  # The common validation/retry path handles malformed model output.
        done_reason = str(body.get("done_reason") or "stop")
        stop_reason = "max_tokens" if done_reason in {"length", "max_tokens"} else "tool_use"
        if tool_input is None and stop_reason == "tool_use":
            stop_reason = "end_turn"
        return ModelResponse(
            tool_input=tool_input,
            stop_reason=stop_reason,
            model=str(body.get("model") or model),
            input_tokens=int(body.get("prompt_eval_count") or 0),
            output_tokens=int(body.get("eval_count") or 0),
            request_id=None,
            text_sha256=hashlib.sha256(content.encode()).hexdigest() if content else None,
            tool_calls=1 if tool_input is not None else 0,
        )

    def installed_models(self) -> tuple[str, ...]:
        body = self.transport("GET", "/api/tags", None)
        models = body.get("models", [])
        return tuple(
            sorted(
                str(item.get("model") or item.get("name"))
                for item in models
                if isinstance(item, dict) and (item.get("model") or item.get("name"))
            )
        )
