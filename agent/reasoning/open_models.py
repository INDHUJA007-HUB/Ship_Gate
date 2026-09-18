"""Curated local Ollama model profiles for the Phase 5 two-tier router.

Profiles are recommendations, not a trust boundary.  Operators may override both model names,
but every Ollama model must already exist on the local daemon and cloud-tagged models are refused.
Kimi is deliberately import-only: Ollama retired its local Kimi library entry, so First Commit
does not silently substitute the paid ``:cloud`` model.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent.reasoning.routing import Tier


@dataclass(frozen=True)
class OpenModelProfile:
    name: str
    small: str
    large: str
    license: str
    local_status: str = "ollama_library"

    @property
    def models(self) -> dict[Tier, str]:
        return {Tier.SMALL: self.small, Tier.LARGE: self.large}


# This is a reviewed, reproducible catalog rather than a claim that one benchmark defines "best".
# The defaults are intentionally laptop-sized; operators with more memory can override either tier.
OPEN_MODEL_PROFILES: dict[str, OpenModelProfile] = {
    "qwen3": OpenModelProfile("qwen3", "qwen3:4b", "qwen3:8b", "Apache-2.0"),
    "deepseek-r1": OpenModelProfile(
        "deepseek-r1", "deepseek-r1:8b", "deepseek-r1:32b", "MIT / base-model terms"
    ),
    "mistral": OpenModelProfile("mistral", "mistral:7b", "mistral-small3.2:24b", "Apache-2.0"),
    "olmo2": OpenModelProfile("olmo2", "olmo2:7b", "olmo2:13b", "Apache-2.0"),
    "gpt-oss": OpenModelProfile("gpt-oss", "gpt-oss:20b", "gpt-oss:120b", "Apache-2.0"),
    # These names are local aliases the operator creates after importing legally obtained weights.
    # They are not pulled automatically and can never resolve to Ollama Cloud.
    "kimi": OpenModelProfile(
        "kimi",
        "first-commit-kimi:small",
        "first-commit-kimi:large",
        "Modified MIT",
        "local_import_required",
    ),
}
DEFAULT_OPEN_MODEL_PROFILE = "qwen3"


def profile(name: str) -> OpenModelProfile:
    try:
        return OPEN_MODEL_PROFILES[name.lower()]
    except KeyError as error:
        choices = ", ".join(sorted(OPEN_MODEL_PROFILES))
        raise ValueError(f"unknown Ollama profile; choose one of: {choices}") from error
