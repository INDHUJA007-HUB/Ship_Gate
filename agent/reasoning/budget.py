"""Per-run model budget, circuit breaker and usage ledger.

An intentional budget stop and a provider problem (throttling, overload, outage) are reported
separately. Neither is ever retried silently past its limit, and neither is cached.
"""

from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass, field

# Anthropic first-party list prices in USD per million tokens (input, output). Amazon Bedrock
# pricing is set by AWS and differs; reports label the basis.
PRICES = {
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-sonnet-5": (2.0, 10.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-4-8": (5.0, 25.0),
}
CACHE_READ_MULTIPLIER = 0.1
CACHE_WRITE_MULTIPLIER = 1.25
TRANSIENT = frozenset({"throttled", "overloaded", "unavailable", "timeout"})


def price(model: str, provider: str = "anthropic") -> tuple[float, float]:
    if provider == "ollama":
        return (0.0, 0.0)
    base = model.removeprefix("anthropic.")
    # Unknown models are priced at the most expensive known rate, never as free.
    return PRICES.get(base, max(PRICES.values()))


class BudgetExhausted(RuntimeError):
    pass


@dataclass(frozen=True)
class Budget:
    max_calls: int = 12
    max_cost_usd: float = 0.50
    max_input_tokens: int = 200_000
    max_output_tokens: int = 60_000
    breaker_threshold: int = 2

    def __post_init__(self):
        if self.max_calls < 0 or self.max_cost_usd < 0 or self.breaker_threshold < 1:
            raise ValueError("invalid_model_budget")


@dataclass
class Ledger:
    budget: Budget
    calls: int = 0
    calls_by_tier: Counter = field(default_factory=Counter)
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float = 0.0
    reserved_usd: float = 0.0
    failures: Counter = field(default_factory=Counter)
    consecutive_failures: int = 0
    circuit: str | None = None
    events: Counter = field(default_factory=Counter)
    prompts: list = field(default_factory=list)
    cost_basis: str = "anthropic_first_party_list_price"
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def reserve(
        self, model: str, estimated_input: int, max_tokens: int, provider: str = "anthropic"
    ) -> float:
        """Reserve the worst-case cost of one call or stop the run intentionally."""
        in_price, out_price = price(model, provider)
        if provider == "ollama":
            self.cost_basis = "local_compute_no_api_charge"
        worst = (estimated_input * in_price + max_tokens * out_price) / 1_000_000
        with self._lock:
            if self.circuit:
                raise BudgetExhausted(self.circuit)
            over = (
                self.calls + 1 > self.budget.max_calls
                or self.cost_usd + self.reserved_usd + worst > self.budget.max_cost_usd
                or self.input_tokens + estimated_input > self.budget.max_input_tokens
                or self.output_tokens + max_tokens > self.budget.max_output_tokens
            )
            if over:
                self.circuit = "budget_exhausted"
                raise BudgetExhausted("budget_exhausted")
            self.reserved_usd += worst
            self.calls += 1
            return worst

    def release(self, reserved: float) -> None:
        with self._lock:
            self.reserved_usd = max(0.0, self.reserved_usd - reserved)

    def record(self, tier: str, response, reserved: float, provider: str = "anthropic") -> None:
        in_price, out_price = price(response.model, provider)
        cost = (
            response.input_tokens * in_price
            + response.cache_read_tokens * in_price * CACHE_READ_MULTIPLIER
            + response.cache_write_tokens * in_price * CACHE_WRITE_MULTIPLIER
            + response.output_tokens * out_price
        ) / 1_000_000
        with self._lock:
            self.reserved_usd = max(0.0, self.reserved_usd - reserved)
            self.calls_by_tier[tier] += 1
            self.input_tokens += response.input_tokens
            self.output_tokens += response.output_tokens
            self.cache_read_tokens += response.cache_read_tokens
            self.cache_write_tokens += response.cache_write_tokens
            self.cost_usd += cost
            self.consecutive_failures = 0

    def record_failure(self, kind: str, reserved: float) -> None:
        with self._lock:
            self.reserved_usd = max(0.0, self.reserved_usd - reserved)
            self.failures[kind] += 1
            if kind not in TRANSIENT:
                self.circuit = f"provider_{kind}"  # Auth, configuration, bad request: stop now.
                return
            self.consecutive_failures += 1
            if self.consecutive_failures >= self.budget.breaker_threshold:
                self.circuit = "provider_unavailable"

    def note(self, event: str, amount: int = 1) -> None:
        with self._lock:
            self.events[event] += amount

    def to_dict(self) -> dict:
        return {
            "model_calls": self.calls,
            "calls_by_tier": dict(sorted(self.calls_by_tier.items())),
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_input_tokens": self.cache_read_tokens,
            "cache_write_input_tokens": self.cache_write_tokens,
            "estimated_cost_usd": round(self.cost_usd, 6),
            "cost_basis": self.cost_basis,
            "budget": {
                "max_calls": self.budget.max_calls,
                "max_cost_usd": self.budget.max_cost_usd,
            },
            "budget_exhausted": self.circuit == "budget_exhausted",
            "circuit_open": self.circuit,
            "provider_failures": dict(sorted(self.failures.items())),
            "throttled": self.failures["throttled"],
            "events": dict(sorted(self.events.items())),
            "model_calls_avoided": self.events["deterministic_units"] + self.events["cache_hits"],
            "prompts": self.prompts,
        }
