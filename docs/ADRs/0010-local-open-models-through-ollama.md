# ADR 0010: Local open models through a loopback-only Ollama adapter

Status: Accepted. Date: 2026-09-13.

## Context

Phase 5 must work without a paid model API and should let contributors evaluate
several open-weight/open-source model families. Local inference adds new risks:
an endpoint can silently point at a remote service, Ollama Cloud tags can create
cost, a model may not fit the machine, small contexts can truncate evidence, and
different models vary in tool support.

## Decision

1. Add Ollama directly behind the existing `ModelProvider` interface. Phase 5
   is one constrained completion, not agentic orchestration, so wrapping the
   local call in Strands would add a second decision-maker and dependency for no
   safety benefit. Strands remains a Phase 6 orchestration concern. The reasoning
   workflow, prompt modules, cache, budget, retries and output validation remain
   provider-neutral.
2. Accept only `http` endpoints on `localhost`, `127.0.0.1` or `::1`. Reject
   credentials, paths, query strings and all model names ending in `:cloud`.
3. Use Ollama structured outputs (`format` is the complete JSON schema),
   temperature 0 and seed 0. Still run the same independent schema and grounding
   validators; provider-side constraints are defense in depth, not trust.
4. Ask `/api/show` for the installed model's context length before inference.
   Refuse a request that cannot fit the prompt, requested output and safety
   margin. Allocate only the request-sized window, rounded to 1K tokens, so a
   large advertised context does not unnecessarily exhaust laptop memory. Do
   not silently truncate or switch to a remote model.
5. Preserve deterministic difficulty routing: small work uses the configured
   local small model; complex, disputed, production, compound, truncated or
   injection-shaped work uses the configured local large model. Evidence itself
   remains bounded before routing.
6. Never pull weights automatically. Operators select a reviewed profile or
   explicitly override both tier names. Model names and prompt versions remain
   in cache keys.
7. Treat Ollama API price as zero while retaining model-call and token caps;
   local compute, electricity and hardware use are not claimed to be free.

## Curated profiles

The catalog is a reviewed choice set, not a mutable benchmark ranking:

| Profile | Low-level tier | High-level tier | License note |
| --- | --- | --- | --- |
| Qwen3 (default) | `qwen3:4b` | `qwen3:8b` | Apache-2.0 |
| DeepSeek-R1 | `deepseek-r1:8b` | `deepseek-r1:32b` | MIT; check distilled base terms |
| Mistral | `mistral:7b` | `mistral-small3.2:24b` | Apache-2.0 |
| OLMo 2 | `olmo2:7b` | `olmo2:13b` | Apache-2.0; short context limits usefulness |
| GPT-OSS | `gpt-oss:20b` | `gpt-oss:120b` | Apache-2.0; substantial memory required |
| Kimi | `first-commit-kimi:small` | `first-commit-kimi:large` | Operator-imported local aliases only |

Kimi's official Ollama local entries are retired and the current official entry
is cloud-only. The aliases avoid falsely claiming that a local Kimi model can be
pulled today. An operator may create them from legally obtained, compatible
local weights; First Commit will never replace them with `kimi-*:cloud`.

## Consequences

- A contributor can run all Phase 5 reasoning locally with no inference API
  charge or repository data leaving the machine.
- The same validation and human-review fallback applies to weaker local models,
  so adding providers does not add decision authority.
- Installing every profile would consume excessive disk and memory. CI uses a
  fake transport; opt-in live verification uses only models chosen for the host.
- An unavailable or undersized model degrades safely to vetted templates and is
  reported distinctly; it is never treated as a clean result.

## References

- [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs)
  and [chat API](https://docs.ollama.com/api/chat)
- Ollama library entries for [Qwen3](https://ollama.com/library/qwen3),
  [DeepSeek-R1](https://ollama.com/library/deepseek-r1),
  [Mistral Small 3.2](https://ollama.com/library/mistral-small3.2),
  [OLMo 2](https://ollama.com/library/olmo2) and
  [GPT-OSS](https://ollama.com/library/gpt-oss)
- The retired [Kimi K2 local entry](https://ollama.com/library/kimi-k2) and the
  cloud-only [Kimi K2.6 entry](https://ollama.com/library/kimi-k2.6)
