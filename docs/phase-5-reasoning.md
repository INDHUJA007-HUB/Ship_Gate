# Phase 5 — AI reasoning layer

Phase 5 turns Phase 3 findings and Phase 4 Cedar decisions into correct,
plain-language explanations and answers to questions about a scan. The model
boundary is [ADR 0008](ADRs/0008-evidence-first-model-boundary.md): a model
explains and may escalate to review, but never changes a decision, supplies a
confidence, or sees source code. The design decisions are in
[ADR 0009](ADRs/0009-tiered-validated-model-explanations.md).

```text
scan report + policy result
  -> evidence packet: consistency checks, grouping, sanitizing, redaction, injection flags
  -> units: one per finding group, plus a scan synthesis
  -> routing: deterministic | small model | large model   (scored, recorded, escalate-only)
  -> cache lookup (tenant + content hash + every version) -> lease against concurrent twins
  -> one evidence-first prompt, rendered from the modules the situation needs
  -> forced tool call -> schema validation -> grounding validation
  -> accept | escalate one tier | one corrective retry | human review with vetted template
  -> report: explanations, synthesis, routing, attempts, usage; decisions unchanged
```

## Commands

```powershell
pip install -e ".[dev]"
first-commit scan fixtures/golden-repo > scan.json
first-commit policy scan.json --tenant demo --user alice --owner demo --environment development --current-hash HASH > policy.json
first-commit explain scan.json policy.json --tenant demo --user alice
first-commit ask scan.json policy.json "What should I fix first?" --tenant demo --user alice
```

Local open-model setup is explicit (downloads never happen inside First Commit):

```powershell
ollama pull qwen3:4b
ollama pull qwen3:8b
first-commit explain scan.json policy.json --tenant demo --user alice --provider ollama --ollama-profile qwen3
```

`--provider` is `none` (default), `anthropic`, `bedrock` or `ollama`. `none` never calls a
model: every unit uses the vetted template, and questions use vetted knowledge.
Other flags: `--audience beginner|developer`, `--max-calls`, `--max-cost` (USD),
`--cache-db`, `--refresh`, `--region`, `--small-model`, `--large-model`,
`--ollama-profile`, `--ollama-url`, `--ollama-max-context`, `--ollama-timeout`.

## Tiers and routing

| Tier | Claude API / Bedrock | Local Ollama default | Used for |
| --- | --- | --- | --- |
| Deterministic | none | none | Deterministic facts with low risk, denied groups, simple syntheses, blocked and policy questions |
| Small | `claude-haiku-4-5` / `anthropic.claude-haiku-4-5` | `qwen3:4b` | Bulk, classification-shaped explanations; ambiguous-question classification |
| Large | `claude-opus-5` / `anthropic.claude-opus-5` | `qwen3:8b` | Nuanced security reasoning, the scan synthesis, disputes and comparisons |

Each group gets a score from explicit, recorded features: severity (critical 3,
high 2, medium 1), category (IAM 3; secret, auth, command execution 2;
validation 1; environment 0), review needed, compound risk, production (2),
batch summary, several locations, inline-suppressed checks (2), mixed evidence,
truncation, and a deterministic fact (−1). A score ≤ 1 on a category whose
template fully explains it uses no model; ≤ 5 goes to the small tier; above that
to the large tier. Two rules override the score: instruction-like repository text
always goes to the large tier, and a denied group (invalid, stale or incomplete
context) never calls a model.

On the planted-issue fixture: secret, IAM and auth route to the large tier
(score 6), validation (4) and the environment variable (2, compound risk) to the
small tier. The same environment variable on its own is a deterministic fact the
policy permits, scores 0, and needs no model.

A model can move work up, never down. A small-tier result that reports
`needs_stronger_model`, `conflicting_evidence`, `insufficient_evidence` or
`possible_prompt_injection` is redone on the large tier. Questions are scored
the same way from intent weights, referenced groups and, for ambiguous
questions, the small model's difficulty classification.

## One prompt template

Every request renders from [agent/reasoning/prompts.py](../agent/reasoning/prompts.py):

- **System prompt:** frozen, with the eight non-negotiable rules. It is the
  cacheable prefix (`cache_control` breakpoint).
- **User message:** tagged sections containing only what the situation needs.
  - Task: explain, synthesis, answer or classify.
  - Audience.
  - Situation modules: production, compound risk, batch summary, several
    locations, heuristic vs deterministic evidence, suppressed checks, known
    example, untrusted text, truncation, denied, permitted, incomplete scan,
    escalated.
  - Guidance for the categories present.
  - Glossary for the policy reasons present.
  - Requested groups, priority order, compact JSON evidence, and any correction.

Token discipline:
- Short refs (`G2.L1`) replace 20-character finding hashes.
- Evidence is compact, sorted JSON; repeated findings collapse into one group
  with its locations.
- Groups on the same tier share a single batched call.
- Answers carry full facts only for referenced groups, plus a one-line index of
  the rest.
- User questions are rewritten into canonical forms, so paraphrases share a
  cache entry.

## Structured output and validation

Every request uses one versioned output contract (`submit_explanations`, `submit_answer`,
`classify_question`). Claude providers force the corresponding tool, and the Claude API also
enforces `strict: true`. Ollama receives the complete contract as its structured-output JSON
schema with temperature 0 and seed 0. Claude in
Amazon Bedrock does not support structured outputs, and no provider enforces
lengths, counts or patterns. So every response goes through the complete local
contract in [schemas.py](../agent/reasoning/schemas.py), then the grounding
checks in [validation.py](../agent/reasoning/validation.py):

| Failure | Detection | Handling |
| --- | --- | --- |
| Prose instead of a tool call, truncation | `MISSING_TOOL_CALL`, `TRUNCATED_OUTPUT` | Retry with the error and more output room |
| Missing, extra or wrong-typed fields; overlong text | `SCHEMA` (values never echoed) | Corrective retry |
| Invented, duplicate or missing group | `UNREQUESTED_GROUP` taints the batch, `DUPLICATE_GROUP`, `MISSING_GROUP` | Corrective retry |
| Hallucinated ref, path, line, check ID, CWE, AWS action, ARN or variable | `UNKNOWN_REF`, `UNGROUNDED_*` | Corrective retry |
| "False positive", "safe to deploy", "no action needed", downplaying high severity | `AUTHORITY_CLAIM` (negations and hypotheticals allowed) | Corrective retry |
| `shell=True`, wildcard grants, disabling auth, scanner suppressions, hardcoding secrets | `UNSAFE_ADVICE` (negated advice allowed) | Corrective retry |
| Secret without rotation, auth fix without authorization | `MISSING_REQUIRED_STEP` | Corrective retry |
| Credential-like or high-entropy output | `SECRET_MATERIAL` | Corrective retry |
| Reordered priorities | `PRIORITY_ORDER_CONFLICT` | Corrective retry |
| Refusal | `stop_reason: refusal` | Escalate once, never a blind retry; then human review |

Retry policy: a unit gets one corrective retry, and it always runs on the large
tier with `effort: high`. A small-tier failure is retried on the large tier
carrying its violations; a large-tier failure is retried once on the large tier.
A unit that still fails is shown with the vetted template, marked
`needs_human_review` with its violation codes, and cached, so unchanged content
never pays again. Every attempt records tier, model, stop reason, violation
codes and hashes of the prompt and output; rejected text is never shown. The
vetted templates pass these same checks.

## Caching, concurrency and cost

- **Cache key:** tenant, audience, provider, models, and the prompt, contract,
  knowledge, router, packet and query versions, plus the unit's evidence facts.
  Only validated results and human-review outcomes are cached. Local mode uses
  SQLite; AWS mode uses the control-plane table with conditional writes.
- **Leases:** acquired all-or-none per run, so concurrent identical requests wait
  for one worker instead of splitting or repeating the work.
- **Budget:** each call reserves its worst-case cost (estimated input plus
  `max_tokens`) against `max_calls`, `max_cost_usd` and token limits before it is
  sent. Exceeding a limit is an intentional `budget_exhausted` stop.
- **Circuit breaker:** two consecutive transient failures (throttled, overloaded,
  unavailable, timeout) after the SDK's own retries open it as
  `provider_unavailable`. Auth, configuration and bad-request errors open it
  immediately. Throttling counts are reported separately from budget stops.
- **Degraded units:** use the vetted template and are never cached.
- **Usage report:** calls per tier, tokens including cache reads and writes,
  estimated cost and its basis (Anthropic list price or zero local API charge),
  calls avoided, and each prompt's modules and size.

## Questions

[query.py](../agent/reasoning/query.py) sanitizes and redacts the question,
resolves references (G-ids, paths and lines, finding-id prefixes, category
words, "this" when only one group exists, "all of these") and scores intents.
It then picks the cheapest safe handling:

| Handling | Intents or situations | Model calls |
| --- | --- | --- |
| Blocked | Instruction override, marking safe or lowering severity, secret disclosure, runtime tracebacks, help, off-topic | 0 |
| Clarify | Ambiguous reference: one question listing the groups, never a guess | 0 |
| Deterministic | Deploy readiness, why the policy decided | 0 |
| Knowledge | Concepts in the vetted glossary (least privilege, authorization, command injection, and so on) | 0 |
| Explanations | Explain, why risky, how to fix | 0 if cached, else the explanation pipeline |
| Synthesis | What to fix first, overview | 0 if cached, else one large call |
| Model | False-positive challenges, comparisons, unknown concepts, general | Small or large; template answer without a provider |
| Classify | Low-confidence general questions | One small classification call, then re-planned |

## Providers and deployment

- **Claude API:** install `first-commit[ai]`, then use `ANTHROPIC_API_KEY` or an
  `ant auth login` profile.
  Large-tier requests use adaptive thinking with an effort level and opt into
  server-side refusal fallbacks (`fallbacks: "default"`).
- **Claude in Amazon Bedrock:** install `first-commit[ai]`, then use the standard AWS credential chain and
  `AWS_REGION`. It uses the Mantle Messages API, forced tools with thinking
  disabled (required there), no `strict`, and the SDK's client-side refusal
  fallback to `anthropic.claude-opus-4-8`.
- **Local Ollama:** `--provider ollama`, or `FIRST_COMMIT_MODEL_PROVIDER=ollama`.
  Only loopback HTTP is accepted; remote hosts, credentials in URLs and every
  `:cloud` model are rejected. The adapter checks the installed model's context
  length through `/api/show`, refuses overflow before inference, uses
  JSON-schema structured output, and reports zero API price while preserving
  call/token caps. It never downloads a model.
- **Open-model profiles:** `FIRST_COMMIT_OLLAMA_PROFILE` selects `qwen3`
  (default), `deepseek-r1`, `mistral`, `olmo2`, `gpt-oss` or `kimi`. Each maps
  the existing low/high routes to explicit local names. The first five use
  official Ollama library names. Kimi requires operator-created local aliases
  because its Ollama local entry is retired; cloud Kimi is intentionally refused.
  One profile is selected per run: the service does not fan a finding out to all
  models, which would multiply latency and create an unprincipled voting gate.
- **Model overrides:** `FIRST_COMMIT_SMALL_MODEL` and `FIRST_COMMIT_LARGE_MODEL`
  select explicit tier models. Claude accepts only models with known
  capabilities; unknown Claude models and Claude Fable 5.1 (which rejects forced
  tools) are refused. Ollama accepts an installed local model after enforcing
  endpoint, cloud-tag and context checks.
- **SAM template:** `ModelProvider` (`none` or `bedrock`) and
  `BedrockInferenceResourceArns` grant the explain worker only
  `bedrock-mantle:CreateInference` on the listed model ARNs. A template rule
  rejects an empty list when Bedrock is selected.

## Exit criteria

| Criterion | Evidence |
| --- | --- |
| Every fixture finding gets a correct, schema-valid explanation | `test_every_golden_finding_gets_a_schema_valid_grounded_explanation` |
| Malformed output is caught and retried, not accepted | `test_malformed_output_is_caught_retried_once_with_correction_then_accepted`, `test_text_only_and_truncated_responses_are_invalid_and_retried` |
| Repeated scan of unchanged content makes zero model calls | `test_repeated_scan_of_unchanged_content_makes_zero_model_calls` |
| Retry once, then human review | `test_persistent_bad_output_goes_to_human_review_and_is_not_repaid` |
| Model tiering with difficulty-based transfer | routing tests, `test_hallucinated_small_output_escalates_to_large_with_the_violations`, `test_model_escalation_moves_work_up_and_flags_prompt_injection_for_review` |
| Throttling reported separately from quota breaks | `test_budget_break_is_degraded_uncached_and_distinct_from_throttling`, `test_throttling_opens_the_breaker_and_auth_errors_stop_immediately` |
| Concurrent requests deduplicated | `test_concurrent_identical_requests_pay_once` |
| Real SDK request shapes (Claude API and Bedrock) | `test_reasoning_provider.py`, over a mock HTTP transport |

## Limits, not claimed

- No live model call was made while building this phase. Explanation quality
  from real models is unmeasured; the opt-in `test_reasoning_live.py` exercises
  it and spends real money.
- Grounding checks are pattern-based. They err toward rejection, which sends a
  unit to human review; they cannot prove every sentence true.
- Question understanding is English-only and rule-based first; unusual
  phrasings fall back to clarification or classification.
- Cloud cost estimates use Anthropic list prices; Bedrock pricing differs. Local
  Ollama reports no API charge but still consumes hardware and electricity. Haiku 4.5
  caches prompts only from 4096 tokens, so small-tier prompts usually are not
  cached.
- The explain worker is now connected to the Phase 6 scan → policy → explain workflow. Live AWS
  execution remains unverified until the SAM stack is deployed.
- Local-model output quality depends strongly on available memory and the
  selected quantization. CI verifies the adapter and safety contracts with a
  fake transport; live local quality must be measured per installed model.
