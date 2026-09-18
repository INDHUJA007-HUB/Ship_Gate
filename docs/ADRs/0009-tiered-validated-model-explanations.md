# ADR 0009: Tiered, validated, cached model explanations

Status: Accepted. Date: 2026-09-13.

## Context

Phase 5 adds model-written explanations and question answering on top of the
ADR 0008 boundary. Model output can be malformed, hallucinated, manipulated by
repository text or questions, refused, throttled or expensive. Claude in Amazon
Bedrock does not support structured outputs, and no provider enforces lengths,
counts or patterns.

## Decision

1. **Deterministic first.** A scored, recorded router chooses a vetted template
   (no call), a small model (`claude-haiku-4-5`) or a large model
   (`claude-opus-5`). A provider may map these logical tiers to reviewed local
   models without changing router authority. Denied groups and blocked, policy, readiness and glossary
   questions never call a model. Models may only escalate a unit up one tier.
2. **One template, minimal context.** A frozen system prompt forms the cacheable
   prefix. The user message contains only the situation modules, category
   guidance and glossary entries that apply, plus compact JSON facts with short
   refs. Groups on the same tier share one call.
3. **Enforced output, then independent validation.** Every request forces a tool
   (`strict` on the Claude API). Every response is validated locally against the
   full schema and then against grounding rules: refs, paths, lines, identifiers,
   secrets, policy-overriding claims, unsafe advice and required steps.
4. **Retry once, then human review.** A failed unit gets exactly one corrective
   retry on the large tier with its violation codes. A second failure yields the
   vetted template marked `needs_human_review`. That result is cached, so
   unchanged evidence never re-spends.
5. **Content-hash cache with leases.** Keys cover tenant, evidence facts and every
   version that shapes output. All-or-none leases stop concurrent twins from
   paying twice.
6. **Explicit budgets.** Worst-case cost is reserved before each call. A budget
   stop, a transient provider failure and a misconfiguration are reported
   distinctly; degraded results are never cached.
7. **Safe defaults.** The provider defaults to `none`. Large-tier Claude API
   requests opt into refusal fallbacks; Bedrock uses the SDK's client-side
   fallback. Unknown Claude models are refused. Local models follow the tighter
   endpoint, cloud-tag and context rules in ADR 0010.

## Consequences

- A typical scan costs at most one small and one large call, plus one corrective
  retry when needed; a rescan of unchanged content costs zero.
- Pattern-based grounding errs toward human review. Some acceptable phrasing
  will be rejected, and each rejection is visible in the attempt records.
- Explanation quality depends on the model, and must be measured with the
  opt-in live test and reviewed labels before any claim beyond validity is made.
- The retained attempts and model escalations are the candidate labels ADR 0008
  anticipates for a future calibrated classifier.
