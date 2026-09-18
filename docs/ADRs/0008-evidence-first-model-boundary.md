# ADR 0008: Prefer proofs and deterministic evidence; models may only escalate

## Status

Accepted.

## Context

An LLM is useful for explanation and organizing evidence, but its output is not
proof and scanned source is untrusted input. A model-generated confidence score
can be manipulated by prompt injection or change between runs.

## Decision

The gate uses the strongest available evidence in this order:

1. Formal proof when an integration can provide one (for example, IAM Access
   Analyzer `CheckNoNewAccess`).
2. Deterministic facts, such as a required environment variable being absent.
3. Versioned detector evidence and heuristics, which remain reviewable rather
   than being treated as probabilities.

The Phase 4 Cedar policy receives an `evidenceClass`, not a hand-tuned
confidence number. It can permit deterministic processing only where an
explicit policy allows it. Secrets, IAM, authentication, validation, unknown
rules, incomplete scans, and malformed context require review or are denied.

A future Phase 5 model receives structured, bounded facts only. It may write an
explanation or escalate to human review; it cannot lower a Cedar outcome or
authorize a change. Its suggestions are retained as candidate labels. A learned
classifier is deferred until there are enough reviewed labels per rule, and must
be calibrated, deterministic at inference, and use conformal abstention. An
abstention always maps to `needs_human_approval`.

## Consequences

The system produces fewer unjustified automatic decisions and preserves an
auditable explanation for every decision. It also means Phase 5 cannot be used
as a shortcut around missing detector coverage or AWS proof integrations.
