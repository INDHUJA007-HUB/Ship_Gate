# ADR 0001: deterministic pipeline before agentic orchestration

**Status:** Accepted

Safety decisions and detector execution are deterministic workflow steps.
Agentic reasoning may later explain structured evidence, but it will not decide
whether a scanner ran, whether access is expanded, or whether a deployment is
permitted. This keeps results auditable, repeatable, and inexpensive.

