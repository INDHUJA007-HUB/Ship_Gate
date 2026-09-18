# Build Sequence — Sequential Implementation Phases

Pure technical build order, no calendar, no team split — just the sequence in which the system actually gets constructed, with each phase detailed enough to design around real failure modes, not just the happy path.

---

## Phase 1 — Foundation & Environment

**Objective:** a working local dev loop before any real feature exists.

- Repo scaffold: `agent/`, `api/`, `web/`, `infra/`, `policies/`, `fixtures/`, `docs/`.
- `infra/template.yaml`: Lambda functions, API Gateway, DynamoDB table, S3 bucket, Step Functions state machine, EventBridge rule, Cognito user pool — all parameterized so the same template targets LocalStack or real AWS via one variable, not two templates that drift apart.
- One Lambda per responsibility from the start (scan-worker, explain-worker, deploy-worker, api-handler), each with its **own** IAM role defined explicitly in the template — not a shared execution role. Retrofitting per-function least privilege later means re-auditing every function at once instead of getting each one right as it's written.
- Local dev loop: `sam local start-api` against LocalStack, hot-reload where possible.
- CI: lint + unit test on every commit, even solo — it catches regressions from a change made an hour ago, not a bug hunt three phases later.

**Complex problem to design for now, not later:** environment parity drift. LocalStack doesn't perfectly emulate every AWS service (X-Ray support in particular is inconsistent across versions/tiers — confirm this early, not when the debug-companion phase needs it). Decide now which components get a "local-emulated" path and which get a "local-mocked-with-fixture-data" path, and record that decision — silently discovering the gap mid-build is far more expensive than deciding for it up front.

**Exit criteria:** a request round-trips through every planned layer with stub responses, against LocalStack.

---

## Phase 2 — Domain Model & Data Layer

**Objective:** the shapes everything else builds on.

- Core entities: `Scan` (repo reference, status, timestamps), `Finding` (type, severity, location, evidence, explanation, fix status), `Policy` (the Cedar rule that produced a finding), `DeploymentAttempt` (target, status, rollback state).
- DynamoDB table design: single-table where it earns its keeping (findings and scans share access patterns — scan_id as partition key, finding_id/timestamp as sort key), on-demand capacity.
- Every write is **idempotent** from day one: a scan re-run on unchanged content should not create duplicate findings. Use a content hash (repo commit SHA + file hash) as part of the key, not an auto-incrementing ID — this alone prevents a whole category of "why do I have three copies of this finding" bugs later.

**Complex problem:** concurrent writes. If a scan pipeline retries a failed step (see Phase 6), a naive design double-writes findings. Conditional writes (`ConditionExpression` on a deterministic key) make retries safe by construction instead of requiring cleanup logic after the fact.

**Exit criteria:** schema documented, a hand-written test proves a re-run of the same input produces no duplicate rows.

---

## Phase 3 — Ingestion & Static Analysis Engine

**Objective:** turn an arbitrary, untrusted repo into structured findings, safely.

- Accept a repo two ways: a Git URL (clone) or a zip upload. Both paths converge on the same normalized file tree before analysis.
- Detectors, each independent and independently testable: secret/credential patterns, IAM-shape parsing (wildcard `Action`/`Resource` in inline policies or IaC templates), missing-auth-check heuristics on route handlers, missing-input-validation heuristics.
- Wrap known-good open detection patterns for the well-solved parts (secret detection) rather than reinventing entropy analysis from scratch — the differentiated engineering effort belongs in the parts nobody else does (Cedar evaluation, least-privilege remediation, traced root-cause), not in re-solving secret scanning.

**Complex problems this phase has to actually solve, because the input is untrusted and unbounded:**
- **Never execute the scanned code.** Every detector is static analysis only — parsing, not running. A repo could contain anything; the scanning environment must be incapable of being made to run it.
- **Resource exhaustion from adversarial or accidental input.** A huge repo, a deeply nested directory tree, a binary masquerading as source, a zip bomb. Enforce hard limits before analysis starts: max file count, max individual file size, max total decompressed size, a wall-clock timeout on the whole scan — and fail with a clear "scan too large" result rather than a Lambda timeout that looks like a bug.
- **Isolation of the analysis environment itself.** Run the scan worker with the narrowest IAM role and network access it can function with (in the real-AWS phase, no outbound network access unless a specific detector genuinely needs it) — the scanner processing untrusted code is itself an attack surface, and should be treated with the same rigor the product asks of its users.
- **Encoding and binary content.** Don't assume UTF-8 or text; detect and skip binary files rather than crashing on them.

**Exit criteria:** the scanner runs against the planted-issue test fixture and returns exactly the expected findings — and separately, runs against a deliberately hostile fixture (huge file, binary file, deeply nested tree) without crashing, hanging, or executing anything.

---

## Phase 4 — Policy Engine (Cedar)

**Objective:** findings get evaluated against declarative, auditable rules — not hardcoded conditionals.

- One Cedar policy per check category, each expressing a permit/deny/severity decision over the structured facts Phase 3 produces.
- Policies are versioned, human-readable, and testable independently of the scanner that feeds them — a policy change should be reviewable as a diff, the way an access-control change would be anywhere else.

**Complex problem:** policy conflicts and precedence. As the rule set grows past the first handful, two policies can legitimately disagree about a borderline case. Decide the conflict-resolution model explicitly (most-specific-wins, or an explicit deny-overrides-permit ordering) rather than letting it fall out of evaluation order by accident — write this down as a real design decision, since "why did policy X win over policy Y" is exactly the kind of question a judge or a future maintainer  will ask.

**Exit criteria:** every finding from Phase 3's fixtures gets a correct, explainable decision; a hand-written conflicting-policy test proves the precedence rule actually holds.

---

## Phase 5 — AI Reasoning Layer

**Objective:** turn structured findings into a correct, readable, plain-language explanation — reliably, not just usually.

- One prompt template taking Phase 3 + Phase 4's structured output as input — never raw, unstructured code dumped into a prompt. A structured, evidence-first prompt is both cheaper (less context) and more reliable (less for the model to misinterpret) than an open-ended one.
- Model tiering: a small/cheap model for any bulk classification-shaped calls, a stronger model reserved for the final explanation synthesis — this is a cost decision made *in* the architecture, not bolted on afterward.
- Enforce structured output (a JSON schema the model must conform to, via tool-calling/function-calling constraints where the model provider supports it) rather than trusting free-text and hoping it parses.

**Complex problems specific to an LLM in the loop:**
- **Hallucinated or malformed output.** Validate every model response against the expected schema; on a validation failure, retry once with a corrective prompt, then fail loudly into a "needs human review" state — never silently pass through unvalidated model output as a "finding."
- **Cost/quota exhaustion.** Cache explanations by content hash (Phase 2's idempotency key) so re-scanning unchanged code never re-spends a model call. Add a circuit breaker that stops calling the model and surfaces a clear degraded-mode message if quota or budget limits are hit mid-run, rather than failing opaquely mid-pipeline.
- **Non-determinism.** The same finding can get slightly different wording on different runs — fine for prose, not fine if downstream logic parses the explanation text. Keep the machine-readable decision (from Phase 4) and the human-readable explanation (from this phase) as separate fields; nothing downstream should ever parse the prose.

**Exit criteria:** every fixture finding gets a correct, schema-valid explanation; a deliberately malformed model response is caught and retried rather than silently accepted; a repeated scan of unchanged content produces zero new model calls.

---

## Phase 6 — Orchestration Layer

**Objective:** the agent and pipeline survive partial failure instead of requiring a clean run every time.

- A single orchestrating agent (Strands) decides which tool to invoke and in what order, backed by a Step Functions state machine for the parts that need durable, resumable execution (a long-running scan shouldn't restart from zero if one step fails).
- Each state is idempotent (Phase 2/5's keys make this possible) so a retry is safe by construction.
- Explicit error handling per state: which failures retry automatically (transient network/throttling), which route to a dead-letter path for human review (a detector crash on unexpected input), which fail the whole scan cleanly with a clear reason (invalid repo, size limit exceeded).

**Complex problem:** partial results. If three of four detectors succeed and one times out, the system should surface the three real findings with a clear "one check didn't complete" flag — not discard everything because one component had a bad run, and not silently pretend the run was complete.

**Exit criteria:** a deliberately-failing detector (inject a fault) still produces a partial, clearly-labeled result rather than an opaque total failure; a transient-failure injection proves the retry path works without duplicating findings.

---

## Phase 7 — Least-Privilege Remediation Engine

**Objective:** turn a finding into a real, usable fix — most concretely, a scoped IAM policy in place of a wildcard one.

- Integrate AWS IAM Access Analyzer's policy-generation flow (`start_policy_generation` / `get_generated_policy`) against the actual role in question, rendered as a before/after diff.

**Complex problem, and it's a real one:** Access Analyzer generates a policy from **observed access activity** (via CloudTrail) — a role with no activity history yet has nothing to generate a meaningful policy from. A freshly-scanned or freshly-deployed target won't have this history by default. Design around it explicitly: either (a) drive a representative burst of real traffic against the target before requesting generation, and say so in the UI ("analyzing recent activity — run your app a few times first"), or (b) fall back to a static, rule-derived scoped policy (built from what the code's own calls indicate it needs, from Phase 3's parse) when no activity history exists yet, and label which method produced which recommendation. Don't present a static guess and a real activity-based policy identically — the user needs to know which one they're looking at.

**Exit criteria:** the tool correctly distinguishes "generated from real activity" vs. "estimated from static analysis" results, and both paths produce a policy strictly narrower than the original.

---

## Phase 8 — Local Validation Layer

**Objective:** a proposed fix gets proven, not just suggested, before it's allowed near real infrastructure.

- Replay the fixed version against LocalStack: deploy succeeds, a smoke-test request returns the expected result.

**Complex problem:** a fix that validates locally can still fail against real AWS due to LocalStack's emulation gaps (IAM enforcement in particular is often looser locally than in production). Treat local validation as a necessary-but-not-sufficient gate — it catches obvious breakage cheaply, but the guided real deploy (Phase 9) still needs its own smoke test against the real target, not just trust in the local pass.

**Exit criteria:** a fix that breaks the app fails local validation and is blocked from proceeding; a fix that works passes and is queued for real deployment.

---

## Phase 9 — Deployment Automation Layer

**Objective:** get the fixed application onto real AWS safely, with a way back out.

- Deploy via CloudFormation change sets (through SAM), not a blind `sam deploy` — a change set can be reviewed before it's applied, and gives a concrete rollback target if something goes wrong.
- Keep a human confirmation checkpoint before any change touches real infrastructure, even for high-confidence fixes — auto-apply means auto-*propose*, not auto-*deploy*.

**Complex problem:** partial deploy failure. A multi-resource CloudFormation stack can fail halfway through an update, leaving the stack in a mixed state. Rely on CloudFormation's own automatic rollback-on-failure behavior rather than building custom rollback logic, and surface the rollback outcome clearly to the user rather than leaving them staring at a stuck "updating" status.

**Exit criteria:** a deliberately-broken deploy (bad resource config) rolls back cleanly and reports why; a good deploy completes and is smoke-tested automatically afterward, not just assumed to have worked because CloudFormation said `UPDATE_COMPLETE`.

---

## Phase 10 — Observability & Debug-Companion

**Objective:** trace a live failure in a deployed app back to root cause, using real evidence instead of a guess.

- Enable X-Ray tracing on every Lambda and API Gateway stage the product touches; enable it on the demo target app too.
- On an error, pull the trace (which hop failed) and a scoped CloudWatch Logs Insights query (that trace ID's window only, not a broad log scan) as structured evidence, then make one high-context model call for the explanation — reusing the reliability patterns from Phase 5.

**Complex problem:** X-Ray sampling. By default, X-Ray doesn't trace every request — it samples. A debug-companion tool that occasionally has "no trace found" for a real error looks broken in a demo and is unreliable in general use. Set an explicit 100%-sampling rule on the target application's X-Ray configuration rather than relying on the default sampling rate, and document that this is a deliberate choice suited to a low-traffic debugging tool, not a decision that would hold at production scale for a high-traffic service.

**Exit criteria:** a deliberately-triggered error in the target app is traced to the correct root cause every time, not intermittently.

---

## Phase 11 — API & Frontend

**Objective:** the whole pipeline becomes usable, not just runnable.

- Thin API layer: request handlers that validate input and delegate to the agent — no business logic living in the API layer itself.
- Dashboard: connect/upload a repo, see findings with explanations, see the fix diff, trigger validation and deploy, see the debug-companion trace when relevant.

**Complex problem:** long-running operations behind a synchronous-feeling UI. A scan or a deploy can take real time — don't block an HTTP request on it. Kick off the Step Functions execution, return an execution ID immediately, and have the frontend poll (or subscribe via a lightweight mechanism) for status — a UI that hangs on a 30-second request reads as broken even when the backend is working correctly.

**Exit criteria:** the full user journey (connect → findings → fix → validate → deploy → trace) works through the UI alone, with visible progress at every long-running step.

---

## Phase 12 — Security & Multi-Tenancy Hardening

**Objective:** the product's own claims about least privilege and safe handling apply to itself, not just to what it analyzes.

- Every credential in Parameter Store, never in code or environment files committed to the repo.
- If team/multi-user accounts exist: Cedar governs who can view findings vs. apply a fix vs. trigger a deploy, enforced at the API layer on every request, not just hidden in the UI.
- Data isolation: a user's scans and findings are only ever queryable by that user's own partition key — verify this with a test that actively tries to read another user's data and confirms it's rejected, not just assumed to be safe because the query "shouldn't" allow it.

**Complex problem:** the auto-apply PR flow needs its own least-privilege story. A GitHub integration token should be scoped to exactly what it needs (open a PR, nothing more) — the same discipline the product enforces on AWS IAM applies to this credential too, and it's worth stating that explicitly, since it's a strong internal-consistency point.

**Exit criteria:** a deliberate cross-tenant read attempt fails; running the product's own scanner against its own repo turns up nothing it wouldn't accept from a stranger's submission.

---

## Phase 13 — Testing & Quality Assurance

**Objective:** confidence that the system is correct, not just that it ran once successfully.

- Unit tests per detector, per Cedar policy, per tool — each independently, with both a "should trigger" and a "should not false-positive" case.
- Integration tests for the full pipeline against LocalStack, using the planted-issue fixture plus the hostile-input fixture from Phase 3.
- One true end-to-end test against real AWS: scan → fix → validate → deploy → trace, run as an automated check, not just a manual demo run-through.
- A chaos pass: deliberately inject a failure at each stage (detector crash, model timeout, deploy failure, missing trace) and confirm Phase 6's partial-failure handling holds in each case, not just in the one scenario it was written for.

**Exit criteria:** the full test suite passes; the chaos pass confirms graceful degradation at every injected failure point, not just success on the happy path.

---

## Phase 14 — Hardening & Submission Packaging

**Objective:** the system as it will actually be judged, not as it exists mid-refactor.

- Final pass against every fixture, plus a fresh real-world repo it hasn't seen before, to catch overfitting to the test data.
- Architecture and cost documentation reflects what was actually built, including the fallback decisions made along the way (Phase 1's LocalStack/X-Ray gap, Phase 7's activity-history fallback, Phase 12's token scoping) — these decisions are themselves evidence of engineering judgment, worth stating rather than hiding.
- Full smoke test across every real AWS service in use, budget spend checked against expectations.

**Exit criteria:** the system runs cleanly, unattended, start to finish, against an unfamiliar input — the actual bar a demo needs to clear.
