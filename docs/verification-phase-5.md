# Phase 5 verification — 2026-09-13

Environment: Windows 11, Python 3.13.14 virtual environment, `anthropic` SDK
1.5.0 (with the `bedrock` extra), cedarpy 4.8.7, Gitleaks 8.30.0, Semgrep
1.177.0, Checkov 3.3.17, SAM CLI 1.166.1, Ollama 0.34.0, Qwen3 4B and
Qwen3 8B. No cloud model, Bedrock or AWS resource was called or provisioned.

## Results

- **Full suite after the Ollama adapter:** 210 passed, 7 skipped. The skips are 5 opt-in real-tool or
  Docker tests, 1 explicitly selected live-model test, and 1 Windows symlink privilege.
  The Phase 5 Ruff check and format check are clean.
- **Phase 5 tests:** 132 cases across service, validation, contracts, questions,
  Claude/Ollama providers, cache and CLI; plus 1 opt-in live Ollama workflow test.
- **Local provider contract:** the Ollama tests prove loopback-only endpoints,
  rejection of `:cloud` tags, full JSON-schema requests, deterministic generation
  settings, model-context preflight, malformed-output handoff to the common retry
  path, zero API-price accounting with token/call caps, six profiles, and model
  overrides. They run through a fake transport and do not claim model quality.
- **Live local workflow:** the opt-in golden-repository test passed end to end
  with the installed Qwen3 4B/8B pair in 619.88 seconds. It exercised low/high
  routing, structured outputs, validation or safe human-review fallback, cache
  reuse, question answering, unchanged Cedar decisions, call bounds and a closed
  circuit. A prior run exposed an oversized 40K context allocation and timed out;
  the adapter now allocates the request-sized 1K-rounded window (13,312 tokens on
  the first large call), reducing the loaded model footprint from about 11 GB to
  7.3 GB on this host.
- **Real SDK:** Claude API and Claude in Amazon Bedrock request shapes checked
  through `anthropic` 1.5.0 over a mock HTTP transport: forced tool, `strict`
  only on the Claude API, adaptive vs disabled thinking, effort only on
  Opus-class models, cache breakpoint, `fallbacks: "default"` with its beta
  header, Bedrock SigV4 and the fallback middleware header. Eight HTTP error
  classes map to provider failure kinds. A full golden explanation run through
  the SDK made 2 HTTP calls (Haiku, then Opus) and completed.
- **SAM:** `sam validate` passes with and without `--lint` after adding the
  model-provider parameter, the conditional `bedrock-mantle:CreateInference`
  policy and the rule that rejects empty model ARNs.
- **Real-scanner regression check:** the 4 opt-in scanner integration tests pass
  (40 s). An earlier run failed once while another real-scanner job ran in
  parallel, most likely a scanner timeout under load; it passed when rerun
  alone.
- **Real CLI chain:** `scan` → `policy` → `explain` → `ask` completed with no
  provider. The chain produced 4 groups and a synthesis. Five questions
  (priorities, IAM fix, deploy readiness, an injection attempt, a
  false-positive challenge) were answered or blocked with 0 model calls and
  exit 0.

## Measured on the planted-issue fixture (scripted model)

| Measure | Value |
| --- | --- |
| Findings / groups / units | 5 / 5 / 6 (with synthesis) |
| First explanation run | 2 model calls: small 1 (2 groups), large 1 (3 groups + synthesis) |
| Estimated input tokens per call | 2,850 small, 3,958 large |
| Evidence JSON sent (small / large) | 1,342 / 2,951 characters, vs 4,951 characters of raw Phase 3+4 JSON |
| Rerun of unchanged content | 0 calls, 6 avoided |
| 15 mixed questions after explaining | 2 model calls: a false-positive challenge and a comparison |

Question handling for those 15: 5 blocked, 1 clarification, 2 deterministic,
2 synthesis, 2 explanation reuse, and 3 routed to the model path. One of those
3, a glossary concept ("What is least privilege?"), was answered from vetted
knowledge with no call.

## Not verified

- Output quality of a real Claude model, or of every supported local model other
  than the tested Qwen3 profile. Run
  `FIRST_COMMIT_LIVE_MODEL=anthropic|bedrock|ollama pytest agent/tests/test_reasoning_live.py`
  with the corresponding credentials or installed Ollama models. Cloud runs spend money.
- Bedrock IAM model ARN formats, Bedrock pricing, and real prompt-cache hit rates.
- GitHub CI and a live cloud invocation. The explain worker was subsequently connected to the
  Phase 6 Step Functions definition; see `verification-phase-6.md` for its local evidence and
  remaining live-AWS boundary.
