# ADR 0011: durable Standard workflow and checkpointed resume

Status: accepted

## Context

A scan fans out to independent native tools and may outlast one Lambda invocation or one HTTP
request. AWS services deliver work at least once, scanners can time out independently, and a
model provider can be unavailable after the deterministic findings already exist. Restarting
the entire scan wastes compute and can duplicate findings or model charges.

The original sketch named Step Functions Express. Express has a five-minute execution limit and
does not provide the durable execution history and redrive behavior this review-oriented workflow
needs. A repository scan can legitimately exceed that duration.

## Decision

- Use one versioned Amazon States Language definition for both environments. AWS deploys it to
  Step Functions Standard; local mode executes the supported JSONPath subset in process.
- Use independent `Prepare`, detector `Map`, `Merge`, `Explain`, and `Finalize` tasks. A separate
  incident task records detector and pipeline failures.
- Key snapshots and detector checkpoints by tenant, content hash, detector fingerprint, and
  pipeline generation. Finding IDs are content-derived and writes are conditional/write-once.
- Retry only classified transient failures with bounded exponential backoff and jitter. A
  detector defect, unavailable tool, or exhausted timeout becomes an incomplete check and a
  durable review item. Invalid input is rejected without retry.
- Preserve successful detector results when another detector fails. Cedar receives the partial
  report and fails closed; the final result names both completed and missing coverage.
- Resume under a bounded new generation. Completed detector checkpoints are reused; recovered
  checks resolve their older review records without deleting audit history.
- A failed, timed-out, or aborted workflow is reconciled by an EventBridge status handler so a
  run cannot remain `running`. If EventBridge omits the input, the handler uses
  `DescribeExecution` against the exact execution ARN.
- Keep orchestration decisions separate from security decisions. Strands may select a pipeline
  tool, but cannot alter findings or Cedar outcomes. A deterministic planner handles clear
  requests with zero model calls; ambiguous requests have a hard one-call agent budget.

## Consequences

- Standard workflow state transitions cost more than Express transitions, but long-run safety,
  execution history, and redrive are the stronger requirements.
- Local behavior is reproducible without a cloud account, but the small local ASL interpreter
  intentionally rejects any definition feature it does not implement. Adding a new ASL feature
  requires a parity test before deployment.
- S3 stores potentially large immutable artifacts; Step Functions carries only compact pointers
  and summaries, keeping the 256 KiB state limit away from repository data.
- Review queue delivery is at least once. FIFO deduplication and deterministic review IDs prevent
  duplicate notifications, while consumers must re-read the durable record before acting.

