// Counts are computed and hard caps enforced in Python, not by Cedar.
@id("batch-summary-required")
forbid(principal, action == Action::"process", resource)
when { context.findingCount >= context.summaryThreshold };
