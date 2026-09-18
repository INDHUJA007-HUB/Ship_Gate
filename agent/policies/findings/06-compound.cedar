@id("compound-risk")
forbid(principal, action == Action::"process", resource)
when { resource.resourceCount >= context.compoundThreshold };
