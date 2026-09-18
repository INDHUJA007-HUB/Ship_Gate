@id("review-supported-finding")
permit(principal, action == Action::"review", resource)
when { context.valid && context.sameTenant && context.complete && context.fresh };
