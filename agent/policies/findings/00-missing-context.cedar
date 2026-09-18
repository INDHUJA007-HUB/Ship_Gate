@id("missing-or-invalid-context")
forbid(principal, action, resource)
when {
    !(resource has environment) || !context.valid || !context.sameTenant ||
    !context.complete || !context.fresh
};
