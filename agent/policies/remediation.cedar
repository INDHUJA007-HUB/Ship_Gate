// The caller supplies trusted facts, never repository-controlled policy files.
@id("allow-review")
permit(principal, action == Action::"review", resource)
when { context.sameTenant && context.knownEnvironment && context.fresh };

@id("allow-proposal")
permit(principal, action == Action::"propose", resource)
when { context.sameTenant && context.knownEnvironment && context.fresh };

@id("allow-pr")
permit(principal, action == Action::"openPR", resource)
when {
    context.sameTenant && context.knownEnvironment && context.fresh &&
    context.validated && context.runtimeValidated && context.accessSafe && context.approved
};

@id("forbid-direct-mutation")
forbid(principal, action, resource)
when { action == Action::"directCommit" || action == Action::"merge" ||
       action == Action::"deploy" };

@id("forbid-untrusted-or-stale")
forbid(principal, action, resource)
unless { context.sameTenant && context.knownEnvironment && context.fresh };
