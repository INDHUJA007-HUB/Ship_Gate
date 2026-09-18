@id("production-or-conflicting-environment")
forbid(principal, action == Action::"process", resource)
when { resource has environment && resource.environment == "production" };
