@id("auth-requires-review")
forbid(principal, action == Action::"process", resource)
when { resource.category == "missing_auth" };
