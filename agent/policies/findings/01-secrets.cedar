@id("secret-requires-review")
forbid(principal, action == Action::"process", resource)
when { resource.category == "secret" && !resource.example };
