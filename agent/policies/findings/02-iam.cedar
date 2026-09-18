@id("iam-requires-review")
forbid(principal, action == Action::"process", resource)
when { resource.category == "iam_wildcard" };
