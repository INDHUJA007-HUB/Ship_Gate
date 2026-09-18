@id("known-example-in-documentation")
permit(principal, action == Action::"process", resource)
when { resource.category == "secret" && resource.example && resource.confidence >= 90 };
