@id("command-execution-requires-review")
forbid(principal, action == Action::"process", resource)
when { resource.category == "unsafe_command_execution" };
