@id("high-risk-requires-review")
forbid(principal, action == Action::"process", resource)
when { (resource.severity == "high" || resource.severity == "critical") && !resource.example };

@id("eligible-static-processing")
permit(principal, action == Action::"process", resource)
when {
    resource.evidenceClass == "deterministic_fact" &&
    (resource.category == "missing_input_validation" ||
     resource.category == "missing_environment_variable")
};
