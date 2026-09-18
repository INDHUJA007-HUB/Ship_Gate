"""Bounded JSON/SAM YAML IAM extraction with explicit supported formats."""

import copy
import json

import yaml


def load_document(text):
    if len(text.encode("utf-8")) > 2 * 1024 * 1024:
        raise ValueError("document_too_large")
    # Reject aliases; CloudFormation intrinsic tags require an explicit future resolver.
    for event in yaml.parse(text):
        if isinstance(event, yaml.AliasEvent) or getattr(event, "tag", None):
            raise ValueError("yaml_aliases_or_intrinsics_unsupported")
    document = yaml.safe_load(text)
    if not isinstance(document, dict):
        raise ValueError("document_must_be_object")
    return document


def identity_policy(document):
    if "Statement" in document:
        return (), document
    found = []
    for name, resource in document.get("Resources", {}).items():
        if resource.get("Type") != "AWS::IAM::Role":
            continue
        for index, policy in enumerate(resource.get("Properties", {}).get("Policies", [])):
            if "PolicyDocument" in policy:
                found.append(
                    (
                        ("Resources", name, "Properties", "Policies", index, "PolicyDocument"),
                        policy["PolicyDocument"],
                    )
                )
    if len(found) != 1:
        raise ValueError("exactly_one_inline_identity_policy_required")
    return found[0]


def replace_policy(document, selector, policy):
    if not selector:
        return policy
    result = copy.deepcopy(document)
    node = result
    for part in selector[:-1]:
        node = node[part]
    node[selector[-1]] = policy
    return result


def serialize(document, suffix):
    if suffix == ".json":
        return json.dumps(document, indent=2, sort_keys=True) + "\n"
    return yaml.safe_dump(document, sort_keys=False)
