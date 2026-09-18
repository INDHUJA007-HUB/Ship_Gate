"""Packaging guards.

The Lambda artifact is built from `infra/template.yaml` plus `requirements.txt`, not from
`pyproject.toml`, so the two can drift apart silently. These tests make that drift fail here
instead of at runtime in a deployed function.
"""

import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]


class CfnLoader(yaml.SafeLoader):
    """CloudFormation intrinsic tags are placeholders; these tests only assert template shape."""


CfnLoader.add_multi_constructor("!", lambda loader, suffix, node: None)


def load_template() -> dict:
    return yaml.load(
        (ROOT / "infra" / "template.yaml").read_text(encoding="utf-8"), Loader=CfnLoader
    )


TEMPLATE = load_template()
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

# Provided by the Lambda runtime image, so the manifest must not pin them.
RUNTIME_PROVIDED = {"boto3", "botocore", "s3transfer", "jmespath"}


def requirement_name(line: str) -> str | None:
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    return re.split(r"[<>=!~\[\s;(]", line, maxsplit=1)[0].strip().lower().replace("_", "-")


def manifest_names() -> set[str]:
    lines = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    return {name for name in map(requirement_name, lines) if name}


def functions() -> dict:
    return {
        name: resource
        for name, resource in TEMPLATE["Resources"].items()
        if resource.get("Type") == "AWS::Serverless::Function"
    }


def test_runtime_pin_is_not_weakened_to_match_a_developer_host():
    assert TEMPLATE["Globals"]["Function"]["Runtime"] == "python3.12"
    assert TEMPLATE["Globals"]["Function"]["Architectures"] == ["x86_64"]


def test_every_function_builds_in_the_container_image_for_its_runtime():
    """A native build on a newer host interpreter ships wheels the runtime cannot import."""
    default = TEMPLATE["Globals"]["Function"]["Runtime"]
    for name, resource in functions().items():
        runtime = resource.get("Properties", {}).get("Runtime", default)
        assert resource.get("Metadata", {}).get("BuildMethod") == runtime, name


def test_lambda_manifest_covers_every_runtime_and_provider_dependency():
    declared = {requirement_name(item) for item in PYPROJECT["project"]["dependencies"]}
    provider = {
        requirement_name(item) for item in PYPROJECT["project"]["optional-dependencies"]["ai"]
    }
    missing = (declared | provider) - manifest_names() - RUNTIME_PROVIDED
    assert not missing, f"requirements.txt must declare {sorted(missing)}"


def test_manifest_does_not_pin_runtime_provided_packages():
    assert manifest_names().isdisjoint(RUNTIME_PROVIDED)


def test_functions_share_one_buildable_codeuri():
    for name, resource in functions().items():
        assert resource["Properties"]["CodeUri"] == "../", name
        assert not Path(resource["Properties"]["Handler"].replace(".", "/")).is_absolute()
