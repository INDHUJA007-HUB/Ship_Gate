from pathlib import Path

from agent.tools.patterns import missing_environment, route_safety

GOLDEN = Path(__file__).parents[2] / "fixtures" / "golden-repo"


def test_golden_repo_has_expected_product_specific_findings() -> None:
    environment = missing_environment(GOLDEN, "hash")
    route = route_safety(GOLDEN, "hash")
    assert [finding.finding_type.value for finding in environment.findings] == [
        "missing_environment_variable"
    ]
    assert {finding.finding_type.value for finding in route.findings} == {
        "missing_auth",
        "missing_input_validation",
    }


def test_authorized_and_validated_route_is_not_flagged(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "@app.post('/photos')\n@require_auth\ndef create():\n"
        "    payload = UploadSchema.load(request.get_json())\n    return payload\n",
        encoding="utf-8",
    )
    assert not route_safety(tmp_path, "hash").findings
