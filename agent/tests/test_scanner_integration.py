"""Phase 3 exit criteria against the real upstream scanners (opt-in: FIRST_COMMIT_INTEGRATION=1)."""

import os
import random
import shutil
import string
from pathlib import Path

import pytest

from agent.config import Settings
from agent.scan import ScanService

FIXTURES = Path(__file__).parents[2] / "fixtures"
real_tools = pytest.mark.skipif(
    os.getenv("FIRST_COMMIT_INTEGRATION") != "1",
    reason="requires installed Gitleaks, Semgrep and Checkov",
)
SUPPRESSED_ROLE = (
    "    Type: AWS::IAM::Role\n"
    "    Metadata:\n"
    "      checkov:\n"
    "        skip:\n"
    "          - id: CKV_AWS_111\n"
    "            comment: suppressed by the scanned repository\n"
)


def synthetic_key() -> str:
    # Generated per run and never committed. Gitleaks deliberately ignores AWS's public
    # AKIA...EXAMPLE value, so the golden fixture's static example cannot prove detection.
    alphabet = string.ascii_uppercase + "234567"
    return "AKIA" + "".join(random.SystemRandom().choice(alphabet) for _ in range(16))


def golden(tmp_path: Path, suffix: str = "") -> Path:
    root = tmp_path / "golden"
    shutil.copytree(FIXTURES / "golden-repo", root)
    (root / "src" / "credentials.py").write_text(
        f'AWS_ACCESS_KEY_ID = "{synthetic_key()}"{suffix}\n', encoding="utf-8"
    )
    return root


def summary(report):
    return sorted(
        (item.finding_type.value, item.location.path, item.evidence.detector)
        for item in report.findings
    )


@real_tools
def test_golden_fixture_returns_exactly_the_planted_findings(tmp_path):
    report = ScanService(Settings.from_env()).scan(golden(tmp_path))
    assert report.complete, report.detector_errors
    assert summary(report) == [
        ("iam_wildcard", "infra/template.yaml", "checkov"),
        ("missing_auth", "src/app.py", "first-commit-patterns"),
        ("missing_environment_variable", "src/app.py", "first-commit-patterns"),
        ("missing_input_validation", "src/app.py", "first-commit-patterns"),
        ("secret", "src/credentials.py", "gitleaks"),
    ]


@real_tools
def test_scanned_repository_cannot_blind_the_scanners(tmp_path):
    root = golden(tmp_path, "  # gitleaks:allow")
    (root / "src" / "run.py").write_text(
        "import subprocess\nsubprocess.run(command, shell=True)  # nosemgrep\n", encoding="utf-8"
    )
    (root / ".gitleaks.toml").write_text('[allowlist]\npaths = [".*"]\n', encoding="utf-8")
    (root / ".gitleaksignore").write_text("*\n", encoding="utf-8")
    (root / ".semgrepignore").write_text("*\n", encoding="utf-8")
    (root / ".checkov.yaml").write_text(
        "skip-check:\n  - CKV_AWS_108\n  - CKV_AWS_109\n  - CKV_AWS_111\n", encoding="utf-8"
    )
    template = root / "infra" / "template.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace("    Type: AWS::IAM::Role\n", SUPPRESSED_ROLE),
        encoding="utf-8",
    )
    report = ScanService(Settings.from_env()).scan(root)
    assert report.complete, report.detector_errors
    found = {item.finding_type.value: item for item in report.findings}
    assert {"secret", "iam_wildcard", "unsafe_command_execution"} <= set(found)
    assert found["iam_wildcard"].evidence.metadata["inline_suppressed_checks"] == ["CKV_AWS_111"]


@pytest.mark.parametrize("external", [False, pytest.param(True, marks=real_tools)])
def test_scan_never_executes_repository_code(tmp_path, external):
    root = golden(tmp_path)
    marker = tmp_path / "executed"
    payload = f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n"
    for name in ("setup.py", "conftest.py", "sitecustomize.py", "src/__init__.py"):
        (root / name).write_text(payload, encoding="utf-8")
    settings = Settings.from_env() if external else Settings()
    report = ScanService(settings, external_detectors=external).scan(root)
    assert report.complete, report.detector_errors
    assert not marker.exists()
