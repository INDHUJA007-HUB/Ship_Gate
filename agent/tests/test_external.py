import json
from pathlib import Path

from agent.config import Settings
from agent.tools.command import CommandResult
from agent.tools.external import checkov, gitleaks, semgrep

ROOT = Path(__file__).parents[2] / "fixtures" / "golden-repo"


def test_gitleaks_normalizes_upstream_json() -> None:
    def runner(command, timeout, cwd):
        report = Path(command[command.index("--report-path") + 1])
        report.write_text(
            json.dumps(
                [
                    {
                        "File": str(ROOT / "src" / "secrets.py"),
                        "StartLine": 2,
                        "RuleID": "aws-access-token",
                        "Description": "AWS Access Key",
                    }
                ]
            ),
            encoding="utf-8",
        )
        return CommandResult("", "", 1)

    result = gitleaks(ROOT, "hash", Settings(), runner=runner)
    assert result.error is None
    assert result.findings[0].finding_type.value == "secret"
    assert result.findings[0].location.path == "src/secrets.py"


def test_semgrep_normalizes_upstream_json() -> None:
    payload = {
        "results": [
            {
                "check_id": "first-commit.missing-auth",
                "path": str(ROOT / "src" / "app.py"),
                "start": {"line": 9},
                "extra": {"message": "missing auth"},
            }
        ]
    }
    result = semgrep(
        ROOT, "hash", Settings(), runner=lambda *_: CommandResult(json.dumps(payload), "", 0)
    )
    assert result.error is None
    assert result.findings[0].finding_type.value == "missing_auth"


def test_checkov_normalizes_iam_finding() -> None:
    payload = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_63",
                    "check_name": "Ensure no IAM policies documents allow * as actions",
                    "file_path": "/infra/template.yaml",
                    "file_line_range": [18, 18],
                    "resource": "Role",
                }
            ]
        }
    }
    result = checkov(
        ROOT, "hash", Settings(), runner=lambda *_: CommandResult(json.dumps(payload), "", 1)
    )
    assert result.error is None
    assert result.findings[0].finding_type.value == "iam_wildcard"
