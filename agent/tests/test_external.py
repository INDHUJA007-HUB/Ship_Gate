import json
import os
from pathlib import Path

from agent.config import Settings
from agent.tools.command import CommandResult
from agent.tools.external import checkov, gitleaks, semgrep

ROOT = Path(__file__).parents[2] / "fixtures" / "golden-repo"
TEMPLATE = (ROOT / "infra" / "template.yaml").resolve()


def test_gitleaks_normalizes_upstream_json_with_trusted_config() -> None:
    calls = []

    def runner(command, timeout, cwd):
        calls.append((command, cwd))
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
    command, cwd = calls[0]
    # Repository .gitleaks.toml, .gitleaksignore and gitleaks:allow comments are not trusted.
    assert cwd != ROOT
    assert Path(command[command.index("--config") + 1]).name == "gitleaks.toml"
    assert Path(command[command.index("--gitleaks-ignore-path") + 1]) == cwd
    assert "--ignore-gitleaks-allow" in command


def semgrep_result(*check_ids):
    payload = {
        "results": [
            {
                "check_id": check_id,
                "path": str(ROOT / "src" / "app.py"),
                "start": {"line": 9},
                "extra": {"message": "matched"},
            }
            for check_id in check_ids
        ]
    }
    calls = []

    def runner(command, timeout, cwd):
        calls.append((command, cwd))
        return CommandResult(json.dumps(payload), "", 1)

    return semgrep(ROOT, "hash", Settings(), runner=runner), calls


def test_semgrep_strips_install_prefix_and_ignores_repository_suppressions() -> None:
    result, calls = semgrep_result(
        "C.work.agent.rules.first-commit.unsafe-shell",
        "home.ci.agent.rules.first-commit.unsafe-subprocess",
    )
    assert result.error is None
    assert [
        (item.finding_type.value, item.severity.value, item.evidence.rule_id)
        for item in result.findings
    ] == [
        ("unsafe_command_execution", "high", "first-commit.unsafe-shell"),
        ("unsafe_command_execution", "low", "first-commit.unsafe-subprocess"),
    ]
    command, cwd = calls[0]
    assert cwd != ROOT
    assert {"--disable-nosem", "--x-ignore-semgrepignore-files", "--no-git-ignore"} <= set(command)


def test_semgrep_finding_ids_do_not_depend_on_install_path() -> None:
    first, _ = semgrep_result("C.one.agent.rules.first-commit.unsafe-shell")
    second, _ = semgrep_result("home.two.agent.rules.first-commit.unsafe-shell")
    assert first.findings[0].finding_id == second.findings[0].finding_id


def test_unknown_semgrep_rule_is_partial_not_mislabelled() -> None:
    result, _ = semgrep_result("first-commit.unsafe-shell", "first-commit.something-new")
    assert result.error == "unmapped semgrep rules: first-commit.something-new"
    assert [item.evidence.rule_id for item in result.findings] == ["first-commit.unsafe-shell"]


def iam_check(check_id, line=3):
    return {
        "check_id": check_id,
        "check_name": f"Ensure IAM policies are constrained ({check_id})",
        "file_line_range": [line, 20],
        "resource": "AWS::IAM::Role.UploadFunctionRole",
    }


def test_checkov_targets_files_and_reports_one_finding_per_role() -> None:
    calls = []
    lambda_check = {
        "check_id": "CKV_AWS_116",
        "check_name": "Ensure that AWS Lambda function is configured for a DLQ",
        "file_line_range": [1, 2],
        "resource": "AWS::Serverless::Function.Other",
    }

    def runner(command, timeout, cwd):
        calls.append((command, cwd))
        target = Path(command[command.index("-f") + 1])
        relative = "/" + os.path.relpath(target, cwd)  # Checkov's own path format.
        results = {
            "failed_checks": [iam_check("CKV_AWS_109", 5), iam_check("CKV_AWS_108"), lambda_check],
            "skipped_checks": [iam_check("CKV_AWS_111")],
        }
        for entries in results.values():
            for entry in entries:
                entry["file_path"] = relative
        payload = {"check_type": "cloudformation", "results": results}
        return CommandResult(json.dumps(payload), "", 1)

    result = checkov(ROOT, "hash", Settings(), runner=runner)
    assert result.error is None
    (finding,) = result.findings
    assert finding.finding_type.value == "iam_wildcard"
    assert (finding.location.path, finding.location.start_line) == ("infra/template.yaml", 3)
    assert finding.evidence.metadata == {
        "resource": "AWS::IAM::Role.UploadFunctionRole",
        "checks": ["CKV_AWS_108", "CKV_AWS_109", "CKV_AWS_111"],
        "inline_suppressed_checks": ["CKV_AWS_111"],
    }
    command, cwd = calls[0]
    # Directory mode loads a repository .checkov.yaml; --quiet hides inline suppressions.
    assert "-d" not in command and "--quiet" not in command
    assert Path(command[command.index("-f") + 1]) == TEMPLATE
    assert cwd != ROOT


def test_checkov_unrecognized_path_fails_closed() -> None:
    payload = {"results": {"failed_checks": [{**iam_check("CKV_AWS_108"), "file_path": "/x.yaml"}]}}
    result = checkov(
        ROOT, "hash", Settings(), runner=lambda *_: CommandResult(json.dumps(payload), "", 1)
    )
    assert result.error and not result.findings


def test_checkov_without_templates_starts_no_process(tmp_path) -> None:
    (tmp_path / "app.py").write_text("print('no infrastructure')\n", encoding="utf-8")

    def runner(*_):
        raise AssertionError("Checkov must not run without a template")

    result = checkov(tmp_path, "hash", Settings(), runner=runner)
    assert result.error is None and result.findings == ()
