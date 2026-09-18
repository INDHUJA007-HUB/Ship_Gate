"""Thin parsers around upstream scanner JSON; scanner logic stays upstream."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable
from pathlib import Path

from agent.config import Settings, semgrep_rules_path
from agent.models import DetectorResult, FindingType, Severity
from agent.normalize import normalized_finding
from agent.tools.command import ToolExecutionError, ToolUnavailableError, run_tool

ToolRunner = Callable[[list[str], int, Path], object]


def _error(detector: str, error: Exception | str) -> DetectorResult:
    return DetectorResult(detector, (), str(error))


def gitleaks(root: Path, content_hash: str, settings: Settings, runner=run_tool) -> DetectorResult:
    detector = "gitleaks"
    with tempfile.TemporaryDirectory(prefix="first-commit-gitleaks-") as temporary:
        report = Path(temporary) / "report.json"
        command = [
            settings.gitleaks_bin,
            "detect",
            "--source",
            str(root),
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--no-banner",
        ]
        try:
            result = runner(command, settings.limits.timeout_seconds, root)
            # Gitleaks returns 1 when leaks are found; its report is authoritative.
            if not report.exists():
                return _error(detector, f"gitleaks did not create a JSON report: {result.stderr}")
            entries = json.loads(report.read_text(encoding="utf-8"))
        except (ToolUnavailableError, ToolExecutionError, OSError, json.JSONDecodeError) as error:
            return _error(detector, error)
    findings = tuple(
        normalized_finding(
            finding_type=FindingType.SECRET,
            severity=Severity.CRITICAL,
            root=root,
            path=entry.get("File", "unknown"),
            line=entry.get("StartLine"),
            detector=detector,
            rule_id=entry.get("RuleID", "gitleaks"),
            message=entry.get("Description", "Potential secret detected"),
            content_hash=content_hash,
            metadata={"known_example": entry.get("Secret") == "AKIAIOSFODNN7EXAMPLE"},
        )
        for entry in entries
    )
    return DetectorResult(detector, findings)


def semgrep(root: Path, content_hash: str, settings: Settings, runner=run_tool) -> DetectorResult:
    detector = "semgrep"
    command = [
        settings.semgrep_bin,
        "scan",
        "--config",
        str(semgrep_rules_path()),
        "--json",
        str(root),
    ]
    try:
        result = runner(command, settings.limits.timeout_seconds, root)
        payload = json.loads(result.stdout)
    except (ToolUnavailableError, ToolExecutionError, json.JSONDecodeError) as error:
        return _error(detector, error)
    if result.returncode not in (0, 1):
        return _error(detector, result.stderr or f"semgrep exited {result.returncode}")
    findings = []
    for entry in payload.get("results", []):
        extra = entry.get("extra", {})
        check_id = entry.get("check_id", "semgrep")
        category = {
            "first-commit.missing-auth": FindingType.MISSING_AUTH,
            "first-commit.missing-input-validation": FindingType.MISSING_INPUT_VALIDATION,
        }.get(check_id, FindingType.MISSING_INPUT_VALIDATION)
        findings.append(
            normalized_finding(
                finding_type=category,
                severity=Severity.HIGH if category == FindingType.MISSING_AUTH else Severity.MEDIUM,
                root=root,
                path=entry.get("path", "unknown"),
                line=entry.get("start", {}).get("line"),
                detector=detector,
                rule_id=check_id,
                message=extra.get("message", "Semgrep rule matched"),
                content_hash=content_hash,
            )
        )
    return DetectorResult(detector, tuple(findings))


def checkov(root: Path, content_hash: str, settings: Settings, runner=run_tool) -> DetectorResult:
    detector = "checkov"
    command = [settings.checkov_bin, "-d", str(root), "-o", "json", "--quiet"]
    try:
        result = runner(command, settings.limits.timeout_seconds, root)
        payload = json.loads(result.stdout)
    except (ToolUnavailableError, ToolExecutionError, json.JSONDecodeError) as error:
        return _error(detector, error)
    if result.returncode not in (0, 1):
        return _error(detector, result.stderr or f"checkov exited {result.returncode}")
    failed = payload.get("results", {}).get("failed_checks", [])
    findings = tuple(
        normalized_finding(
            finding_type=FindingType.IAM_WILDCARD,
            severity=Severity.HIGH,
            root=root,
            path=entry.get("file_path", "unknown").lstrip("/\\"),
            line=entry.get("file_line_range", [None])[0],
            detector=detector,
            rule_id=entry.get("check_id", "checkov"),
            message=entry.get("check_name", "IAM policy finding"),
            content_hash=content_hash,
            metadata={"resource": entry.get("resource")},
        )
        for entry in failed
        if "IAM" in entry.get("check_name", "").upper()
        or "IAM" in entry.get("check_id", "").upper()
    )
    return DetectorResult(detector, findings)
