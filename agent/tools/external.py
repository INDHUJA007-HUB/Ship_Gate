"""Thin parsers around upstream scanner JSON; scanner logic stays upstream.

The scanned repository is untrusted. Every scanner runs from a trusted scratch directory with
packaged configuration, and repository-controlled config files, ignore files and inline
suppression comments are disregarded wherever the upstream tool allows it.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path

from agent.config import RULES, Settings, semgrep_rules_path
from agent.models import DetectorResult, FindingType, Severity
from agent.normalize import normalized_finding
from agent.tools.command import ToolExecutionError, ToolUnavailableError, run_tool

ToolRunner = Callable[[list[str], int, Path], object]
SEMGREP_RULES = {
    "first-commit.unsafe-shell": (FindingType.UNSAFE_COMMAND_EXECUTION, Severity.HIGH),
    "first-commit.unsafe-subprocess": (FindingType.UNSAFE_COMMAND_EXECUTION, Severity.LOW),
}
CHECKOV_SUFFIXES = {".yaml", ".yml", ".json", ".template"}
CHECKOV_BATCH = 100  # Keeps each command line far below the Windows 32K character limit.


def _error(detector: str, error: Exception | str) -> DetectorResult:
    return DetectorResult(detector, (), str(error))


def gitleaks(root: Path, content_hash: str, settings: Settings, runner=run_tool) -> DetectorResult:
    detector = "gitleaks"
    with tempfile.TemporaryDirectory(prefix="first-commit-gitleaks-") as temporary:
        workspace = Path(temporary)
        report = workspace / "report.json"
        command = [
            *settings.gitleaks_command,
            "detect",
            "--no-git",
            "--source",
            str(root),
            # Repository .gitleaks.toml, .gitleaksignore and `gitleaks:allow` cannot hide secrets.
            "--config",
            str(RULES / "gitleaks.toml"),
            "--gitleaks-ignore-path",
            str(workspace),
            "--ignore-gitleaks-allow",
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--no-banner",
        ]
        try:
            result = runner(command, settings.limits.timeout_seconds, workspace)
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
        *settings.semgrep_command,
        "scan",
        "--config",
        str(semgrep_rules_path()),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        # Repository .semgrepignore/.gitignore files and `nosemgrep` comments are untrusted.
        "--disable-nosem",
        "--x-ignore-semgrepignore-files",
        "--no-git-ignore",
        str(root),
    ]
    with tempfile.TemporaryDirectory(prefix="first-commit-semgrep-") as workspace:
        try:
            result = runner(command, settings.limits.timeout_seconds, Path(workspace))
            payload = json.loads(result.stdout)
        except (ToolUnavailableError, ToolExecutionError, json.JSONDecodeError) as error:
            return _error(detector, error)
    if result.returncode not in (0, 1):
        return _error(detector, result.stderr or f"semgrep exited {result.returncode}")
    findings, unmapped = [], set()
    for entry in payload.get("results", []):
        check_id = entry.get("check_id", "")
        # Local rule files get a machine-specific dotted-path prefix; strip it for stable IDs.
        marker = check_id.rfind("first-commit.")
        rule_id = check_id[marker:] if marker >= 0 else check_id
        if rule_id not in SEMGREP_RULES:
            unmapped.add(rule_id)
            continue
        category, severity = SEMGREP_RULES[rule_id]
        findings.append(
            normalized_finding(
                finding_type=category,
                severity=severity,
                root=root,
                path=entry.get("path", "unknown"),
                line=entry.get("start", {}).get("line"),
                detector=detector,
                rule_id=rule_id,
                message=entry.get("extra", {}).get("message", "Semgrep rule matched"),
                content_hash=content_hash,
            )
        )
    # Never guess a category: an unknown rule makes the scan partial instead of mislabelled.
    error = f"unmapped semgrep rules: {', '.join(sorted(unmapped))}" if unmapped else None
    return DetectorResult(detector, tuple(findings), error)


def _templates(root: Path, files: Iterable[Path] | None) -> list[Path]:
    found = []
    for path in root.rglob("*") if files is None else files:
        if path.suffix.lower() not in CHECKOV_SUFFIXES or path.is_symlink() or not path.is_file():
            continue
        try:
            if b"Resources" in path.read_bytes():
                found.append(path.resolve())
        except OSError:
            continue
    return sorted(found)


def _checkov_path(raw: str, workspace: Path, targets: set[Path]) -> Path | None:
    # Checkov reports target paths relative to its working directory, prefixed with a slash.
    for candidate in (workspace / raw.lstrip("/\\"), Path(raw)):
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in targets:
            return resolved
    return None


def checkov(
    root: Path,
    content_hash: str,
    settings: Settings,
    runner=run_tool,
    files: Iterable[Path] | None = None,
) -> DetectorResult:
    detector = "checkov"
    templates = _templates(root, files)
    groups: dict[tuple[Path, str], dict] = {}
    with tempfile.TemporaryDirectory(prefix="first-commit-checkov-") as temporary:
        workspace = Path(temporary)
        for start in range(0, len(templates), CHECKOV_BATCH):
            batch = templates[start : start + CHECKOV_BATCH]
            # Explicit -f targets: directory mode would load a repository `.checkov.yaml`.
            # No --quiet, so inline-suppressed IAM checks stay visible in skipped_checks.
            command = [
                *settings.checkov_command,
                *(part for path in batch for part in ("-f", str(path))),
                "-o",
                "json",
                "--framework",
                "cloudformation",
                "--skip-download",
            ]
            try:
                result = runner(command, settings.limits.timeout_seconds, workspace)
                payload = json.loads(result.stdout)
            except (ToolUnavailableError, ToolExecutionError, json.JSONDecodeError) as error:
                return _error(detector, error)
            if result.returncode not in (0, 1):
                return _error(detector, result.stderr or f"checkov exited {result.returncode}")
            for report in payload if isinstance(payload, list) else [payload]:
                results = report.get("results", {})
                for kind in ("failed_checks", "skipped_checks"):
                    for entry in results.get(kind, []):
                        check_id = entry.get("check_id", "checkov")
                        if "IAM" not in (entry.get("check_name", "") + check_id).upper():
                            continue
                        path = _checkov_path(entry.get("file_path", ""), workspace, set(batch))
                        if path is None:
                            return _error(detector, "checkov reported an unrecognized file path")
                        group = groups.setdefault(
                            (path, str(entry.get("resource") or "unknown")),
                            {"checks": set(), "suppressed": set(), "lines": []},
                        )
                        group["checks"].add(check_id)
                        if kind == "skipped_checks":
                            group["suppressed"].add(check_id)
                        line = (entry.get("file_line_range") or [None])[0]
                        if isinstance(line, int):
                            group["lines"].append(line)
    # Checkov raises several overlapping checks per role; report one finding per IAM resource.
    findings = tuple(
        normalized_finding(
            finding_type=FindingType.IAM_WILDCARD,
            severity=Severity.HIGH,
            root=root,
            path=path,
            line=min(group["lines"], default=None),
            detector=detector,
            rule_id="iam-policy-overly-permissive",
            message="IAM policy grants unconstrained access: " + ", ".join(sorted(group["checks"])),
            content_hash=content_hash,
            metadata={
                "resource": resource,
                "checks": sorted(group["checks"]),
                "inline_suppressed_checks": sorted(group["suppressed"]),
            },
        )
        for (path, resource), group in sorted(groups.items(), key=lambda item: str(item[0]))
    )
    return DetectorResult(detector, findings)
