"""Small, transparent product checks that complement—not replace—upstream tools."""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from agent.models import DetectorResult, FindingType, Severity
from agent.normalize import normalized_finding

PYTHON_SUFFIXES = {".py"}
DECLARATION_SUFFIXES = {".yaml", ".yml", ".json"}
ENV_PATTERN = re.compile(r"os\.environ\s*\[\s*['\"]([A-Z][A-Z0-9_]*)['\"]\s*\]")
ROUTE_PATTERN = re.compile(r"^\s*@(?:\w+\.)?(?:get|post|put|patch|delete|route)\(")
AUTH_PATTERN = re.compile(r"(?:require_auth|login_required|authorize|current_user)")
REQUEST_PATTERN = re.compile(
    r"(?:request\.(?:json|get_json|form|args)|body\s*=\s*await\s+request\.json)"
)
VALIDATION_PATTERN = re.compile(r"(?:BaseModel|validate\(|[Ss]chema\.load|jsonschema|@validate)")
DECLARED_ENV_PATTERN = re.compile(r"^\s*([A-Z][A-Z0-9_]+)\s*:", re.MULTILINE)


def _candidates(root: Path, files: Iterable[Path] | None) -> list[Path]:
    # Prefer the bounded, binary-free preflight list over a second, unbounded tree walk.
    paths = root.rglob("*") if files is None else files
    return [path for path in paths if path.is_file() and not path.is_symlink()]


def _text_files(root: Path, files: Iterable[Path] | None = None) -> list[Path]:
    return [path for path in _candidates(root, files) if path.suffix in PYTHON_SUFFIXES]


def _declared_environment(root: Path, files: Iterable[Path] | None = None) -> set[str]:
    names: set[str] = set()
    for path in _candidates(root, files):
        if path.suffix not in DECLARATION_SUFFIXES and path.name != ".env.example":
            continue
        try:
            names.update(
                DECLARED_ENV_PATTERN.findall(path.read_text(encoding="utf-8", errors="replace"))
            )
        except OSError:
            continue
    return names


def missing_environment(
    root: Path, content_hash: str, files: Iterable[Path] | None = None
) -> DetectorResult:
    files = None if files is None else tuple(files)
    declared = _declared_environment(root, files)
    findings = []
    for path in _text_files(root, files):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for number, line in enumerate(lines, start=1):
            for name in ENV_PATTERN.findall(line):
                if name not in declared:
                    findings.append(
                        normalized_finding(
                            finding_type=FindingType.MISSING_ENVIRONMENT_VARIABLE,
                            severity=Severity.MEDIUM,
                            root=root,
                            path=path,
                            line=number,
                            detector="first-commit-patterns",
                            rule_id="missing-required-environment",
                            content_hash=content_hash,
                            message=(
                                f"{name} is required at runtime but is not declared in a template "
                                "or .env.example."
                            ),
                            metadata={"environment_variable": name},
                        )
                    )
    return DetectorResult("missing-environment", tuple(findings))


def route_safety(
    root: Path, content_hash: str, files: Iterable[Path] | None = None
) -> DetectorResult:
    findings = []
    for path in _text_files(root, files):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for index, line in enumerate(lines):
            if not ROUTE_PATTERN.match(line):
                continue
            # Decorator plus its handler body, stopping at the next route decorator.
            end = next(
                (pos for pos in range(index + 1, len(lines)) if ROUTE_PATTERN.match(lines[pos])),
                len(lines),
            )
            handler = "\n".join(lines[index:end])
            line_number = index + 1
            if not AUTH_PATTERN.search(handler):
                findings.append(
                    normalized_finding(
                        finding_type=FindingType.MISSING_AUTH,
                        severity=Severity.HIGH,
                        root=root,
                        path=path,
                        line=line_number,
                        detector="first-commit-patterns",
                        rule_id="route-missing-auth",
                        content_hash=content_hash,
                        message="Route handler has no recognized authorization check.",
                    )
                )
            if REQUEST_PATTERN.search(handler) and not VALIDATION_PATTERN.search(handler):
                findings.append(
                    normalized_finding(
                        finding_type=FindingType.MISSING_INPUT_VALIDATION,
                        severity=Severity.MEDIUM,
                        root=root,
                        path=path,
                        line=line_number,
                        detector="first-commit-patterns",
                        rule_id="route-missing-input-validation",
                        content_hash=content_hash,
                        message="Route reads request input without a recognized validation step.",
                    )
                )
    return DetectorResult("route-safety", tuple(findings))
