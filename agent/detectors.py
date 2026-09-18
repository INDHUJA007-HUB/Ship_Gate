"""One registry of static detectors, shared by the local scan and the durable pipeline.

Each entry states which finding categories it covers, so an incomplete check can say exactly
which kinds of issue may be missing, and a fingerprint of its adapter version and packaged
rules, so a cached detector result is reused only while those are unchanged.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from agent.config import RULES, Settings, semgrep_rules_path
from agent.models import SCHEMA_VERSION, DetectorResult, FindingType
from agent.tools.external import CHECKOV_SUFFIXES, checkov, gitleaks, semgrep
from agent.tools.patterns import missing_environment, route_safety

Runner = Callable[[Path, str, tuple[Path, ...], Settings], DetectorResult]
PYTHON = frozenset({".py"})


@dataclass(frozen=True)
class Detector:
    name: str
    version: str
    categories: tuple[FindingType, ...]
    run: Runner = field(repr=False)
    external: bool = False
    # None: every repository. Otherwise the check only applies when a file has one of these.
    suffixes: frozenset[str] | None = None
    rule_files: tuple[Path, ...] = ()

    def applies(self, files: Iterable[Path]) -> bool:
        return self.suffixes is None or any(path.suffix.lower() in self.suffixes for path in files)

    @cached_property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(f"{self.name}\0{self.version}\0{SCHEMA_VERSION}".encode())
        for path in self.rule_files:
            digest.update(path.name.encode())
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        return digest.hexdigest()[:24]


DETECTORS: dict[str, Detector] = {
    detector.name: detector
    for detector in (
        Detector(
            "gitleaks",
            "gitleaks-adapter-2",
            (FindingType.SECRET,),
            lambda root, content_hash, files, settings: gitleaks(root, content_hash, settings),
            external=True,
            rule_files=(RULES / "gitleaks.toml",),
        ),
        Detector(
            "semgrep",
            "semgrep-adapter-2",
            (FindingType.UNSAFE_COMMAND_EXECUTION,),
            lambda root, content_hash, files, settings: semgrep(root, content_hash, settings),
            external=True,
            suffixes=PYTHON,  # Every packaged Semgrep rule targets Python.
            rule_files=(semgrep_rules_path(),),
        ),
        Detector(
            "checkov",
            "checkov-adapter-2",
            (FindingType.IAM_WILDCARD,),
            lambda root, content_hash, files, settings: checkov(
                root, content_hash, settings, files=files
            ),
            external=True,
            suffixes=frozenset(CHECKOV_SUFFIXES),
        ),
        Detector(
            "missing-environment",
            "patterns-2",
            (FindingType.MISSING_ENVIRONMENT_VARIABLE,),
            lambda root, content_hash, files, settings: missing_environment(
                root, content_hash, files
            ),
            suffixes=PYTHON,
        ),
        Detector(
            "route-safety",
            "patterns-2",
            (FindingType.MISSING_AUTH, FindingType.MISSING_INPUT_VALIDATION),
            lambda root, content_hash, files, settings: route_safety(root, content_hash, files),
            suffixes=PYTHON,
        ),
    )
}


def selected(external: bool = True) -> tuple[Detector, ...]:
    return tuple(d for d in DETECTORS.values() if external or not d.external)
