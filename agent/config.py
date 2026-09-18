from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_files: int = 2_000
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 25 * 1024 * 1024
    max_depth: int = 30
    timeout_seconds: int = 60


@dataclass(frozen=True, slots=True)
class Settings:
    mode: str = "local"
    gitleaks_bin: str = "gitleaks"
    semgrep_bin: str = "semgrep"
    checkov_bin: str = "checkov"
    limits: ScanLimits = ScanLimits()

    @classmethod
    def from_env(cls) -> Settings:
        timeout = int(os.getenv("FIRST_COMMIT_SCAN_TIMEOUT_SECONDS", "60"))
        return cls(
            mode=os.getenv("FIRST_COMMIT_MODE", "local"),
            gitleaks_bin=os.getenv("FIRST_COMMIT_GITLEAKS_BIN", "gitleaks"),
            semgrep_bin=os.getenv("FIRST_COMMIT_SEMGREP_BIN", "semgrep"),
            checkov_bin=os.getenv("FIRST_COMMIT_CHECKOV_BIN", "checkov"),
            limits=ScanLimits(timeout_seconds=timeout),
        )


def semgrep_rules_path() -> Path:
    return Path(__file__).parent / "rules" / "semgrep.yml"
