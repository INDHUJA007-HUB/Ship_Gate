from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from agent.toolchain import command


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
    gitleaks_command: tuple[str, ...] = ("gitleaks",)
    semgrep_command: tuple[str, ...] = ("semgrep",)
    checkov_command: tuple[str, ...] = ("checkov",)
    limits: ScanLimits = ScanLimits()

    @classmethod
    def from_env(cls) -> Settings:
        timeout = int(os.getenv("FIRST_COMMIT_SCAN_TIMEOUT_SECONDS", "60"))
        return cls(
            mode=os.getenv("FIRST_COMMIT_MODE", "local"),
            gitleaks_command=command("gitleaks"),
            semgrep_command=command("semgrep"),
            checkov_command=command("checkov"),
            limits=ScanLimits(timeout_seconds=timeout),
        )


RULES = Path(__file__).parent / "rules"


def semgrep_rules_path() -> Path:
    return RULES / "semgrep.yml"
