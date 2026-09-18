"""Run only the packaged, trusted smoke harness. Never invoke submitted repository code."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuntimeResult:
    status: str
    checks: tuple[str, ...]
    errors: tuple[str, ...]
    scope: str = "packaged_smoke_harness_only_not_user_application_or_aws_iam"

    def to_dict(self):
        return asdict(self)


def validate_runtime() -> RuntimeResult:
    """Fixed commands, trusted template, finite deadlines, no submitted test commands."""
    missing = tuple(tool for tool in ("sam", "docker") if shutil.which(tool) is None)
    if missing:
        return RuntimeResult("blocked", (), tuple(f"missing_dependency:{tool}" for tool in missing))
    harness = Path(__file__).parent / "harness"
    checks = []
    commands = [
        ("docker_engine", ["docker", "info", "--format", "{{.ServerVersion}}"]),
        (
            "sam_template",
            [
                "sam",
                "validate",
                "--template",
                str(harness / "template.yaml"),
                "--region",
                "us-east-1",
            ],
        ),
        (
            "sam_smoke",
            [
                "sam",
                "local",
                "invoke",
                "SmokeFunction",
                "--template",
                str(harness / "template.yaml"),
                "--event",
                str(harness / "event.json"),
                "--region",
                "us-east-1",
            ],
        ),
    ]
    for name, command in commands:
        try:
            result = subprocess.run(
                command,
                cwd=harness,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                shell=False,
            )
            if result.returncode:
                return RuntimeResult("failed", tuple(checks), (f"{name}:nonzero_exit",))
            if name == "sam_smoke" and json.loads(result.stdout).get("statusCode") != 200:
                return RuntimeResult("failed", tuple(checks), ("unexpected_smoke_response",))
            checks.append(name)
        except subprocess.TimeoutExpired:
            return RuntimeResult("timed_out", tuple(checks), (f"{name}:timeout",))
        except (OSError, ValueError):
            return RuntimeResult("failed", tuple(checks), (f"{name}:invalid_response",))
    return RuntimeResult("passed", tuple(checks), ())
