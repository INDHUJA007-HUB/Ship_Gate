"""Discover isolated project tools and user-installed Docker without global PATH writes."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def executable(name: str) -> str:
    override = os.environ.get(f"FIRST_COMMIT_{name.upper()}_BIN")
    if override:
        return override
    found = shutil.which(name)
    if found:
        return found
    root = Path(__file__).resolve().parents[1]
    suffix = ".exe" if os.name == "nt" else ""
    candidates = [
        root / ".tools" / name / (name + suffix),
        root / ".tools" / name / ("Scripts" if os.name == "nt" else "bin") / (name + suffix),
        Path(sys.executable).parent / (name + suffix),
    ]
    if name == "docker" and os.name == "nt":
        candidates.append(
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "Programs/DockerDesktop/resources/bin/docker.exe"
        )
        candidates.append(Path("C:/Program Files/Docker/Docker/resources/bin/docker.exe"))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return name


# Python tools installed into isolated `.tools/<name>` virtual environments.
PYTHON_MODULES = {"checkov": "checkov.main"}


def command(name: str) -> tuple[str, ...]:
    """Argument prefix for a scanner.

    Venv-installed Python tools run through their own interpreter. On Windows their console
    entry point is a `.cmd` shim, which cmd.exe re-parses (unsafe with untrusted paths and, for
    Checkov, it corrupted the JSON report).
    """
    override = os.environ.get(f"FIRST_COMMIT_{name.upper()}_BIN")
    if override:
        return (override,)
    module = PYTHON_MODULES.get(name)
    if module:
        venv = Path(__file__).resolve().parents[1] / ".tools" / name
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if python.is_file():
            return (str(python), "-m", module)
    return (executable(name),)


def local_environment():
    # Explicit OS essentials only. AWS profiles/tokens/proxies never enter validation workers.
    keep = {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC", "PATHEXT"}
    env = {key: value for key, value in os.environ.items() if key.upper() in keep}
    env.update(
        {
            "PATH": str(Path(executable("docker")).parent) + os.pathsep + os.defpath,
            "AWS_DEFAULT_REGION": "us-east-1",
            "AWS_REGION": "us-east-1",
            "AWS_ACCESS_KEY_ID": "localtest",
            "AWS_SECRET_ACCESS_KEY": "localtest",
            "AWS_EC2_METADATA_DISABLED": "true",
            "SAM_CLI_TELEMETRY": "0",
            "SEMGREP_SEND_METRICS": "off",
            "CHECKOV_SKIP_MAPPING": "true",
        }
    )
    return env
