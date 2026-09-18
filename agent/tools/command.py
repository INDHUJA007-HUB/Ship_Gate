from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class CommandResult:
    stdout: str
    stderr: str
    returncode: int


class ToolUnavailableError(RuntimeError):
    pass


class ToolExecutionError(RuntimeError):
    pass


class ToolTimeoutError(ToolExecutionError):
    pass


def run_tool(command: list[str], timeout_seconds: int, cwd: Path) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )
    except FileNotFoundError as error:
        raise ToolUnavailableError(f"scanner executable not found: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise ToolTimeoutError(
            f"scanner timed out after {timeout_seconds}s: {command[0]}"
        ) from error
    return CommandResult(completed.stdout, completed.stderr, completed.returncode)
