"""Operator-only fault injection for chaos testing the pipeline's failure paths.

Faults come from a CLI flag or, in AWS, from an environment variable that the template only
sets when the `FaultInjection` parameter is enabled. They are never read from a scan request,
so a tenant cannot make another run, or their own, fail on purpose.

    crash                   raise an unclassified exception (proves unknown crashes dead-letter)
    defect                  raise DetectorDefect (unexpected detector output)
    timeout                 raise DetectorTimeout on every attempt (retries exhaust)
    unavailable             raise ToolUnavailable (operator action)
    transient[:N]           raise TransientStepError on the first N attempts, then succeed
    transient_after_write[:N]  do the real work and persist it, then fail the first N attempts
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass

from agent.orchestration.failures import (
    DetectorDefect,
    DetectorTimeout,
    ToolUnavailable,
    TransientStepError,
)

KINDS = {"crash", "defect", "timeout", "unavailable", "transient", "transient_after_write"}
SPEC = re.compile(r"(?P<step>[a-z][a-z0-9-]{0,39})=(?P<kind>[a-z_]+)(?::(?P<times>[1-9]))?")
ENABLE_VARIABLE = "FIRST_COMMIT_FAULT_INJECTION"
FAULTS_VARIABLE = "FIRST_COMMIT_FAULTS"


class InjectedCrash(RuntimeError):
    """Deliberately not a StepError: stands in for any bug nobody classified."""


@dataclass(frozen=True, slots=True)
class Fault:
    step: str
    kind: str
    times: int = 1

    def active(self, attempt: int) -> bool:
        if self.kind in {"transient", "transient_after_write"}:
            return attempt < self.times
        return True


class FaultPlan:
    def __init__(self, faults: Iterable[Fault] = ()):
        self.faults = {fault.step: fault for fault in faults}

    @classmethod
    def parse(cls, specs: Iterable[str], steps: Iterable[str]) -> FaultPlan:
        known, faults = set(steps), []
        for spec in specs:
            match = SPEC.fullmatch(spec.strip())
            if not match or match["kind"] not in KINDS or match["step"] not in known:
                raise ValueError("invalid fault specification")
            faults.append(Fault(match["step"], match["kind"], int(match["times"] or 1)))
        return cls(faults)

    @classmethod
    def from_environment(cls, steps: Iterable[str]) -> FaultPlan:
        if os.getenv(ENABLE_VARIABLE) != "enabled":
            return cls()
        specs = [part for part in os.getenv(FAULTS_VARIABLE, "").split(",") if part.strip()]
        return cls.parse(specs, steps)

    def __bool__(self) -> bool:
        return bool(self.faults)

    def describe(self) -> list[str]:
        return [f"{f.step}={f.kind}:{f.times}" for f in sorted(self.faults.values(), key=str)]

    def before(self, step: str, attempt: int) -> None:
        fault = self.faults.get(step)
        if not fault or fault.kind == "transient_after_write" or not fault.active(attempt):
            return
        if fault.kind == "crash":
            raise InjectedCrash("injected crash")
        raise {
            "defect": DetectorDefect,
            "timeout": DetectorTimeout,
            "unavailable": ToolUnavailable,
            "transient": TransientStepError,
        }[fault.kind](
            {
                "defect": "injected_defect",
                "timeout": "timeout",
                "unavailable": "tool_unavailable",
                "transient": "injected_transient",
            }[fault.kind]
        )

    def after_write(self, step: str, attempt: int) -> None:
        fault = self.faults.get(step)
        if fault and fault.kind == "transient_after_write" and fault.active(attempt):
            raise TransientStepError("injected_transient_after_write")
