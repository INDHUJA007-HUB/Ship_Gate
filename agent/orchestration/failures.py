"""Failure taxonomy: every step failure has exactly one disposition.

retry     transient (throttling, network, a timeout that may clear): retried with backoff
review    defect (a detector crash or unexpected output): never retried, dead-lettered for a person
operator  configuration (a scanner is not installed): never retried, dead-lettered for an operator
reject    invalid input (bad repository, size limit): the whole scan fails cleanly with a reason

Exception class names are the Step Functions error names the state machine retries and catches
on, so renaming one is a contract change. Messages are always a safe reason code: Lambda puts
the message in the execution history, and raw exception text can quote scanned source.
"""

from __future__ import annotations

import json
import re

CODE = re.compile(r"[a-z][a-z0-9_]{0,47}")
ERROR_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.]{0,63}")


def safe_code(value: object, default: str = "unclassified") -> str:
    return value if isinstance(value, str) and CODE.fullmatch(value) else default


class StepError(Exception):
    disposition = "review"

    def __init__(self, code: str):
        self.code = safe_code(code)
        super().__init__(self.code)


class TransientStepError(StepError):
    disposition = "retry"


class DetectorTimeout(StepError):
    disposition = "retry"


class DetectorDefect(StepError):
    disposition = "review"


class PipelineDefect(StepError):
    """The pipeline's own contract broke: a malformed payload, a lost checkpoint."""

    disposition = "review"


class UnexpectedStepError(StepError):
    """An unclassified exception, re-raised without its text so no source reaches history."""

    disposition = "review"


class ToolUnavailable(StepError):
    disposition = "operator"


class ScanRejected(StepError):
    disposition = "reject"


DETECTOR_FAILURES: dict[str, type[StepError]] = {
    "timeout": DetectorTimeout,
    "io_error": TransientStepError,
    "tool_unavailable": ToolUnavailable,
    "tool_failed": DetectorDefect,
    "malformed_output": DetectorDefect,
    "missing_report": DetectorDefect,
    "unmapped_rule": DetectorDefect,
    "unrecognized_output": DetectorDefect,
    "crashed": DetectorDefect,
}


def detector_failure(code: str) -> StepError:
    return DETECTOR_FAILURES.get(code, DetectorDefect)(code)


# Ingestion and preflight raise fixed messages (agent/ingest.py, agent/preflight.py). Unknown
# messages fall through to `invalid_source`, which still fails the scan cleanly.
REJECTIONS: tuple[tuple[str, type[StepError], str], ...] = (
    ("source changed during preflight", TransientStepError, "source_changed"),
    ("unable to read", TransientStepError, "source_unreadable"),
    ("git host could not be resolved", TransientStepError, "repository_unreachable"),
    ("git clone failed", TransientStepError, "repository_unavailable"),
    ("git is unavailable", ToolUnavailable, "git_unavailable"),
    ("git clone exceeded the size limit", ScanRejected, "size_limit_exceeded"),
    ("git clone timed out", ScanRejected, "repository_clone_timeout"),
    ("git clone produced no readable revision", ScanRejected, "repository_invalid"),
    ("non-public address", ScanRejected, "repository_address_rejected"),
    ("git url", ScanRejected, "repository_url_rejected"),
    ("maximum file count", ScanRejected, "file_count_exceeded"),
    ("entry count", ScanRejected, "file_count_exceeded"),
    ("individual file size", ScanRejected, "file_size_exceeded"),
    ("total size", ScanRejected, "size_limit_exceeded"),
    ("directory depth", ScanRejected, "depth_limit_exceeded"),
    ("linked files", ScanRejected, "links_not_supported"),
    ("special files", ScanRejected, "special_files_not_supported"),
    ("timed out", ScanRejected, "preflight_timeout"),
    ("compression ratio", ScanRejected, "archive_rejected"),
    ("archive", ScanRejected, "archive_rejected"),
    ("zip", ScanRejected, "archive_rejected"),
    ("must be a directory", ScanRejected, "invalid_source"),
)


def ingestion_failure(error: Exception) -> StepError:
    message = str(error).casefold()
    for fragment, kind, code in REJECTIONS:
        if fragment in message:
            return kind(code)
    return ScanRejected("invalid_source")


# How a Step Functions error name (from a Catch) maps to a dead-letter disposition.
RETRY_EXHAUSTED = {
    "TransientStepError",
    "DetectorTimeout",
    "States.Timeout",
    "States.HeartbeatTimeout",
    "Sandbox.Timedout",
    "Lambda.ServiceException",
    "Lambda.AWSLambdaException",
    "Lambda.SdkClientException",
    "Lambda.TooManyRequestsException",
}
OPERATOR = {"ToolUnavailable", "States.Permissions"}


def disposition(error_name: str) -> str:
    if error_name in RETRY_EXHAUSTED:
        return "retry_exhausted"
    if error_name in OPERATOR:
        return "operator_action"
    return "human_review"  # DetectorDefect, PipelineDefect and any unexpected exception.


STEP_ERRORS = {
    cls.__name__
    for cls in (
        TransientStepError,
        DetectorTimeout,
        DetectorDefect,
        PipelineDefect,
        UnexpectedStepError,
        ToolUnavailable,
        ScanRejected,
    )
}


def reason_from_error(error: dict | None) -> tuple[str, str]:
    """(error name, reason code) from a Catch output, never copying free text."""
    error = error if isinstance(error, dict) else {}
    name = error.get("Error")
    name = name if isinstance(name, str) and ERROR_NAME.fullmatch(name) else "UnknownError"
    code = None
    if name in STEP_ERRORS and isinstance(error.get("Cause"), str):
        # Lambda serializes {"errorMessage", "errorType", ...}. Only our own classes carry a
        # message that is known to be a code; any other exception text is discarded.
        try:
            parsed = json.loads(error["Cause"])
            code = parsed.get("errorMessage") if isinstance(parsed, dict) else None
        except ValueError:
            code = error["Cause"]
    if not (isinstance(code, str) and CODE.fullmatch(code)):
        if name in {"States.Timeout", "Sandbox.Timedout", "DetectorTimeout"}:
            code = "timeout"
        elif name in RETRY_EXHAUSTED:
            code = "transient_failure"
        elif name in OPERATOR:
            code = "configuration_error"
        else:
            code = "unexpected_error"
    return name, code
