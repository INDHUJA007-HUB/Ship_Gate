"""IAM Access Analyzer boundary: activity-based policy generation and CheckNoNewAccess.

Phase 7 asks AWS for a policy built from what a principal was *observed* doing, then proves the
replacement is narrower. Both calls sit behind the `PolicyGenerator` protocol so the whole flow
can be exercised without an AWS account and so an AWS failure surfaces as a bounded reason code
instead of provider exception text (ADR 0002).

Nothing in this module decides whether a candidate is acceptable; it reports what AWS said.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

# `jobError.code` is a closed set in the API. Each one becomes one public reason code.
JOB_ERRORS = {
    "AUTHORIZATION_ERROR": "access_analyzer_authorization_error",
    "RESOURCE_NOT_FOUND_ERROR": "access_analyzer_resource_not_found",
    "SERVICE_QUOTA_EXCEEDED_ERROR": "access_analyzer_quota_exceeded",
    "SERVICE_ERROR": "access_analyzer_service_error",
}

# SDK/HTTP error codes and exception class names that mean the same thing to a caller.
CLIENT_ERRORS = {
    "AccessDeniedException": "access_denied",
    "ConflictException": "generation_conflict",
    "InvalidParameterException": "invalid_request",
    "NoCredentialsError": "credentials_unavailable",
    "PartialCredentialsError": "credentials_unavailable",
    "ThrottlingException": "throttled",
    "UnprocessableEntityException": "unprocessable_request",
    "ValidationException": "invalid_request",
    "InvalidClientTokenId": "credentials_unavailable",
    "UnrecognizedClientException": "credentials_unavailable",
    "EndpointConnectionError": "endpoint_unreachable",
    "ConnectionError": "endpoint_unreachable",
    "ConnectTimeoutError": "endpoint_unreachable",
    "ReadTimeoutError": "endpoint_unreachable",
}

TRAIL_ARN = re.compile(r"arn:aws[a-z-]*:cloudtrail:[a-z0-9-]+:\d{12}:trail/.+")
PRINCIPAL_ARN = re.compile(r"arn:aws[a-z-]*:iam::\d{12}:(role|user)/.+")
PENDING = "IN_PROGRESS"
SUCCEEDED = "SUCCEEDED"


class AnalysisUnavailable(RuntimeError):
    """A bounded, source-free reason code raised by this boundary."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


def client_error_code(error: Exception) -> str:
    """Map an SDK exception to one reason code. Exception text is never propagated."""
    code = getattr(error, "response", {}).get("Error", {}).get("Code", "")
    if code in CLIENT_ERRORS:
        return CLIENT_ERRORS[code]
    name = type(error).__name__
    if name in CLIENT_ERRORS:
        return CLIENT_ERRORS[name]
    if "Credential" in name:
        return "credentials_unavailable"
    if any(word in name for word in ("Timeout", "Connection", "Endpoint")):
        return "endpoint_unreachable"
    return "access_analyzer_unavailable"


@dataclass(frozen=True)
class CloudTrailTarget:
    """The activity window to analyze. Access Analyzer cannot generate from nothing."""

    trail_arn: str
    access_role: str
    start: datetime
    end: datetime | None = None
    regions: tuple[str, ...] = ()
    all_regions: bool = False

    def __post_init__(self):
        if not TRAIL_ARN.fullmatch(self.trail_arn or ""):
            raise ValueError("invalid_cloudtrail_arn")
        if not PRINCIPAL_ARN.fullmatch(self.access_role or ""):
            raise ValueError("invalid_access_role_arn")
        if not isinstance(self.start, datetime):
            raise ValueError("start_time_required")
        if self.end is not None and self.end <= self.start:
            raise ValueError("end_time_before_start")

    def to_request(self) -> dict:
        trail: dict = {"cloudTrailArn": self.trail_arn}
        # `regions` and `allRegions` are mutually exclusive in the API.
        if self.all_regions:
            trail["allRegions"] = True
        elif self.regions:
            trail["regions"] = list(self.regions)
        details: dict = {"trails": [trail], "accessRole": self.access_role, "startTime": self.start}
        if self.end is not None:
            details["endTime"] = self.end
        return details

    def to_dict(self) -> dict:
        return {
            "trail_arn": self.trail_arn,
            "access_role": self.access_role,
            "start": self.start.isoformat(),
            "end": self.end.isoformat() if self.end else None,
            "regions": list(self.regions),
            "all_regions": self.all_regions,
        }


@dataclass(frozen=True)
class GenerationRequest:
    principal_arn: str
    cloud_trail: CloudTrailTarget | None = None
    client_token: str | None = None

    def __post_init__(self):
        if not PRINCIPAL_ARN.fullmatch(self.principal_arn or ""):
            raise ValueError("invalid_principal_arn")

    def to_request(self) -> dict:
        request: dict = {"policyGenerationDetails": {"principalArn": self.principal_arn}}
        if self.cloud_trail is not None:
            request["cloudTrailDetails"] = self.cloud_trail.to_request()
        if self.client_token:
            request["clientToken"] = self.client_token
        return request


@dataclass(frozen=True)
class GenerationOutcome:
    """What the generation job said, including the empty result that means 'no activity yet'."""

    job_id: str
    status: str
    policies: tuple[dict, ...] = ()
    reason: str | None = None
    is_complete: bool = True
    principal_arn: str | None = None
    activity: tuple[tuple[str, str], ...] = ()

    @property
    def has_statements(self) -> bool:
        return any(policy.get("Statement") for policy in self.policies)

    @property
    def no_activity(self) -> bool:
        """A succeeded job with nothing in it is the cold-start case, not an error."""
        return self.status == SUCCEEDED and not self.has_statements

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "reason": self.reason,
            "is_complete": self.is_complete,
            "policy_count": len(self.policies),
            "statement_count": sum(len(policy.get("Statement") or ()) for policy in self.policies),
            "no_activity": self.no_activity,
            "activity": dict(self.activity),
        }


@dataclass(frozen=True)
class ExpansionCheck:
    """AWS's answer to 'does this candidate allow anything the current policy did not?'"""

    status: str  # safe, expansion, inconclusive
    method: str = "aws_check_no_new_access"
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"status": self.status, "method": self.method, "reasons": list(self.reasons)}


def cloud_trail_from_config(
    *,
    trail_arn,
    access_role,
    start_time,
    end_time=None,
    regions=(),
    all_regions: bool = False,
) -> CloudTrailTarget:
    """Build an activity window from CLI flags or a job request. Times accept ISO-8601."""
    if not trail_arn:
        raise ValueError("trail_arn_required")
    if not access_role or not start_time:
        raise ValueError("incomplete_cloud_trail_details")
    if regions and all_regions:
        raise ValueError("regions_and_all_regions_are_mutually_exclusive")

    def moment(value):
        return value if isinstance(value, datetime) else datetime.fromisoformat(str(value))

    return CloudTrailTarget(
        trail_arn=trail_arn,
        access_role=access_role,
        start=moment(start_time),
        end=None if end_time is None else moment(end_time),
        regions=tuple(regions),
        all_regions=all_regions,
    )


class PolicyGenerator(Protocol):
    def start(self, request: GenerationRequest) -> str: ...

    def generated(self, job_id: str) -> GenerationOutcome: ...

    def no_new_access(self, before: dict, candidate: dict) -> ExpansionCheck: ...


def _policy_document(text) -> dict:
    if isinstance(text, dict):
        return text
    try:
        document = json.loads(text)
    except (TypeError, ValueError) as error:
        raise AnalysisUnavailable("malformed_generated_policy") from error
    if not isinstance(document, dict):
        raise AnalysisUnavailable("malformed_generated_policy")
    return document


def activity_facts(outcome: GenerationOutcome) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(outcome.activity))


class AwsAccessAnalyzer:
    """Real IAM Access Analyzer client. Callers inject the boto3 client."""

    def __init__(self, client):
        self.client = client

    def start(self, request: GenerationRequest) -> str:
        try:
            response = self.client.start_policy_generation(**request.to_request())
        except Exception as error:  # noqa: BLE001 - mapped to a bounded reason code
            raise AnalysisUnavailable(client_error_code(error)) from error
        job_id = (response or {}).get("jobId")
        if not job_id:
            raise AnalysisUnavailable("missing_job_id")
        return job_id

    def generated(self, job_id: str) -> GenerationOutcome:
        try:
            # Placeholders keep resource-level detail instead of degrading every ARN to "*",
            # and the service-level template explains which services were used at all.
            response = self.client.get_generated_policy(
                jobId=job_id,
                includeResourcePlaceholders=True,
                includeServiceLevelTemplate=True,
            )
        except Exception as error:  # noqa: BLE001
            raise AnalysisUnavailable(client_error_code(error)) from error
        details = (response or {}).get("jobDetails") or {}
        status = details.get("status") or "FAILED"
        if status == "FAILED":
            code = (details.get("jobError") or {}).get("code")
            return GenerationOutcome(
                job_id=job_id,
                status=status,
                reason=JOB_ERRORS.get(code, "access_analyzer_job_failed"),
            )
        result = (response or {}).get("generatedPolicyResult") or {}
        properties = result.get("properties") or {}
        policies = tuple(
            _policy_document(entry.get("policy"))
            for entry in result.get("generatedPolicies") or []
            if isinstance(entry, dict) and entry.get("policy")
        )
        return GenerationOutcome(
            job_id=job_id,
            status=status,
            policies=policies,
            is_complete=bool(properties.get("isComplete", True)),
            principal_arn=properties.get("principalArn"),
            activity=_cloud_trail_facts(properties.get("cloudTrailProperties")),
        )

    def no_new_access(self, before: dict, candidate: dict) -> ExpansionCheck:
        try:
            response = self.client.check_no_new_access(
                newPolicyDocument=json.dumps(candidate),
                existingPolicyDocument=json.dumps(before),
                policyType="IDENTITY_POLICY",
            )
        except Exception as error:  # noqa: BLE001
            raise AnalysisUnavailable(client_error_code(error)) from error
        reasons = tuple(
            entry.get("description", "")
            for entry in (response or {}).get("reasons") or []
            if isinstance(entry, dict)
        )
        return ExpansionCheck(
            status={"PASS": "safe", "FAIL": "expansion"}.get(
                (response or {}).get("result"), "inconclusive"
            ),
            reasons=reasons,
        )


def _cloud_trail_facts(properties) -> tuple[tuple[str, str], ...]:
    if not isinstance(properties, dict):
        return ()
    facts = []
    for trail in properties.get("trailProperties") or []:
        if isinstance(trail, dict) and trail.get("cloudTrailArn"):
            facts.append(("cloud_trail_arn", str(trail["cloudTrailArn"])))
    for key in ("startTime", "endTime"):
        if properties.get(key) is not None:
            facts.append((key.replace("Time", "_time"), str(properties[key])))
    return tuple(facts)


def build_analyzer(region: str | None = None) -> AwsAccessAnalyzer:
    import boto3

    return AwsAccessAnalyzer(boto3.client("accessanalyzer", region_name=region))


def await_generation(
    generator: PolicyGenerator,
    job_id: str,
    *,
    timeout_seconds: float = 600,
    interval_seconds: float = 5,
    sleep=time.sleep,
    clock=time.monotonic,
) -> GenerationOutcome:
    """Poll one job to a terminal state. Generation is minutes, not milliseconds."""
    deadline = clock() + timeout_seconds
    while True:
        outcome = generator.generated(job_id)
        if outcome.status != PENDING:
            return outcome
        if clock() >= deadline:
            raise AnalysisUnavailable("generation_timeout")
        sleep(interval_seconds)
