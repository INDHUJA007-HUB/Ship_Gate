"""The IAM Access Analyzer boundary: request shapes, closed reason codes, job polling."""

import json
from datetime import UTC, datetime

import pytest

from agent.access_analyzer import (
    AnalysisUnavailable,
    AwsAccessAnalyzer,
    GenerationOutcome,
    GenerationRequest,
    await_generation,
    client_error_code,
    cloud_trail_from_config,
)

START = datetime(2026, 9, 1, tzinfo=UTC)
END = datetime(2026, 9, 13, tzinfo=UTC)
ROLE = "arn:aws:iam::123456789012:role/upload"
TRAIL = "arn:aws:cloudtrail:us-east-1:123456789012:trail/management"
POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
}


class Client:
    """Records every call and replays one canned response per API."""

    def __init__(self, **responses):
        self.responses = responses
        self.calls = []

    def _call(self, name, **kwargs):
        self.calls.append((name, kwargs))
        reply = self.responses[name]
        if isinstance(reply, Exception):
            raise reply
        return reply

    def start_policy_generation(self, **kwargs):
        return self._call("start_policy_generation", **kwargs)

    def get_generated_policy(self, **kwargs):
        return self._call("get_generated_policy", **kwargs)

    def check_no_new_access(self, **kwargs):
        return self._call("check_no_new_access", **kwargs)


def aws_error(code, message="raw tool output that must never be reported"):
    error = Exception(message)
    error.response = {"Error": {"Code": code}}
    return error


def generated(policies=({"Version": "2012-10-17", "Statement": POLICY["Statement"]},), **extra):
    properties = {
        "isComplete": extra.get("is_complete", True),
        "principalArn": ROLE,
        "cloudTrailProperties": {
            "trailProperties": [{"cloudTrailArn": TRAIL, "allRegions": True}],
            "startTime": START,
            "endTime": END,
        },
    }
    return {
        "jobDetails": {"jobId": "job-1", "status": extra.get("status", "SUCCEEDED")},
        "generatedPolicyResult": {
            "properties": properties,
            "generatedPolicies": [{"policy": json.dumps(policy)} for policy in policies],
        },
    }


def test_start_sends_only_the_principal_when_no_trail_is_given():
    client = Client(start_policy_generation={"jobId": "job-1"})
    assert AwsAccessAnalyzer(client).start(GenerationRequest(principal_arn=ROLE)) == "job-1"
    name, kwargs = client.calls[0]
    assert name == "start_policy_generation"
    assert kwargs == {"policyGenerationDetails": {"principalArn": ROLE}}


def test_cloud_trail_details_request_shape():
    target = cloud_trail_from_config(
        trail_arn=TRAIL, access_role=ROLE, start_time=START, end_time=END, regions=["us-east-1"]
    )
    assert target.to_request() == {
        "trails": [{"cloudTrailArn": TRAIL, "regions": ["us-east-1"]}],
        "accessRole": ROLE,
        "startTime": START,
        "endTime": END,
    }
    assert target.to_dict()["start"] == START.isoformat()
    # allRegions and regions are mutually exclusive in the API.
    assert cloud_trail_from_config(
        trail_arn=TRAIL, access_role=ROLE, start_time=START, all_regions=True
    ).to_request()["trails"] == [{"cloudTrailArn": TRAIL, "allRegions": True}]
    for kwargs, code in [
        ({"trail_arn": "", "access_role": ROLE, "start_time": START}, "trail_arn_required"),
        (
            {"trail_arn": TRAIL, "access_role": "", "start_time": START},
            "incomplete_cloud_trail_details",
        ),
        (
            {
                "trail_arn": TRAIL,
                "access_role": ROLE,
                "start_time": START,
                "regions": ["us-east-1"],
                "all_regions": True,
            },
            "regions_and_all_regions_are_mutually_exclusive",
        ),
    ]:
        with pytest.raises(ValueError, match=code):
            cloud_trail_from_config(**kwargs)
    with pytest.raises(ValueError, match="invalid_cloudtrail_arn"):
        cloud_trail_from_config(trail_arn="not-an-arn", access_role=ROLE, start_time=START)
    with pytest.raises(ValueError, match="end_time_before_start"):
        cloud_trail_from_config(trail_arn=TRAIL, access_role=ROLE, start_time=END, end_time=START)
    with pytest.raises(ValueError, match="invalid_principal_arn"):
        GenerationRequest(principal_arn="arn:aws:s3:::bucket")


def test_generated_policy_reports_completeness_and_activity_facts():
    client = Client(get_generated_policy=generated(is_complete=False))
    outcome = AwsAccessAnalyzer(client).generated("job-1")
    assert outcome.status == "SUCCEEDED" and outcome.has_statements
    assert outcome.is_complete is False and outcome.no_activity is False
    assert outcome.policies[0]["Statement"][0]["Action"] == ["s3:GetObject"]
    assert dict(outcome.activity)["cloud_trail_arn"] == TRAIL
    assert client.calls[0][1] == {
        "jobId": "job-1",
        "includeResourcePlaceholders": True,
        "includeServiceLevelTemplate": True,
    }


def test_empty_success_is_the_cold_start_case_not_a_failure():
    outcome = AwsAccessAnalyzer(Client(get_generated_policy=generated(policies=()))).generated(
        "job-1"
    )
    assert outcome.status == "SUCCEEDED" and outcome.no_activity is True
    assert outcome.reason is None and outcome.to_dict()["statement_count"] == 0


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("AUTHORIZATION_ERROR", "access_analyzer_authorization_error"),
        ("RESOURCE_NOT_FOUND_ERROR", "access_analyzer_resource_not_found"),
        ("SERVICE_QUOTA_EXCEEDED_ERROR", "access_analyzer_quota_exceeded"),
        ("SOMETHING_NEW", "access_analyzer_job_failed"),
    ],
)
def test_failed_jobs_map_to_closed_reason_codes(code, expected):
    response = generated()
    response["jobDetails"] = {"jobId": "job-1", "status": "FAILED", "jobError": {"code": code}}
    outcome = AwsAccessAnalyzer(Client(get_generated_policy=response)).generated("job-1")
    assert outcome.status == "FAILED" and outcome.reason == expected and not outcome.policies


def test_malformed_generated_policy_is_rejected():
    response = generated()
    response["generatedPolicyResult"]["generatedPolicies"] = [{"policy": "{not json"}]
    with pytest.raises(AnalysisUnavailable, match="malformed_generated_policy"):
        AwsAccessAnalyzer(Client(get_generated_policy=response)).generated("job-1")


def test_sdk_errors_become_reason_codes_and_never_leak_text():
    analyzer = AwsAccessAnalyzer(Client(start_policy_generation=aws_error("AccessDeniedException")))
    with pytest.raises(AnalysisUnavailable) as raised:
        analyzer.start(GenerationRequest(principal_arn=ROLE))
    assert raised.value.code == "access_denied"
    assert "raw tool output" not in str(raised.value)
    assert client_error_code(aws_error("ThrottlingException")) == "throttled"
    for name, expected in [
        ("NoCredentialsError", "credentials_unavailable"),
        ("EndpointConnectionError", "endpoint_unreachable"),
        ("SomethingUnexpected", "access_analyzer_unavailable"),
    ]:
        assert client_error_code(type(name, (Exception,), {})()) == expected


def test_check_no_new_access_shape_and_result_mapping():
    passing = Client(check_no_new_access={"result": "PASS", "message": "ok", "reasons": []})
    check = AwsAccessAnalyzer(passing).no_new_access(POLICY, POLICY)
    assert check.status == "safe" and check.method == "aws_check_no_new_access"
    name, kwargs = passing.calls[0]
    assert name == "check_no_new_access"
    assert json.loads(kwargs["newPolicyDocument"]) == POLICY
    assert json.loads(kwargs["existingPolicyDocument"]) == POLICY
    assert kwargs["policyType"] == "IDENTITY_POLICY"

    failing = AwsAccessAnalyzer(
        Client(
            check_no_new_access={
                "result": "FAIL",
                "message": "expands",
                "reasons": [{"description": "s3:PutObject is new", "statementIndex": 0}],
            }
        )
    ).no_new_access(POLICY, POLICY)
    assert failing.status == "expansion" and failing.reasons == ("s3:PutObject is new",)
    unknown = AwsAccessAnalyzer(Client(check_no_new_access={})).no_new_access(POLICY, POLICY)
    assert unknown.status == "inconclusive"


def test_generation_polls_until_terminal_state_and_times_out():
    class Scripted:
        def __init__(self, statuses):
            self.statuses = list(statuses)

        def generated(self, job_id):
            return GenerationOutcome(job_id=job_id, status=self.statuses.pop(0))

    slept = []
    outcome = await_generation(
        Scripted(["IN_PROGRESS", "IN_PROGRESS", "SUCCEEDED"]),
        "job-1",
        sleep=slept.append,
        clock=lambda: 0.0,
    )
    assert outcome.status == "SUCCEEDED" and slept == [5, 5]
    with pytest.raises(AnalysisUnavailable, match="generation_timeout"):
        await_generation(
            Scripted(["IN_PROGRESS", "IN_PROGRESS"]),
            "job-1",
            timeout_seconds=0,
            sleep=slept.append,
            clock=iter([0.0, 1.0]).__next__,
        )
