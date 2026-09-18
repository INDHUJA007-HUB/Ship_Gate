"""Phase 7 exit criteria: activity and estimate results stay distinguishable, and both narrow.

No AWS call is made here: a scripted generator stands in for IAM Access Analyzer, exactly like
the hosted Step Functions tests stand in for a deployed state machine.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent.access_analyzer import AnalysisUnavailable, ExpansionCheck, GenerationOutcome
from agent.least_privilege import (
    ACTIVITY,
    PROVENANCE,
    STATIC,
    action_values,
    evaluate_narrowing,
    over_broad,
    recommend,
    render,
    static_candidate,
)

ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "fixtures" / "least-privilege-repo"
TARGET = "infra/template.yaml"
ROLE = "arn:aws:iam::123456789012:role/UploadFunctionRole"
TRAIL = "arn:aws:cloudtrail:us-east-1:123456789012:trail/management"
OBSERVED = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::first-commit-demo/*",
        }
    ],
}
GOVERNANCE = {"tenant": "demo", "environment": "development"}


class Generator:
    """A scripted IAM Access Analyzer: the same protocol, no account, no network."""

    def __init__(
        self,
        *,
        policies=(),
        is_complete=True,
        status="SUCCEEDED",
        check=None,
        error=None,
        check_error=None,
    ):
        self.policies = tuple(policies)
        self.is_complete = is_complete
        self.status = status
        self.check = check
        self.error = error
        self.check_error = check_error
        self.starts = []
        self.checks = []

    def start(self, request):
        self.starts.append(request)
        if self.error:
            raise self.error
        return "job-1"

    def generated(self, job_id):
        return GenerationOutcome(
            job_id=job_id,
            status=self.status,
            policies=self.policies,
            reason=None if self.status == "SUCCEEDED" else "access_analyzer_job_failed",
            is_complete=self.is_complete,
            activity=(("cloud_trail_arn", TRAIL), ("start_time", "2026-09-01")),
        )

    def no_new_access(self, before, candidate):
        self.checks.append((before, candidate))
        if self.check_error:
            raise self.check_error
        return self.check or ExpansionCheck("safe")


def observed_generator(**kwargs):
    return Generator(policies=(OBSERVED,), **kwargs)


def with_activity(**kwargs):
    return recommend(FIXTURE, TARGET, role_arn=ROLE, generator=observed_generator(), **kwargs)


def repo(tmp_path, policy, source):
    (tmp_path / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
    if source is not None:
        (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return tmp_path


def test_methods_are_labelled_and_never_presented_as_the_same_thing():
    result = with_activity(**GOVERNANCE)
    activity, static = result.attempts
    assert [attempt.method for attempt in result.attempts] == [ACTIVITY, STATIC]
    assert activity.provenance.confidence == "observed_activity"
    assert static.provenance.confidence == "static_estimate"
    assert activity.provenance.label != static.provenance.label
    assert activity.provenance.observed and not static.provenance.observed
    # A reader must be able to tell which one they are looking at from the rendered report alone.
    report = render(result)
    assert PROVENANCE[ACTIVITY]["label"] in report and PROVENANCE[STATIC]["label"] in report
    assert result.chosen.method == ACTIVITY


def test_activity_generated_policy_is_strictly_narrower_with_a_before_after_diff():
    result = with_activity(**GOVERNANCE)
    chosen = result.chosen
    assert chosen.status == "recommended" and chosen.provenance.observed
    assert chosen.narrowing.verdict == "strictly_narrower"
    assert "s3:*" in chosen.narrowing.removed_actions
    assert "dynamodb:*" in chosen.narrowing.removed_actions
    assert action_values(chosen.candidate) == ["s3:GetObject", "s3:PutObject"]
    assert chosen.candidate["Statement"][0]["Resource"] == "arn:aws:s3:::first-commit-demo/*"
    # The focused policy diff and the document patch are both real diffs of this change.
    assert '"s3:*"' in chosen.policy_diff and '"s3:GetObject"' in chosen.policy_diff
    assert chosen.policy_diff.startswith("--- a/") and "#PolicyDocument" in chosen.policy_diff
    assert "a/infra/template.yaml" in chosen.diff and "s3:GetObject" in chosen.diff
    assert dict(chosen.provenance.activity)["cloud_trail_arn"] == TRAIL
    assert result.status == "recommended"


def test_no_activity_history_yields_guidance_and_a_labelled_estimate():
    bare = Generator(policies=())
    result = recommend(FIXTURE, TARGET, role_arn=ROLE, generator=bare, **GOVERNANCE)
    activity, static = result.attempts
    assert activity.status == "unavailable" and activity.candidate is None
    assert activity.reasons == ("no_activity_history",)
    assert any("run your app a few times first" in line for line in activity.guidance)
    # The fallback is offered, but it is never dressed up as observed activity.
    assert result.chosen.method == STATIC and not result.chosen.provenance.observed
    assert result.chosen.status == "recommended"
    assert static.narrowing.verdict == "strictly_narrower"


def test_activity_only_mode_fails_closed_without_history():
    result = recommend(
        FIXTURE,
        TARGET,
        role_arn=ROLE,
        method="activity",
        generator=Generator(policies=()),
        **GOVERNANCE,
    )
    assert [attempt.method for attempt in result.attempts] == [ACTIVITY]
    assert result.status == "none" and result.chosen is None


def test_static_estimate_narrows_actions_and_keeps_exact_statements():
    before = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": "arn:aws:sqs:us-east-1:1:q",
            },
        ],
    }
    candidate, dropped = static_candidate(
        before, ("s3:GetObject", "s3:PutObject", "sqs:SendMessage")
    )
    assert dropped == ()
    assert candidate["Statement"][0]["Action"] == ["s3:GetObject", "s3:PutObject"]
    assert candidate["Statement"][1] == before["Statement"][2]  # already exact, untouched
    assert len(candidate["Statement"]) == 2  # the unused wildcard statement is dropped
    narrowing = evaluate_narrowing(before, candidate)
    assert narrowing.verdict == "strictly_narrower"
    assert set(narrowing.removed_actions) == {"dynamodb:*", "s3:*"}
    assert narrowing.retained_resource_wildcards == 1
    assert over_broad(before) and not over_broad(candidate)
    assert not evaluate_narrowing(before, before).strictly_narrower
    assert evaluate_narrowing(before, before).reason == "candidate_not_narrower"


def test_estimate_reports_unresolved_and_ungranted_code(tmp_path):
    root = repo(
        tmp_path,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        },
        "import boto3\n"
        "s3 = boto3.client('s3')\n"
        "queue = boto3.client('sqs')\n"
        "table = boto3.resource('dynamodb').Table('uploads')\n"
        "def go():\n"
        "    s3.get_object(Bucket='b', Key='k')\n"
        "    queue.send_message(QueueUrl='https://q', MessageBody='x')\n",
    )
    result = recommend(root, "policy.json", method="static", **GOVERNANCE)
    attempt = result.attempts[0]
    assert attempt.coverage.unresolved_files == ("app.py",)
    assert attempt.coverage.ungranted_by_original == ("sqs:SendMessage",)
    assert set(attempt.reasons) >= {
        "code_actions_partially_unresolved",
        "code_actions_not_granted_by_original",
    }
    assert attempt.status == "needs_review" and result.status == "needs_review"
    assert attempt.narrowing.verdict == "strictly_narrower"


def test_a_condition_makes_the_local_proof_inconclusive_rather_than_confident(tmp_path):
    root = repo(
        tmp_path,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:PrincipalTag/team": "uploads"}},
                }
            ],
        },
        "import boto3\ns3 = boto3.client('s3')\n"
        "def go():\n    s3.get_object(Bucket='b', Key='k')\n",
    )
    result = recommend(root, "policy.json", method="static", **GOVERNANCE)
    attempt = result.attempts[0]
    assert attempt.narrowing.verdict == "inconclusive"
    assert attempt.narrowing.reason == "local_subset_proof_inconclusive"
    assert attempt.status == "needs_review" and attempt.candidate is not None


def test_aws_check_blocks_a_candidate_that_allows_new_access():
    generator = observed_generator(
        check=ExpansionCheck("expansion", reasons=("s3:PutObject on a new bucket",))
    )
    result = recommend(
        FIXTURE, TARGET, role_arn=ROLE, generator=generator, verify="aws", **GOVERNANCE
    )
    activity = result.attempts[0]
    assert activity.narrowing.verdict == "expansion"
    assert activity.narrowing.reason == "aws_check_reports_new_access"
    assert activity.narrowing.aws_status == "expansion"
    assert activity.status == "rejected" and generator.checks
    # The estimate cannot claim the AWS check either, so nothing is offered as verified.
    assert result.chosen is None or result.chosen.narrowing.aws_status in {"safe", "not_run"}


def test_aws_verification_failure_becomes_a_reason_code():
    generator = observed_generator(check_error=AnalysisUnavailable("throttled"))
    result = recommend(
        FIXTURE, TARGET, role_arn=ROLE, generator=generator, verify="aws", **GOVERNANCE
    )
    assert result.attempts[0].status == "unavailable"
    assert result.attempts[0].reasons == ("throttled",)


def test_generated_actions_outside_the_replaced_policy_are_dropped_and_reported():
    extra = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup"], "Resource": "*"},
        ],
    }
    result = recommend(
        FIXTURE, TARGET, role_arn=ROLE, generator=Generator(policies=(extra,)), **GOVERNANCE
    )
    attempt = result.attempts[0]
    assert action_values(attempt.candidate) == ["s3:GetObject"]
    assert attempt.coverage.outside_target_scope == ("logs:CreateLogGroup",)
    assert "actions_outside_replaced_policy" in attempt.reasons
    assert attempt.narrowing.verdict == "strictly_narrower"
    assert attempt.status == "needs_review"  # offered, but flagged for a human


def test_role_and_generator_are_required_before_any_activity_claim():
    no_role = recommend(FIXTURE, TARGET, generator=observed_generator(), **GOVERNANCE)
    assert no_role.attempts[0].reasons == ("role_required_for_activity",)
    assert no_role.attempts[0].candidate is None
    no_client = recommend(FIXTURE, TARGET, role_arn=ROLE, **GOVERNANCE)
    assert no_client.attempts[0].reasons == ("access_analyzer_not_configured",)
    assert no_client.chosen.method == STATIC


def test_an_already_narrow_policy_is_never_presented_as_a_narrowing(tmp_path):
    root = repo(
        tmp_path,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
            ],
        },
        "import boto3\ns3 = boto3.client('s3')\n"
        "def go():\n    s3.get_object(Bucket='b', Key='k')\n",
    )
    result = recommend(root, "policy.json", method="static", **GOVERNANCE)
    attempt = result.attempts[0]
    assert attempt.narrowing.verdict == "not_narrower"
    assert attempt.status == "rejected" and result.status == "none" and result.chosen is None


def test_recommendation_is_read_only_and_deterministic():
    target = FIXTURE / TARGET
    before = target.read_bytes()
    first = with_activity(**GOVERNANCE)
    second = with_activity(**GOVERNANCE)
    assert target.read_bytes() == before
    assert first.recommendation_id == second.recommendation_id
    assert first.to_dict()["chosen_method"] == ACTIVITY


def test_unknown_environment_or_tenant_is_denied():
    with pytest.raises(ValueError):
        recommend(FIXTURE, TARGET, tenant="demo", environment="sandbox")


def test_cli_prints_the_method_and_the_before_after_diff():
    def run(*arguments):
        return subprocess.run(
            [sys.executable, "-m", "agent.cli", *map(str, arguments)],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=ROOT,
            check=False,
        )

    report = run(
        "remediate-iam", FIXTURE, TARGET, "--tenant", "demo", "--environment", "development"
    )
    assert report.returncode == 0, report.stdout + report.stderr
    assert PROVENANCE[STATIC]["label"] in report.stdout
    assert PROVENANCE[ACTIVITY]["label"] in report.stdout
    assert "policy before/after:" in report.stdout
    assert '"s3:GetObject"' in report.stdout and '"Action": "s3:*"' in report.stdout

    machine = run(
        "remediate-iam",
        FIXTURE,
        TARGET,
        "--tenant",
        "demo",
        "--environment",
        "development",
        "--json",
    )
    payload = json.loads(machine.stdout)
    assert payload["status"] == "recommended"
    assert payload["chosen_method"] == STATIC
    assert [attempt["provenance"]["confidence"] for attempt in payload["attempts"]] == [
        "observed_activity",
        "static_estimate",
    ]
    forced = run(
        "remediate-iam",
        FIXTURE,
        TARGET,
        "--tenant",
        "demo",
        "--environment",
        "development",
        "--method",
        "activity",
        "--role",
        "arn:aws:iam::000000000000:role/absent",
        "--region",
        "us-east-1",
        "--json",
    )
    assert forced.returncode == 2
    attempts = json.loads(forced.stdout)["attempts"]
    assert [attempt["status"] for attempt in attempts] == ["unavailable"]
