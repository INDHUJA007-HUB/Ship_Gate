import json
from dataclasses import replace

import pytest

from agent.iam import check_no_expansion, policy_from_evidence
from agent.remediation import propose_iam, validate_proposal

BEFORE = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
}
OPERATIONS = [{"action": "s3:GetObject", "resource": "arn:aws:s3:::example/photos/demo.jpg"}]


def test_access_guard():
    candidate = policy_from_evidence(OPERATIONS)
    assert check_no_expansion(BEFORE, candidate).status == "safe"
    assert check_no_expansion(candidate, BEFORE).status == "expansion"
    conditioned = json.loads(json.dumps(BEFORE))
    conditioned["Statement"][0]["Condition"] = {"StringEquals": {"key": "value"}}
    assert check_no_expansion(conditioned, candidate).status == "inconclusive"
    for key in ["NotAction", "NotResource", "Principal"]:
        original = json.loads(json.dumps(BEFORE))
        original["Statement"][0][key] = "*"
        assert check_no_expansion(original, candidate).status == "inconclusive"


def test_statement_pairs_cannot_be_crossed():
    before = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::a/x"},
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::b/x"},
        ],
    }
    after = policy_from_evidence([{"action": "s3:PutObject", "resource": "arn:aws:s3:::a/x"}])
    assert check_no_expansion(before, after).status == "expansion"


def test_untrusted_operations_rejected():
    for ops in [
        [],
        [{"action": "s3:*", "resource": "*"}],
        [{"action": "s3:GetObject", "resource": "${BucketArn}"}],
    ]:
        with pytest.raises(ValueError):
            policy_from_evidence(ops)


def test_proposal_is_readonly_and_stale_input_is_blocked(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(BFORE := BEFORE))
    original = path.read_bytes()
    proposal = propose_iam(
        tmp_path, "policy.json", OPERATIONS, tenant="alice", environment="development"
    )
    result = validate_proposal(tmp_path, proposal, tenant="alice", environment="development")
    assert result.status == "static_validated"
    assert result.runtime_status == "not_run"
    assert result.aws_iam_status == "not_verified"
    assert path.read_bytes() == original
    assert (
        validate_proposal(
            tmp_path, replace(proposal, replacement="{}"), tenant="alice", environment="development"
        ).status
        == "unvalidated"
    )
    path.write_text(json.dumps(BFORE) + "\n")
    assert (
        validate_proposal(tmp_path, proposal, tenant="alice", environment="development").status
        == "unvalidated"
    )


def test_invalid_source_does_not_execute(tmp_path):
    (tmp_path / "policy.json").write_text(json.dumps(BEFORE))
    (tmp_path / "app.py").write_text("raise RuntimeError('must never execute')\n")
    proposal = propose_iam(
        tmp_path, "policy.json", OPERATIONS, tenant="alice", environment="production"
    )
    assert (
        validate_proposal(tmp_path, proposal, tenant="alice", environment="production").status
        == "static_validated"
    )
    assert (
        validate_proposal(tmp_path, proposal, tenant="bob", environment="production").status
        == "unvalidated"
    )
