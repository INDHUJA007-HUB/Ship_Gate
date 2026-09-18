import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from threading import Event

import pytest

from agent.candidate_runtime import CandidateRuntime, RuntimeFailure, contract
from agent.config import Settings
from agent.preflight import inspect_tree
from agent.remediation import propose_iam, validate_proposal

FIXTURES = Path(__file__).parents[2] / "fixtures"
FIXTURE = FIXTURES / "runtime-repo"
OPERATIONS = json.loads((FIXTURES / "runtime-operations.json").read_text(encoding="utf-8"))
MANIFEST = json.loads((FIXTURES / "runtime-validation.json").read_text(encoding="utf-8"))
integration = pytest.mark.skipif(
    os.getenv("FIRST_COMMIT_INTEGRATION") != "1",
    reason="requires Docker, SAM, the scanners and the pinned images",
)


def proposal(root, operations=OPERATIONS):
    return propose_iam(root, "template.yaml", operations, tenant="local", environment="development")


def copy(tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    return root


def test_sam_yaml_proposal_is_reviewable_and_source_untouched(tmp_path):
    root = copy(tmp_path)
    original = (root / "template.yaml").read_bytes()
    patch = proposal(root)
    result = validate_proposal(root, patch, tenant="local", environment="development")
    assert result.status == "static_validated", result
    assert "code_actions_covered" in result.checks
    assert (root / "template.yaml").read_bytes() == original
    assert "dynamodb:GetItem" in patch.replacement and "s3:*" not in patch.replacement


def test_fix_dropping_an_action_the_code_calls_is_blocked(tmp_path):
    # Local emulators never enforce IAM, so an over-narrow fix must be caught statically.
    narrow = [item for item in OPERATIONS if item["action"] != "s3:GetObject"]
    with pytest.raises(ValueError, match="missing_code_actions: s3:GetObject"):
        proposal(copy(tmp_path), narrow)


def test_manifest_and_packaging_contract(tmp_path):
    root = copy(tmp_path)
    files = inspect_tree(root, Settings().limits).files
    assert contract(root, MANIFEST, files) == "app.handler"
    for change, error in [
        ({"extra": 1}, "invalid_validation_manifest"),
        ({"seed": {"sqs": []}}, "invalid_seed"),
        ({"seed": {"s3": [{"bucket": "photos", "objects": {"key": 1}}]}}, "invalid_seed"),
        ({"environment": {"DDB_ENDPOINT": "http://elsewhere"}}, "environment_contract_mismatch"),
        ({"function": "Missing"}, "function_not_found"),
    ]:
        with pytest.raises(RuntimeFailure, match=error):
            contract(root, {**MANIFEST, **change}, files)
    (root / "requirements.txt").write_text("untrusted-package\n", encoding="utf-8")
    with pytest.raises(RuntimeFailure, match="custom_dependency"):
        contract(root, MANIFEST, inspect_tree(root, Settings().limits).files)


def test_cancelled_candidate_never_starts_a_process():
    cancel = Event()
    cancel.set()
    result = CandidateRuntime(cancel=cancel, settings=Settings()).validate(
        FIXTURE, proposal(FIXTURE), MANIFEST, tenant="local", environment="development"
    )
    assert result["status"] == "cancelled" and result["audit"] == []
    assert result["pr_gate"]["outcome"] == "deny"


def test_stale_proposal_rejected_before_any_process(tmp_path, monkeypatch):
    root = copy(tmp_path)
    patch = proposal(root)
    with (root / "app.py").open("a", encoding="utf-8") as handle:
        handle.write("\n# changed after review\n")

    def no_process(*args, **kwargs):
        pytest.fail("a stale proposal must not start Docker")

    monkeypatch.setattr("agent.candidate_runtime.subprocess.Popen", no_process)
    result = CandidateRuntime(settings=Settings()).validate(
        root, patch, MANIFEST, tenant="local", environment="development"
    )
    assert result["errors"] == ["source_changed_rescan_required"]
    assert result["pr_gate"]["outcome"] == "deny" and result["audit"] == []


def test_cli_rejects_manifest_inside_scanned_source(tmp_path):
    root = copy(tmp_path)
    manifest = root / "validation.json"
    manifest.write_text(json.dumps(MANIFEST), encoding="utf-8")
    command = [sys.executable, "-m", "agent.cli", "validate-candidate", str(root)]
    command += [str(tmp_path / "proposal.json"), "--tenant", "local"]
    command += ["--environment", "development", "--manifest", str(manifest)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "failed"


@integration
def test_real_candidate_runtime_passes_and_still_requires_approval():
    result = CandidateRuntime().validate(
        FIXTURE, proposal(FIXTURE), MANIFEST, tenant="local", environment="development"
    )
    assert result["status"] == "runtime_validated", result
    assert {
        "code_actions_covered",
        "scanner_replay_no_new_findings",
        "sam_template_validated",
        "dynamodb_minio_seeded",
        "candidate_lambda_smoke_passed",
    } <= set(result["checks"])
    assert result["pr_gate"]["outcome"] == "needs_human_approval"
    assert result["aws_iam_status"] == "not_verified"


@integration
def test_real_candidate_with_failing_smoke_is_blocked():
    seed = {**MANIFEST["seed"], "s3": [{"bucket": "photos", "objects": {}}]}
    missing_object = {**MANIFEST, "seed": seed}
    result = CandidateRuntime().validate(
        FIXTURE, proposal(FIXTURE), missing_object, tenant="local", environment="development"
    )
    assert (result["status"], result["errors"]) == ("failed", ["smoke_response_mismatch"]), result
    assert result["pr_gate"]["outcome"] == "deny"
    assert result["candidate_hash"] is None
