from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from agent.detectors import Detector
from agent.models import DetectorResult, FindingType, Severity
from agent.normalize import normalized_finding
from agent.orchestration.asl import StateMachine, UnsupportedDefinition, validate
from agent.orchestration.contracts import new_run_id
from agent.orchestration.faults import Fault, FaultPlan
from agent.orchestration.pipeline import RESOURCES, load_definition, local_pipeline, with_faults


def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "app.py").write_text(
        "import os\nfrom flask import request\n\n"
        "VALUE = os.environ['TEST_KEY']\n\n"
        "@app.post('/items')\ndef create_item():\n    return request.json\n",
        encoding="utf-8",
    )
    return root


def request(source: Path, *, tenant: str = "tenant", run_id: str | None = None) -> dict:
    return {
        "tenant_id": tenant,
        "user_id": "user",
        "run_id": run_id or new_run_id(tenant),
        "source_ref": str(source),
        "environments": ["development"],
        "audience": "beginner",
    }


def probe_detector(calls: Counter) -> Detector:
    def run(root, content_hash, files, settings):
        calls["probe"] += 1
        assert root.is_absolute()
        finding = normalized_finding(
            finding_type=FindingType.MISSING_ENVIRONMENT_VARIABLE,
            severity=Severity.MEDIUM,
            root=root,
            path=root / "app.py",
            line=1,
            detector="test-probe",
            rule_id="missing-required-environment",
            content_hash=content_hash,
            message="A required test environment variable is not declared.",
            metadata={"environment_variable": "TEST_KEY"},
        )
        return DetectorResult("probe", (finding,))

    return Detector(
        "probe",
        "probe-1",
        (FindingType.MISSING_ENVIRONMENT_VARIABLE,),
        run,
    )


def pipeline_with_probe(tmp_path: Path, faults=()) -> tuple[object, Counter]:
    calls = Counter()
    pipeline = local_pipeline(
        tmp_path / "state",
        faults=FaultPlan(faults),
        external_detectors=False,
        provider_factory=lambda: None,
        provider_identity="none",
    )
    pipeline.context.detectors = {"probe": probe_detector(calls)}
    return pipeline, calls


def test_deployed_definition_is_the_definition_local_mode_executes():
    definition = load_definition()
    validate(definition, set(RESOURCES))
    assert definition["StartAt"] == "Prepare"
    assert definition["States"]["Detect"]["Type"] == "Map"
    assert (
        definition["States"]["Detect"]["ItemProcessor"]["States"]["RunDetector"]["Catch"][0]["Next"]
        == "RecordIncompleteCheck"
    )

    with pytest.raises(UnsupportedDefinition):
        StateMachine({**definition, "QueryLanguage": "JSONata"}, {})


def test_lambda_dependency_manifest_covers_pipeline_imports():
    requirements = (Path(__file__).parents[2] / "requirements.txt").read_text(encoding="utf-8")
    assert "PyYAML" in requirements
    assert "cedarpy==4.8.7" in requirements
    assert "anthropic[bedrock]" in requirements


def test_detector_crash_preserves_findings_and_labels_partial(tmp_path):
    source = repository(tmp_path)
    pipeline = local_pipeline(
        tmp_path / "state",
        faults=FaultPlan((Fault("route-safety", "crash"),)),
        external_detectors=False,
        provider_factory=lambda: None,
        provider_identity="none",
    )
    run = pipeline.submit(request(source))
    result = pipeline.result("tenant", run["run_id"])

    assert run["status"] == "partial"
    assert result["findings"]  # The successful environment check was not discarded.
    assert result["coverage"]["complete"] is False
    assert result["coverage"]["missing_categories"] == [
        "missing_auth",
        "missing_input_validation",
    ]
    assert all(decision["outcome"] == "deny" for decision in result["policy"]["decisions"])
    assert pipeline.last_execution.status == "SUCCEEDED"
    assert pipeline.last_execution.events("caught", "RunDetector")
    review = pipeline.reviews("tenant", run["run_id"])
    assert [(item["step"], item["disposition"]) for item in review] == [
        ("route-safety", "human_review")
    ]


def test_retry_after_write_reuses_checkpoint_without_duplicate_finding(tmp_path):
    source = repository(tmp_path)
    pipeline, calls = pipeline_with_probe(tmp_path, (Fault("probe", "transient_after_write", 1),))
    run = pipeline.submit(request(source))
    result = pipeline.result("tenant", run["run_id"])

    assert run["status"] == "completed"
    assert calls["probe"] == 1
    assert len(result["findings"]) == 1
    assert result["usage"]["detectors_reused"] == 1
    assert len(pipeline.context.store.get_findings("tenant", result["scan_id"])) == 1
    retries = pipeline.last_execution.events("retry", "RunDetector")
    assert [(event["error"], event["attempt"]) for event in retries] == [("TransientStepError", 1)]


def test_resume_reuses_successes_and_resolves_recovered_review_item(tmp_path):
    source = repository(tmp_path)
    pipeline = local_pipeline(
        tmp_path / "state",
        faults=FaultPlan((Fault("route-safety", "defect"),)),
        external_detectors=False,
        provider_factory=lambda: None,
        provider_identity="none",
    )
    run_id = new_run_id("tenant")
    assert pipeline.submit(request(source, run_id=run_id))["status"] == "partial"

    recovered = with_faults(pipeline, FaultPlan())
    run = recovered.resume("tenant", run_id)
    result = recovered.result("tenant", run_id)

    assert run["status"] == "completed" and run["generation"] == 1
    assert result["usage"]["detectors_reused"] == 1
    assert result["usage"]["detectors_run"] == 1
    assert recovered.reviews("tenant", run_id) == []
    history = recovered.state.list_reviews("tenant", run_id)
    assert history[0]["status"] == "resolved"
    assert history[0]["resolved_by_generation"] == 1


def test_invalid_source_fails_cleanly_without_retry_or_review(tmp_path):
    pipeline, _ = pipeline_with_probe(tmp_path)
    run = pipeline.submit(request(tmp_path / "does-not-exist"))
    result = pipeline.result("tenant", run["run_id"])

    assert run["status"] == "failed"
    assert run["reason"] in {"invalid_source", "repository_url_rejected"}
    assert run["resumable"] is False
    assert result["error"] == "ScanRejected"
    assert pipeline.reviews("tenant", run["run_id"]) == []
    assert pipeline.last_execution.error == "ScanFailed"


def test_identical_completed_content_reuses_the_whole_result(tmp_path):
    source = repository(tmp_path)
    pipeline, calls = pipeline_with_probe(tmp_path)
    first = pipeline.submit(request(source))
    second = pipeline.submit(request(source))
    result = pipeline.result("tenant", second["run_id"])

    assert first["run_id"] != second["run_id"]
    assert first["status"] == second["status"] == "completed"
    assert calls["probe"] == 1
    assert result["reused_from"] == first["run_id"]
    assert result["usage"] == {
        "detectors_run": 0,
        "detectors_reused": 0,
        "model_calls": 0,
        "estimated_model_cost_usd": 0.0,
        "reused_result": True,
    }


def test_same_run_submission_is_idempotent(tmp_path):
    source = repository(tmp_path)
    pipeline, calls = pipeline_with_probe(tmp_path)
    submitted = request(source)
    first = pipeline.submit(submitted)
    second = pipeline.submit(submitted)

    assert first == second
    assert calls["probe"] == 1
