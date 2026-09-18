from pathlib import Path

from agent.cache import ScanCache
from agent.config import Settings
from agent.scan import ScanService

GOLDEN = Path(__file__).parents[2] / "fixtures" / "golden-repo"


def test_local_scan_returns_deterministic_findings_and_caches(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    service = ScanService(Settings(), cache=cache, external_detectors=False)
    first = service.scan(GOLDEN)
    second = service.scan(GOLDEN)
    assert first.complete
    assert not first.cached
    assert second.cached
    assert {finding.finding_type.value for finding in first.findings} == {
        "missing_auth",
        "missing_input_validation",
        "missing_environment_variable",
    }


def test_crashed_detector_returns_partial_without_exception_text(monkeypatch):
    def crashed(*args):
        raise RuntimeError("sensitive source must never be emitted")

    import dataclasses

    from agent.detectors import DETECTORS

    broken = dataclasses.replace(DETECTORS["missing-environment"], run=crashed)
    monkeypatch.setitem(DETECTORS, "missing-environment", broken)
    report = ScanService(Settings(), external_detectors=False).scan(GOLDEN)
    assert not report.complete
    assert len(report.findings) == 2
    assert report.detector_errors == ("missing-environment: crashed",)
