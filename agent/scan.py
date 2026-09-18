from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agent.cache import ScanCache
from agent.config import Settings
from agent.detectors import selected
from agent.models import SCHEMA_VERSION, DetectorResult, ScanReport
from agent.preflight import PreflightError, inspect_tree


class ScanService:
    """Orchestrates independent static-only detectors without executing source."""

    def __init__(
        self, settings: Settings, cache: ScanCache | None = None, external_detectors=True
    ) -> None:
        self.settings = settings
        self.cache = cache
        self.external_detectors = external_detectors

    def scan(self, source: Path, label: str | None = None) -> ScanReport:
        """Scan a directory. `label` names the original input (URL or archive) in the report."""
        try:
            preflight = inspect_tree(source, self.settings.limits)
        except (OSError, PreflightError) as error:
            raise PreflightError(f"scan rejected: {error}") from error
        root = source.resolve()
        if self.cache:
            cached = self.cache.get(preflight.content_hash)
            if cached:
                return cached
        content_hash, files = preflight.content_hash, preflight.files
        detectors = selected(self.external_detectors)

        def execute(detector):
            try:
                return detector.run(root, content_hash, files, self.settings)
            except Exception:
                # Tool exceptions can contain source or secrets; retain only a safe status.
                return DetectorResult(detector.name, (), "crashed")

        with ThreadPoolExecutor(max_workers=len(detectors)) as pool:
            results = list(pool.map(execute, detectors))
        findings = tuple(
            sorted(
                (finding for result in results for finding in result.findings),
                key=lambda item: (
                    item.location.path,
                    item.location.start_line or 0,
                    item.finding_id,
                ),
            )
        )
        errors = tuple(f"{result.detector}: {result.error}" for result in results if result.error)
        report = ScanReport(SCHEMA_VERSION, label or str(root), content_hash, findings, errors)
        if self.cache:
            self.cache.put(report)
        return report
