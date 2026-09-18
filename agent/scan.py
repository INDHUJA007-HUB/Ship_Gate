from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agent.cache import ScanCache
from agent.config import Settings
from agent.models import SCHEMA_VERSION, DetectorResult, ScanReport
from agent.preflight import PreflightError, inspect_tree
from agent.tools.external import checkov, gitleaks, semgrep
from agent.tools.patterns import missing_environment, route_safety


class ScanService:
    """Orchestrates independent static-only detectors without executing source."""

    def __init__(
        self, settings: Settings, cache: ScanCache | None = None, external_detectors=True
    ) -> None:
        self.settings = settings
        self.cache = cache
        self.external_detectors = external_detectors

    def scan(self, source: Path) -> ScanReport:
        try:
            preflight = inspect_tree(source, self.settings.limits)
        except (OSError, PreflightError) as error:
            raise PreflightError(f"scan rejected: {error}") from error
        root = source.resolve()
        if self.cache:
            cached = self.cache.get(preflight.content_hash)
            if cached:
                return cached
        tasks = [
            lambda: missing_environment(root, preflight.content_hash),
            lambda: route_safety(root, preflight.content_hash),
        ]
        if self.external_detectors:
            tasks.extend(
                [
                    lambda: gitleaks(root, preflight.content_hash, self.settings),
                    lambda: semgrep(root, preflight.content_hash, self.settings),
                    lambda: checkov(root, preflight.content_hash, self.settings),
                ]
            )

        def execute(task):
            try:
                return task()
            except Exception:
                # Tool exceptions can contain source or secrets; retain only a safe status.
                return DetectorResult("detector", (), "detector_crashed")

        with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
            results = list(pool.map(execute, tasks))
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
        report = ScanReport(SCHEMA_VERSION, str(root), preflight.content_hash, findings, errors)
        if self.cache:
            self.cache.put(report)
        return report
