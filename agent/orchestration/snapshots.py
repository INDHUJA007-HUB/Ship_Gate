"""Content-addressed source snapshots, so every detector scans exactly the preflighted bytes.

A snapshot is an uncompressed zip with sorted entries and fixed timestamps: identical content
always produces identical bytes, so a retried upload is a no-op. Detectors materialize it once
per worker and re-verify the content hash before scanning, which also closes the window in
which a local directory could change between preflight and detection.
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import shutil
import tempfile
import threading
import time
import zipfile
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from agent.config import ScanLimits
from agent.ingest import extract_zip
from agent.orchestration.contracts import tenant_key
from agent.orchestration.failures import PipelineDefect, TransientStepError
from agent.orchestration.state import PipelineState
from agent.preflight import PreflightError, PreflightResult, inspect_tree

ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
KEEP_TREES = 2  # Bounds worker disk use; Lambda /tmp defaults to 512 MiB.


def _rename(source: Path, target: Path, attempts: int = 5) -> None:
    for attempt in range(attempts):
        try:
            source.replace(target)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.05 * 2**attempt)


def build_snapshot(root: Path, preflight: PreflightResult, destination: Path) -> None:
    root = root.resolve()
    relative = sorted(
        [path.relative_to(root).as_posix() for path in preflight.files]
        + list(preflight.skipped_binaries)
    )
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_STORED) as bundle:
        for name in relative:
            info = zipfile.ZipInfo(name, date_time=ZIP_EPOCH)
            info.external_attr = 0o644 << 16
            bundle.writestr(info, (root / name).read_bytes())


class SnapshotWorkspace:
    def __init__(self, root: Path, state: PipelineState, limits: ScanLimits):
        # Scanner subprocesses run from a trusted scratch cwd. Their target must therefore be
        # absolute; a relative state directory would otherwise point inside that scratch folder
        # and could turn a real scan into a tool error (or, worse, an empty successful scan).
        self.root = root.resolve()
        self.state = state
        self.limits = limits
        self._locks: dict[str, threading.Lock] = {}
        self._active: Counter[str] = Counter()
        self._verified: dict[str, PreflightResult] = {}
        self._guard = threading.Lock()

    def _lock(self, key: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(key, threading.Lock())

    @contextmanager
    def materialize(
        self, tenant: str, content_hash: str
    ) -> Iterator[tuple[Path, tuple[Path, ...]]]:
        key = f"{tenant_key(tenant)}-{content_hash[:32]}"
        tree = self.root / key
        with self._guard:
            self._active[key] += 1
        try:
            with self._lock(key):
                preflight = self._verified.get(key) if tree.is_dir() else None
                if preflight is None:
                    if not tree.is_dir():
                        self._extract(tenant, content_hash, tree)
                    try:
                        preflight = inspect_tree(tree, self.limits)
                    except (OSError, PreflightError) as error:
                        raise PipelineDefect("snapshot_unreadable") from error
                    if preflight.content_hash != content_hash:
                        shutil.rmtree(tree, ignore_errors=True)
                        raise PipelineDefect("snapshot_integrity_mismatch")
                    # Verified once per worker; the tree lives in the worker's private scratch.
                    self._verified[key] = preflight
                with contextlib.suppress(OSError):
                    os.utime(tree)  # Recency for eviction only.
            yield tree, preflight.files
        finally:
            with self._guard:
                self._active[key] -= 1

    def _extract(self, tenant: str, content_hash: str, tree: Path) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self._evict()
        staging = Path(tempfile.mkdtemp(prefix="snapshot-", dir=self.root))
        try:
            archive = staging / "snapshot.zip"
            if not self.state.fetch_snapshot(tenant, content_hash, archive):
                raise PipelineDefect("snapshot_missing")
            extracted = staging / "tree"
            extracted.mkdir()
            # Zip headers add bytes the tree does not have; decompressed bytes stay bounded.
            limits = dataclasses.replace(
                self.limits,
                max_total_bytes=self.limits.max_total_bytes + 512 * self.limits.max_files,
            )
            try:
                extract_zip(archive, extracted, limits)
            except PreflightError as error:
                raise PipelineDefect("snapshot_invalid") from error
            _rename(extracted, tree)
        except OSError as error:
            # Disk pressure, or on Windows a scanner briefly holding a new file: retry the step.
            raise TransientStepError("workspace_io_error") from error
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def _evict(self) -> None:
        trees = sorted(
            (p for p in self.root.iterdir() if p.is_dir() and not p.name.startswith("snapshot-")),
            key=lambda p: p.stat().st_mtime,
        )
        for stale in trees[: max(0, len(trees) - KEEP_TREES + 1)]:
            with self._guard:
                busy = self._active[stale.name] > 0
            if not busy:
                self._verified.pop(stale.name, None)
                shutil.rmtree(stale, ignore_errors=True)
