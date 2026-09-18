"""Input limits for untrusted source trees; no scanned code is ever executed."""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path

from agent.config import ScanLimits


class PreflightError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PreflightResult:
    files: tuple[Path, ...]
    content_hash: str
    skipped_binaries: tuple[str, ...]


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(8_192)
    except OSError as error:
        raise PreflightError(f"unable to read {path.name}: {error}") from error


def inspect_tree(root: Path, limits: ScanLimits) -> PreflightResult:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise PreflightError("scan source must be a directory")

    files: list[Path] = []
    binaries: list[str] = []
    total_bytes = 0
    digest = hashlib.sha256()
    deadline = time.monotonic() + limits.timeout_seconds
    if (
        min(
            limits.max_files,
            limits.max_file_bytes,
            limits.max_total_bytes,
            limits.max_depth,
            limits.timeout_seconds,
        )
        <= 0
    ):
        raise PreflightError("scan limits must be positive")

    def walk(directory, depth=0):
        # Bound traversal before materializing a potentially enormous tree.
        nonlocal entries
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                if time.monotonic() >= deadline:
                    raise PreflightError("scan timed out during preflight")
                if entries > limits.max_files * 2:
                    raise PreflightError("maximum filesystem entry count exceeded")
                candidate = Path(child.path)
                if child.is_symlink() or candidate.is_junction():
                    raise PreflightError("linked files or directories are not supported")
                if child.is_dir(follow_symlinks=False):
                    if depth + 1 >= limits.max_depth:
                        raise PreflightError("maximum directory depth exceeded")
                    yield from walk(candidate, depth + 1)
                elif child.is_file(follow_symlinks=False):
                    yield candidate
                else:
                    raise PreflightError("special files are not supported")

    entries = 0
    hashes = []
    for candidate in walk(root):
        relative = candidate.relative_to(root)
        if len(relative.parts) > limits.max_depth:
            raise PreflightError(f"maximum directory depth exceeded at {relative}")
        if len(files) + len(binaries) >= limits.max_files:
            raise PreflightError(f"maximum file count ({limits.max_files}) exceeded")
        size = candidate.stat().st_size
        if size > limits.max_file_bytes:
            raise PreflightError(f"maximum individual file size exceeded at {relative}")
        total_bytes += size
        if total_bytes > limits.max_total_bytes:
            raise PreflightError(f"maximum total size ({limits.max_total_bytes}) exceeded")
        content = candidate.read_bytes()
        if len(content) != size:
            raise PreflightError("source changed during preflight")
        hashes.append((relative.as_posix(), hashlib.sha256(content).digest()))
        if b"\x00" in content:
            binaries.append(relative.as_posix())
            continue
        files.append(candidate)
    for name, file_hash in sorted(hashes):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_hash)
    return PreflightResult(tuple(sorted(files)), digest.hexdigest(), tuple(sorted(binaries)))
