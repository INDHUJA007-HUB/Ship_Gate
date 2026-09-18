"""Bounded ingestion of untrusted zip archives and Git URLs into a scannable directory.

Nothing from the input is executed. Archives are extracted by Python with every entry checked
before bytes are written, and Git runs with hooks, credential prompts, submodules, LFS filters,
redirects, symlinks and every non-HTTPS transport disabled.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from agent.config import ScanLimits
from agent.preflight import PreflightError
from agent.toolchain import executable

MAX_COMPRESSION_RATIO = 100
CHUNK_BYTES = 64 * 1024
GIT_SCHEMES = ("https://", "http://", "ssh://", "git://", "file://", "git@")


class IngestionError(PreflightError):
    """A safe, source-free rejection of an archive or repository reference."""


@dataclass(frozen=True, slots=True)
class Ingested:
    root: Path
    kind: str  # directory, zip or git
    label: str
    revision: str | None = None

    def to_dict(self) -> dict:
        return {"kind": self.kind, "label": self.label, "revision": self.revision}


@contextmanager
def ingest(reference: str, limits: ScanLimits) -> Iterator[Ingested]:
    """Yield a directory for `reference`; temporary copies are removed on exit."""
    if reference.startswith(GIT_SCHEMES):
        validate_git_url(reference)
        with tempfile.TemporaryDirectory(
            prefix="first-commit-git-", ignore_cleanup_errors=True
        ) as temporary:
            root = Path(temporary) / "repo"
            revision = clone(reference, root, limits)
            yield Ingested(root, "git", reference, revision)
        return
    path = Path(reference)
    if path.is_file() and path.suffix.lower() == ".zip":
        with tempfile.TemporaryDirectory(
            prefix="first-commit-zip-", ignore_cleanup_errors=True
        ) as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            extract_zip(path, root, limits)
            yield Ingested(root, "zip", path.name)
        return
    if path.is_dir():
        yield Ingested(path, "directory", str(path.resolve()))
        return
    raise IngestionError("source must be a directory, a .zip archive or an https Git URL")


def _archive_parts(name: str, limits: ScanLimits) -> tuple[str, ...]:
    normalized = name.replace("\\", "/")
    parts = tuple(part for part in normalized.split("/") if part)
    if (
        not parts
        or normalized.startswith("/")
        or any(part in {".", ".."} or ":" in part for part in parts)
        or any(ord(char) < 32 for char in normalized)
    ):
        raise IngestionError("archive entry has an unsafe path")
    if len(parts) > limits.max_depth:
        raise IngestionError("maximum directory depth exceeded in archive")
    return parts


def extract_zip(archive: Path, destination: Path, limits: ScanLimits) -> None:
    if archive.stat().st_size > limits.max_total_bytes:
        raise IngestionError("archive exceeds the maximum total size")
    deadline = time.monotonic() + limits.timeout_seconds
    destination = destination.resolve(strict=True)
    try:
        bundle = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as error:
        raise IngestionError("invalid zip archive") from error
    with bundle:
        entries = bundle.infolist()
        if len(entries) > limits.max_files * 2:
            raise IngestionError("maximum archive entry count exceeded")
        seen: set[str] = set()
        total = 0
        for entry in entries:
            if time.monotonic() >= deadline:
                raise IngestionError("archive extraction timed out")
            parts = _archive_parts(entry.filename, limits)
            key = "/".join(parts).casefold()
            if key in seen:
                # Case-insensitive file systems would silently merge these entries.
                raise IngestionError("archive contains duplicate paths")
            seen.add(key)
            mode = entry.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise IngestionError("linked files or directories are not supported")
            if entry.flag_bits & 0x1:
                raise IngestionError("encrypted archive entries are not supported")
            target = destination.joinpath(*parts)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if entry.file_size > limits.max_file_bytes:
                raise IngestionError("maximum individual file size exceeded in archive")
            if (
                entry.file_size > CHUNK_BYTES
                and entry.file_size > entry.compress_size * MAX_COMPRESSION_RATIO
            ):
                raise IngestionError("archive compression ratio is too high")
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                # Header sizes can lie, so count the bytes actually decompressed.
                with bundle.open(entry) as source, target.open("xb") as output:
                    while chunk := source.read(CHUNK_BYTES):
                        written += len(chunk)
                        total += len(chunk)
                        if written > min(entry.file_size, limits.max_file_bytes):
                            raise IngestionError("archive entry is larger than declared")
                        if total > limits.max_total_bytes:
                            raise IngestionError("maximum total size exceeded in archive")
                        output.write(chunk)
            except (zipfile.BadZipFile, EOFError, OSError, NotImplementedError) as error:
                raise IngestionError("invalid or unsupported archive entry") from error


def validate_git_url(url: str, resolver=socket.getaddrinfo) -> None:
    if len(url) > 2048 or any(char.isspace() or ord(char) < 32 for char in url):
        raise IngestionError("invalid Git URL")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise IngestionError("only https Git URLs are supported")
    if parts.username or parts.password:
        raise IngestionError("credentials in Git URLs are not accepted")
    if parts.query or parts.fragment or parts.port not in (None, 443):
        raise IngestionError("Git URL must not include a query, fragment or custom port")
    try:
        addresses = {info[4][0] for info in resolver(parts.hostname, 443, 0, socket.SOCK_STREAM)}
    except (OSError, UnicodeError) as error:
        raise IngestionError("Git host could not be resolved") from error
    # Rejects loopback, private, link-local (cloud metadata) and reserved targets. Git resolves
    # again when it connects, so hosted mode still needs an egress proxy against DNS rebinding.
    for address in addresses:
        if not ipaddress.ip_address(address.split("%")[0]).is_global:
            raise IngestionError("Git host resolves to a non-public address")


def _git_environment(home: Path) -> dict[str, str]:
    keep = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC", "PATHEXT"}
    env = {key: value for key, value in os.environ.items() if key.upper() in keep}
    env.update(
        {
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GCM_INTERACTIVE": "never",
        }
    )
    return env


def _git_config(protocols: tuple[str, ...]) -> list[str]:
    settings = {
        "protocol.allow": "never",
        **{f"protocol.{name}.allow": "always" for name in protocols},
        "core.hooksPath": os.devnull,
        "core.symlinks": "false",
        "core.fsmonitor": "false",
        "credential.helper": "",
        "http.followRedirects": "false",
        "submodule.recurse": "false",
        "init.templateDir": "",
        "transfer.fsckObjects": "true",
        "filter.lfs.required": "false",
        "filter.lfs.smudge": "",
        "filter.lfs.process": "",
    }
    return [part for key, value in settings.items() for part in ("-c", f"{key}={value}")]


def _tree_bytes(root: Path) -> int:
    total = 0
    for directory, _, names in os.walk(root):
        for name in names:
            try:
                total += os.lstat(os.path.join(directory, name)).st_size
            except OSError:
                continue
    return total


def _force_remove(function, path, _):
    os.chmod(path, stat.S_IWRITE)  # Git object files are read-only on Windows.
    function(path)


def clone(
    url: str, destination: Path, limits: ScanLimits, *, protocols: tuple[str, ...] = ("https",)
) -> str:
    """Shallow, hardened clone. Returns the commit SHA and removes `.git` from the tree."""
    git = executable("git")
    home = destination.parent / "git-home"
    home.mkdir(parents=True, exist_ok=True)
    env = _git_environment(home)
    config = _git_config(protocols)
    command = [
        git,
        *config,
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
        "--quiet",
        "--",
        url,
        str(destination),
    ]
    started = time.monotonic()
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(
                command, stdout=output, stderr=subprocess.STDOUT, env=env, shell=False
            )
            while process.poll() is None:
                elapsed = time.monotonic() - started
                # Objects plus worktree: bound the download itself, not only the checkout.
                too_large = destination.exists() and _tree_bytes(destination) > (
                    limits.max_total_bytes * 4
                )
                if elapsed > limits.timeout_seconds or too_large or output.tell() > 1024 * 1024:
                    process.kill()
                    process.wait()
                    raise IngestionError(
                        "Git clone exceeded the size limit" if too_large else "Git clone timed out"
                    )
                time.sleep(0.25)
        if process.returncode:
            # Git's own message may echo remote-controlled text; report a stable reason only.
            raise IngestionError("Git clone failed")
        revision = subprocess.run(
            [git, *config, "rev-parse", "HEAD"],
            cwd=destination,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise IngestionError("Git is unavailable or failed to run") from error
    sha = revision.stdout.strip()
    if revision.returncode or len(sha) not in (40, 64) or set(sha) - set("0123456789abcdef"):
        raise IngestionError("Git clone produced no readable revision")
    shutil.rmtree(destination / ".git", onexc=_force_remove)
    return sha
