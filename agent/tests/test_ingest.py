import os
import shutil
import socket
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest

from agent.config import ScanLimits, Settings
from agent.ingest import IngestionError, clone, extract_zip, ingest, validate_git_url
from agent.scan import ScanService

GOLDEN = Path(__file__).parents[2] / "fixtures" / "golden-repo"


def archive(tmp_path, entries, name="upload.zip"):
    """entries: (ZipInfo or name, bytes) pairs."""
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
        for info, data in entries:
            bundle.writestr(info, data)
    return path


def test_zip_upload_is_scanned_with_its_name_as_label(tmp_path):
    entries = [
        (path.relative_to(GOLDEN).as_posix(), path.read_bytes())
        for path in GOLDEN.rglob("*")
        if path.is_file()
    ]
    upload = archive(tmp_path, entries)
    with ingest(str(upload), ScanLimits()) as source:
        extracted = source.root
        report = ScanService(Settings(), external_detectors=False).scan(source.root, source.label)
        assert source.to_dict() == {"kind": "zip", "label": "upload.zip", "revision": None}
    assert not extracted.exists()
    assert report.source == "upload.zip"
    assert {item.finding_type.value for item in report.findings} == {
        "missing_auth",
        "missing_input_validation",
        "missing_environment_variable",
    }


@pytest.mark.parametrize(
    "name", ["../evil.py", "/absolute.py", "C:/drive.py", "..\\evil.py", "ok/../../evil.py"]
)
def test_zip_path_escape_rejected(tmp_path, name):
    upload = archive(tmp_path, [(name, b"x")])
    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(IngestionError, match="unsafe path"):
        extract_zip(upload, destination, ScanLimits())
    assert not (tmp_path / "evil.py").exists()


def symlink_archive(tmp_path):
    link = zipfile.ZipInfo("link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    return archive(tmp_path, [(link, b"/etc/passwd")])


def duplicate_archive(tmp_path):
    return archive(tmp_path, [("App.py", b"a"), ("app.py", b"b")])


def encrypted_archive(tmp_path):
    # zipfile clears flag_bits when writing, so set the encryption bit in the raw headers.
    data = bytearray(archive(tmp_path, [("secret.py", b"x")]).read_bytes())
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        data[data.index(signature) + offset] |= 0x1
    path = tmp_path / "encrypted.zip"
    path.write_bytes(bytes(data))
    return path


@pytest.mark.parametrize(
    "build,message",
    [
        (symlink_archive, "linked"),
        (duplicate_archive, "duplicate"),
        (encrypted_archive, "encrypted"),
    ],
)
def test_zip_unsafe_entry_kinds_rejected(tmp_path, build, message):
    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(IngestionError, match=message):
        extract_zip(build(tmp_path), destination, ScanLimits())


def test_zip_bomb_and_size_limits(tmp_path):
    bomb = archive(tmp_path, [("zeros.txt", b"\0" * (5 * 1024 * 1024))], "bomb.zip")
    assert bomb.stat().st_size < 100_000
    destination = tmp_path / "bomb"
    destination.mkdir()
    with pytest.raises(IngestionError, match="compression ratio"):
        extract_zip(bomb, destination, ScanLimits(max_file_bytes=10 * 1024 * 1024))
    assert not any(destination.iterdir())

    checks = [
        ([("a.txt", b"a" * 800), ("b.txt", b"b" * 800)], ScanLimits(max_total_bytes=1500), "total"),
        ([("big.txt", b"a" * 11)], ScanLimits(max_file_bytes=10), "individual file size"),
        ([(f"{n}.py", b"") for n in range(5)], ScanLimits(max_files=2), "entry count"),
        ([("a/b/c/d.py", b"")], ScanLimits(max_depth=3), "depth"),
    ]
    for number, (entries, limits, message) in enumerate(checks):
        destination = tmp_path / f"limit{number}"
        destination.mkdir()
        with pytest.raises(IngestionError, match=message):
            extract_zip(archive(tmp_path, entries, f"limit{number}.zip"), destination, limits)


def test_invalid_archive_and_unknown_source_rejected(tmp_path):
    fake = tmp_path / "fake.zip"
    fake.write_bytes(b"not a zip")
    with pytest.raises(IngestionError, match="invalid zip"), ingest(str(fake), ScanLimits()):
        pass
    with pytest.raises(IngestionError, match="must be a directory"):
        with ingest(str(tmp_path / "missing"), ScanLimits()):
            pass


def public(host, port, family=0, kind=0):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.112.3", port))]


def resolving_to(address):
    return lambda host, port, family=0, kind=0: [(socket.AF_INET, kind, 6, "", (address, port))]


def test_git_url_validation():
    validate_git_url("https://github.com/owner/repo.git", resolver=public)
    rejected = {
        "http://github.com/owner/repo.git": "only https",
        "ssh://git@github.com/owner/repo.git": "only https",
        "git@github.com:owner/repo.git": "only https",
        "file:///etc": "only https",
        "https://user:token@github.com/owner/repo.git": "credentials",
        "https://github.com/owner/repo.git?ref=main": "query",
        "https://github.com:8443/owner/repo.git": "custom port",
        "https://github.com/owner/repo .git": "invalid",
    }
    for url, message in rejected.items():
        with pytest.raises(IngestionError, match=message):
            validate_git_url(url, resolver=public)
    for address in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::1"):
        with pytest.raises(IngestionError, match="non-public"):
            validate_git_url("https://internal.example/repo.git", resolver=resolving_to(address))


def test_non_https_reference_never_starts_git(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "agent.ingest.subprocess.Popen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("git must not run")),
    )
    with pytest.raises(IngestionError, match="only https"):
        with ingest((tmp_path / "repo").as_uri(), ScanLimits()):
            pass


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def git(*args, cwd, stdin=None):
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            f"core.hooksPath={os.devnull}",
            *args,
        ],
        cwd=cwd,
        input=stdin,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout.strip()


@needs_git
def test_real_clone_is_hardened_and_strips_git_metadata(tmp_path):
    remote = tmp_path / "remote"
    (remote / "src").mkdir(parents=True)
    (remote / "src" / "app.py").write_text("print('static only')\n", encoding="utf-8")
    git("init", "--quiet", cwd=remote)
    git("add", ".", cwd=remote)
    # A committed symlink must arrive as a plain file, never as a link out of the tree.
    blob = git("hash-object", "-w", "--stdin", cwd=remote, stdin="../../outside")
    git("update-index", "--add", "--cacheinfo", f"120000,{blob},escape", cwd=remote)
    git("commit", "--quiet", "-m", "fixture", cwd=remote)
    head = git("rev-parse", "HEAD", cwd=remote)

    destination = tmp_path / "work" / "repo"
    destination.parent.mkdir()
    revision = clone(remote.as_uri(), destination, ScanLimits(), protocols=("file",))
    assert revision == head
    assert not (destination / ".git").exists()
    assert (destination / "src" / "app.py").read_text(encoding="utf-8") == "print('static only')\n"
    escape = destination / "escape"
    assert escape.is_file() and not escape.is_symlink()
    report = ScanService(Settings(), external_detectors=False).scan(destination)
    assert report.complete


@needs_git
def test_real_clone_refuses_transports_outside_allowlist(tmp_path):
    remote = tmp_path / "remote"
    remote.mkdir()
    (remote / "a.txt").write_text("a", encoding="utf-8")
    git("init", "--quiet", cwd=remote)
    git("add", ".", cwd=remote)
    git("commit", "--quiet", "-m", "fixture", cwd=remote)
    destination = tmp_path / "work" / "repo"
    destination.parent.mkdir()
    with pytest.raises(IngestionError, match="clone failed"):
        clone(remote.as_uri(), destination, ScanLimits())  # https-only by default


def test_extracted_bytes_match_archive(tmp_path):
    payload = os.urandom(4096)
    upload = archive(tmp_path, [("data/blob.bin", payload), ("data/", b"")])
    destination = tmp_path / "out"
    destination.mkdir()
    extract_zip(upload, destination, ScanLimits())
    assert (destination / "data" / "blob.bin").read_bytes() == payload
