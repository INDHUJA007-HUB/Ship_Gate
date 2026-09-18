from pathlib import Path

import pytest

from agent.config import ScanLimits
from agent.preflight import PreflightError, inspect_tree


def test_preflight_hash_is_stable_and_binary_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text("print('static only')\n", encoding="utf-8")
    (tmp_path / "image.bin").write_bytes(b"\x00not source")
    first = inspect_tree(tmp_path, ScanLimits())
    second = inspect_tree(tmp_path, ScanLimits())
    assert first.content_hash == second.content_hash
    assert first.skipped_binaries == ("image.bin",)
    assert [item.name for item in first.files] == ["source.py"]


def test_preflight_rejects_oversized_file(tmp_path: Path) -> None:
    (tmp_path / "large.txt").write_text("x" * 11, encoding="utf-8")
    with pytest.raises(PreflightError, match="individual file size"):
        inspect_tree(tmp_path, ScanLimits(max_file_bytes=10))


def test_preflight_rejects_excessive_depth(tmp_path: Path) -> None:
    nested = tmp_path / "one" / "two" / "three"
    nested.mkdir(parents=True)
    (nested / "source.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(PreflightError, match="directory depth"):
        inspect_tree(tmp_path, ScanLimits(max_depth=3))


def test_binary_changes_invalidate_hash(tmp_path):
    path = tmp_path / "asset.bin"
    path.write_bytes(b"\x00a")
    first = inspect_tree(tmp_path, ScanLimits()).content_hash
    path.write_bytes(b"\x00b")
    assert inspect_tree(tmp_path, ScanLimits()).content_hash != first


def test_directory_only_exhaustion_is_bounded(tmp_path):
    for number in range(5):
        (tmp_path / str(number)).mkdir()
    with pytest.raises(PreflightError, match="entry count"):
        inspect_tree(tmp_path, ScanLimits(max_files=2))


def test_symlink_rejected(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("data")
    try:
        (tmp_path / "link").symlink_to(target)
    except OSError:
        pytest.skip("Windows symlink privilege is unavailable")
    with pytest.raises(PreflightError, match="linked"):
        inspect_tree(tmp_path, ScanLimits())
