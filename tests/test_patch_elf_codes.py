import os
import sys
from pathlib import Path

import py7zr
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from opl480pcheatgen.patch_generation import extract_patches
from opl480pcheatgen import patcher


def _extract(name: str, tmp_path: Path) -> Path:
    """Extract 7z archive *name* into *tmp_path* and return root dir."""
    arch_path = Path(__file__).parent.parent / ".temp" / name
    if not arch_path.exists():
        pytest.skip(f"archive {arch_path} not available")
    with py7zr.SevenZipFile(arch_path, mode="r") as zf:
        zf.extractall(path=tmp_path)
    # archive contains a single folder
    [root] = list(tmp_path.iterdir())
    return root


@pytest.mark.parametrize(
    "archive_filename,elf_name",
    [
        ("Persona4_test_files.7z", "SLUS_217.82"),
        ("artonelico2_test_files.7z", "SLES_554.44"),
    ],
)
def test_patch_elf_uses_generated_codes(tmp_path, monkeypatch, archive_filename, elf_name):
    root = _extract(archive_filename, tmp_path)
    elf_path = root / elf_name

    cheats, _gid, _title = extract_patches(str(elf_path))
    expected = []
    for _hdr, codes in cheats[1:]:
        expected.extend(codes)

    captured = []

    def fake_apply(path: str, codes: list[tuple[int, int]]):
        captured.extend(codes)

    monkeypatch.setattr(patcher, "_apply_codes_to_elf", fake_apply)
    patcher.patch_elf(str(elf_path))

    assert captured == expected
