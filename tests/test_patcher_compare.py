import os
import shutil
from pathlib import Path

import py7zr
import pytest

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from opl480pcheatgen.patcher import patch_elf


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


def _binary_eq(p1: Path, p2: Path) -> bool:
    return p1.read_bytes() == p2.read_bytes()


def test_patch_artonelico2(tmp_path):
    root = _extract("artonelico2_test_files.7z", tmp_path)
    orig = root / "SLES_554.44"
    expected = root / "SLES_554.44_OPL480p"
    patched = tmp_path / "patched.elf"
    shutil.copyfile(orig, patched)
    patch_elf(str(patched), dy=51)
    assert _binary_eq(patched, expected)


def test_patch_persona4(tmp_path):
    root = _extract("Persona4_test_files.7z", tmp_path)
    orig = root / "SLUS_217.82"
    expected = root / "SLUS_217.82_PS2Force480p"
    patched = tmp_path / "persona4_patched.elf"
    shutil.copyfile(orig, patched)
    patch_elf(str(patched), aggressive=True)
    assert _binary_eq(patched, expected)
