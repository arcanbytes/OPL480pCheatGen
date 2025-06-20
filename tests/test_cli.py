import os
import sys
from pathlib import Path

import py7zr
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from opl480pcheatgen.patches import extract_patches


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


def test_extract_without_interlace_sles(tmp_path):
    archive_name = "artonelico2_test_files.7z" 
    
    root_extracted_files = _extract(archive_name, tmp_path)
    
    elf_path = root_extracted_files / "SLES_554.44"

    cheats, _gid, _title = extract_patches(
        str(elf_path),
        interlace_patch=False,
        force_240p=False,
        include_init_constants=True,
    )
    titles = [c[0] for c in cheats[1:]]

    assert "//Force 480p Progressive" not in titles
    assert "//Init constants" not in titles