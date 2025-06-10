"""Utility functions to patch ISO images or ELF files in place."""

from __future__ import annotations

import os
import re
import struct
import tempfile

from elftools.elf.elffile import ELFFile

from .patches import extract_patches

try:
    import pycdlib
except ImportError:  # pragma: no cover
    pycdlib = None


def _apply_codes_to_elf(path: str, codes: list[tuple[int, int]]):
    """Apply cheat codes directly to the ELF binary."""
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        segments = [
            (seg['p_vaddr'], seg['p_offset'], seg['p_filesz'])
            for seg in elf.iter_segments()
            if seg['p_type'] == 'PT_LOAD'
        ]
    with open(path, 'r+b') as f:
        for addr, val in codes:
            if addr >> 24 != 0x20:
                continue
            a = addr & 0x00FFFFFF
            for base, off, size in segments:
                if base <= a < base + size:
                    f.seek(off + (a - base))
                    f.write(struct.pack('<I', val))
                    break
            else:
                print(f"[WARN] Address 0x{a:08X} not within ELF sections")


def patch_elf(
    path: str,
    *,
    interlace_patch: bool = True,
    force_240p: bool = False,
    pal60: bool = False,
    dy: int | None = None,
    aggressive: bool = False,
    debug_aggr: bool = False,
    force_aggr_skip: bool = False,
    inject_hook: int | None = None,
    inject_handler: int | None = None,
) -> int:
    """Patch *path* ELF file in place."""
    cheats, _gid, _title = extract_patches(
        path,
        interlace_patch=interlace_patch,
        force_240p=force_240p,
        pal60=pal60,
        new_dy=dy,
        aggressive=aggressive,
        debug_aggr=debug_aggr,
        force_aggr_skip=force_aggr_skip,
        inject_hook=inject_hook,
        inject_handler=inject_handler,
    )
    patch_lines = []
    for _hdr, codes in cheats[1:]:
        patch_lines.extend(codes)
    _apply_codes_to_elf(path, patch_lines)
    print('[INFO] ELF patched successfully')
    return 0


def _find_boot_path(iso: pycdlib.PyCdlib, override: str | None) -> str:
    """Return the boot ELF path inside *iso*."""
    if override:
        p = '/' + override.upper()
        if not p.endswith(';1'):
            p += ';1'
        return p
    with tempfile.NamedTemporaryFile(delete=False, suffix='.cnf') as tmp:
        iso.get_file_from_iso(iso_path='/SYSTEM.CNF;1', local_path=tmp.name)
        with open(tmp.name, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip().upper()
                if 'BOOT2' in line and 'CDROM0:\\' in line:
                    m = re.search(r'CDROM0:\\([^\s;]+);?1?', line)
                    if m:
                        return '/' + m.group(1).upper() + ';1'
    raise RuntimeError('Could not determine BOOT2 path from SYSTEM.CNF')


def patch_iso(
    iso_path: str,
    *,
    elfpath: str | None = None,
    interlace_patch: bool = True,
    force_240p: bool = False,
    pal60: bool = False,
    dy: int | None = None,
    aggressive: bool = False,
    debug_aggr: bool = False,
    force_aggr_skip: bool = False,
    inject_hook: int | None = None,
    inject_handler: int | None = None,
) -> int:
    """Patch the boot ELF inside *iso_path*."""
    if not pycdlib:
        print('pycdlib is required to patch ISO images')
        return 1
    iso = pycdlib.PyCdlib()
    iso.open(iso_path)
    try:
        boot = _find_boot_path(iso, elfpath)
        record = iso.get_record(iso_path=boot)
        block_size = iso.logical_block_size
        with tempfile.NamedTemporaryFile(delete=False, suffix='.elf') as tmp:
            iso.get_file_from_iso(iso_path=boot, local_path=tmp.name)
    finally:
        iso.close()

    base = os.path.basename(boot).split(';')[0]
    cheats, _gid, _title = extract_patches(
        tmp.name,
        base_override=base,
        interlace_patch=interlace_patch,
        force_240p=force_240p,
        pal60=pal60,
        new_dy=dy,
        aggressive=aggressive,
        debug_aggr=debug_aggr,
        force_aggr_skip=force_aggr_skip,
        inject_hook=inject_hook,
        inject_handler=inject_handler,
    )
    patch_lines = []
    for _hdr, codes in cheats[1:]:
        patch_lines.extend(codes)
    _apply_codes_to_elf(tmp.name, patch_lines)

    if os.path.getsize(tmp.name) != record.data_length:
        print('Error: Patched ELF size changed; cannot apply in-place')
        return 1

    with open(iso_path, 'r+b') as iso_fp, open(tmp.name, 'rb') as fp:
        iso_fp.seek(record.extent_location() * block_size)
        iso_fp.write(fp.read())
    print('[INFO] ISO patched successfully')
    return 0
