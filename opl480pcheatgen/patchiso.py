"""Command-line tool to patch ISO images by modifying the boot ELF."""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys
import tempfile

from elftools.elf.elffile import ELFFile

from .patches import extract_patches

try:
    import pycdlib
except ImportError:  # pragma: no cover
    pycdlib = None


def _find_boot_path(iso: pycdlib.PyCdlib, override: str | None) -> str:
    """Return the boot ELF path inside *iso*."""
    if override:
        p = '/' + override.upper()
        if not p.endswith(';1'):
            p += ';1'
        return p
    with tempfile.NamedTemporaryFile(delete=False, suffix=".cnf") as tmp:
        iso.get_file_from_iso(iso_path='/SYSTEM.CNF;1', local_path=tmp.name)
        with open(tmp.name, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip().upper()
                if "BOOT2" in line and "CDROM0:\\" in line:
                    m = re.search(r'CDROM0:\\([^\s;]+);?1?', line)
                    if m:
                        return '/' + m.group(1).upper() + ';1'
    raise RuntimeError('Could not determine BOOT2 path from SYSTEM.CNF')


def _apply_patches_to_elf(path: str, codes: list[tuple[int, int]]):
    """Apply cheat codes directly to the ELF binary."""
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        segs = [
            (seg['p_vaddr'], seg['p_offset'], seg['p_filesz'])
            for seg in elf.iter_segments()
            if seg['p_type'] == 'PT_LOAD'
        ]
    with open(path, 'r+b') as f:
        for addr, val in codes:
            if addr >> 24 != 0x20:
                continue
            a = addr & 0x00FFFFFF
            for base, off, size in segs:
                if base <= a < base + size:
                    f.seek(off + (a - base))
                    # PS2 executables are little-endian
                    f.write(struct.pack('<I', val))
                    break
            else:
                print(f"[WARN] Address 0x{a:08X} not within ELF sections")


def build_arg_parser() -> argparse.ArgumentParser:
    """Return the argument parser for ISO patching."""
    p = argparse.ArgumentParser(description="Patch ISO image directly")
    p.add_argument('iso', help='ISO image to patch')
    p.add_argument('--elfpath', help='Path inside ISO to ELF (e.g. SLUS_123.45;1)')
    p.add_argument('--no-interlace-patch', dest='interlace_patch', action='store_false',
                   help='Disable No-Interlace patch (enabled by default)')
    p.add_argument('--force-240p', dest='force_240p', action='store_true',
                   help='Force the game into 240p progressive mode')
    p.add_argument('--pal60', dest='pal60', action='store_true',
                   help='Enable PAL 60Hz patch for PAL region games')
    p.add_argument('--dy', dest='dy', type=int, help='Override GS DY value (vertical offset)')
    p.add_argument('--aggressive', dest='aggressive', action='store_true',
                   help='Aggressively patch DISPLAY writes')
    p.add_argument('--debug-aggr', dest='debug_aggr', action='store_true',
                   help='Print potential DISPLAY writes for analysis')
    p.add_argument('--aggr-skipcheck', dest='force_aggr_skip', action='store_true',
                   help='Override safety checks during aggressive patching')
    p.add_argument('--injhook', dest='inject_hook', type=lambda x: int(x, 16),
                   help='Manual hook address for aggressive patch', metavar='HOOK')
    p.add_argument('--injhandler', dest='inject_handler', type=lambda x: int(x, 16),
                   help='Manual handler address for aggressive patch', metavar='HANDLER')
    return p


def main(argv: list[str] | None = None) -> int:
    """Program entry point for ISO patching."""
    if not pycdlib:
        print('pycdlib is required to patch ISO images')
        return 1
    parser = build_arg_parser()
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    if args.dy is not None and not (-100 <= args.dy <= 100):
        print('Error: --dy must be between -100 and 100.')
        return 1
    print(f"[INFO] Patching ISO {args.iso}")
    iso = pycdlib.PyCdlib()
    iso.open(args.iso)
    try:
        boot = _find_boot_path(iso, args.elfpath)
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
        interlace_patch=args.interlace_patch,
        force_240p=args.force_240p,
        pal60=args.pal60,
        new_dy=args.dy,
        aggressive=args.aggressive,
        debug_aggr=args.debug_aggr,
        force_aggr_skip=args.force_aggr_skip,
        inject_hook=args.inject_hook,
        inject_handler=args.inject_handler,
    )
    patch_lines = []
    for _hdr, codes in cheats[1:]:
        patch_lines.extend(codes)
    _apply_patches_to_elf(tmp.name, patch_lines)

    if os.path.getsize(tmp.name) != record.data_length:
        print('Error: Patched ELF size changed; cannot apply in-place')
        return 1

    with open(args.iso, 'r+b') as iso_fp, open(tmp.name, 'rb') as fp:
        iso_fp.seek(record.extent_location() * block_size)
        iso_fp.write(fp.read())
    print('[INFO] ISO patched successfully')
    return 0


if __name__ == '__main__':  # pragma: no cover
    raise SystemExit(main())
