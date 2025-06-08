"""Utility helpers used by OPL480pCheatGen."""

from __future__ import annotations

import os
import sys
import json
import re
import struct
import tempfile
from typing import Iterable, List, Tuple, Optional

try:
    import pycdlib
except ImportError:  # pragma: no cover
    pycdlib = None


def extract_boot_id_from_iso(iso_path: str) -> Optional[str]:
    """Return the BOOT2 ID from an ISO image if possible."""
    if not pycdlib:
        return None
    iso = pycdlib.PyCdlib()
    try:
        iso.open(iso_path)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cnf") as tmp:
            iso.get_file_from_iso(iso_path='/SYSTEM.CNF;1', local_path=tmp.name)
            with open(tmp.name, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip().upper()
                    if "BOOT2" in line and "CDROM0:\\" in line:
                        match = re.search(r'CDROM0:\\([A-Z]{4}_\d{3}\.\d{2});1', line)
                        if match:
                            return match.group(1)
    except Exception as e:  # pragma: no cover - diagnostic
        print(f"[WARN] Could not extract SYSTEM.CNF boot ID: {e}")
    finally:
        iso.close()
    return None


def find_pattern(data: bytes, pat: bytes) -> int:
    """Return the first offset of *pat* in *data* aligned to 4 bytes or ``-1``."""
    for off in range(0, len(data) - len(pat), 4):
        if data[off:off + len(pat)] == pat:
            return off
    return -1


def fetch_mastercode(base: str) -> Tuple[Optional[str], Optional[str]]:
    """Lookup *base* in ``mastercodes.json`` returning ``(title, code)``."""
    candidates = []
    if getattr(sys, 'frozen', False):
        # When packaged with PyInstaller, the data may reside in the
        # temporary extraction folder (``sys._MEIPASS``) or alongside the
        # executable depending on the build settings.
        candidates.append(os.path.join(getattr(sys, '_MEIPASS', os.path.dirname(sys.executable)), 'mastercodes.json'))
        candidates.append(os.path.join(os.path.dirname(sys.executable), 'mastercodes.json'))
    else:
        candidates.append(os.path.join(os.path.dirname(__file__), '../mastercodes.json'))

    db_path = next((p for p in candidates if os.path.exists(p)), None)
    if not db_path:
        print("[WARN] Local mastercode database not found.")
        return None, None

    with open(db_path, 'r', encoding='utf-8') as f:
        db = json.load(f)
    entry = db.get(base)
    if entry:
        return entry["title"], entry["mastercode"]
    return None, None


def parse_elf_strings(path: str, patterns: Iterable[bytes]) -> List[str]:
    """Return a list of text strings from *path* matching *patterns*."""
    found = set()
    try:
        data = open(path, 'rb').read()
        for pat in patterns:
            if re.search(pat, data, re.IGNORECASE):
                found.add(pat.decode('ascii', 'ignore'))
    except Exception:
        pass
    return sorted(found)


def write_cht(output_dir: str, cheats: list, game_id: str, title: str) -> str:
    """Write *cheats* to ``<game_id>.cht`` in *output_dir* and return its path."""
    out_name = f"{game_id}.cht"
    if getattr(sys, 'frozen', False):
        actual_output_dir = os.path.dirname(sys.executable)
    else:
        actual_output_dir = os.path.join(output_dir)
    out_path = os.path.join(actual_output_dir, out_name)
    print(f"\nGenerating {out_path}...")
    with open(out_path, 'w', encoding='utf-8') as c:
        c.write(f"{cheats[0][0]}\nMastercode\n{cheats[0][1]}\n\n")
        for hdr, codes in cheats[1:]:
            c.write(f"{hdr}\n")
            for a, v in codes:
                c.write(f"{a:08X} {v:08X}\n")
            c.write("\n")
    print(f"[INFO] Wrote: {out_path}\n")
    return out_path


def extract_from_iso(iso_path: str, elf_override: str | None = None) -> Tuple[str, str]:
    """Extract the ELF from *iso_path* and return ``(path, base_name)``."""
    if not pycdlib:
        raise RuntimeError("pycdlib is required to read ISO images")
    from pycdlib.pycdlibexception import PyCdlibInvalidInput
    iso = pycdlib.PyCdlib()
    try:
        iso.open(iso_path)
    except PyCdlibInvalidInput:
        print("[ERROR] Not a valid ISO file.")
        sys.exit(1)
    boot_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cnf") as tmp:
            iso.get_file_from_iso(iso_path='/SYSTEM.CNF;1', local_path=tmp.name)
            with open(tmp.name, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip().upper()
                    if "BOOT2" in line and "CDROM0:\\" in line:
                        match = re.search(r'CDROM0:\\([^\s;]+);?1?', line)
                        if match:
                            boot_path = '/' + match.group(1).upper() + ';1'
                            break
    except Exception as e:  # pragma: no cover
        print(f"[WARN] Failed to read SYSTEM.CNF: {e}")
    if not boot_path:
        print("Error: Could not determine BOOT2 path from SYSTEM.CNF.")
        sys.exit(1)
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as tmp:
            iso.get_file_from_iso(iso_path=boot_path, local_path=tmp.name)
            base = os.path.basename(boot_path).split(';')[0]
            print(f"[INFO] Extracted ELF {boot_path} --> {tmp.name}, base='{base}'")
            iso.close()
            return tmp.name, base
    except Exception as e:
        print(f"[ERROR] Failed to extract ELF: {e}")
        sys.exit(1)


def format_cht_text(cheats: List[Tuple[str, List[Tuple[int, int]]]]) -> str:
    """Return a formatted cheat text block."""
    lines = [cheats[0][0], "Mastercode", f"{cheats[0][1]}\n"]
    for hdr, codes in cheats[1:]:
        lines.append(hdr)
        for a, v in codes:
            lines.append(f"{a:08X} {v:08X}")
        lines.append("")
    return "\n".join(lines).strip()

