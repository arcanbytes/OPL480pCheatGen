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


def _open_iso(iso_path: str) -> "pycdlib.PyCdlib":
    """Return a ``PyCdlib`` instance opened on *iso_path*.

    Work around images that report UDF descriptors but only contain a
    single anchor by retrying without parsing UDF when that error is
    encountered.
    """
    from pycdlib.pycdlibexception import PyCdlibInvalidISO, PyCdlibInvalidInput

    def _open(cls: type[pycdlib.PyCdlib]) -> pycdlib.PyCdlib:
        iso = cls()
        iso.open(iso_path)
        return iso

    try:
        return _open(pycdlib.PyCdlib)
    except PyCdlibInvalidInput:
        raise
    except PyCdlibInvalidISO as e:
        if "UDF Anchors" not in str(e):
            raise
        class NoUDF(pycdlib.PyCdlib):
            def _parse_udf_descriptors(self):  # type: ignore[override]
                # Disable UDF handling on malformed descriptors
                self._has_udf = False

            def _walk_udf_directories(self, extent_to_inode):  # type: ignore[override]
                # Skip walking the UDF filesystem entirely
                return
        return _open(NoUDF)


def extract_boot_id_from_iso(iso_path: str) -> Optional[str]:
    """Return the BOOT2 ID from an ISO image if possible."""
    if not pycdlib:
        return None
    iso = _open_iso(iso_path)
    try:
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
    db_path = None
    
    # 1. Definir la ruta del archivo externo (next to the .exe or .py script)
    # Si es un ejecutable, usamos os.path.dirname(sys.executable)
    # Si es un script .py, usamos os.path.dirname(os.path.abspath(__file__))
    current_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
    external_db_path = os.path.join(current_dir, 'mastercodes.json')

    # 2. Priorizar el archivo externo si existe
    if os.path.exists(external_db_path):
        db_path = external_db_path
    
    # 3. Si no es un archivo externo Y estamos en un ejecutable congelado, buscar el archivo embebido
    elif getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # sys._MEIPASS es el directorio temporal donde PyInstaller desempaqueta los datos
        embedded_db_path = os.path.join(sys._MEIPASS, 'mastercodes.json')
        if os.path.exists(embedded_db_path):
            db_path = embedded_db_path

    # 4. Si no se encontró ninguna ruta válida, advertir y salir
    if not db_path:
        print("[WARN] Local mastercode database (mastercodes.json) not found.")
        return None, None

    # 5. Abrir y cargar la base de datos
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            db = json.load(f)
        entry = db.get(base)
        if entry:
            return entry["title"], entry["mastercode"]
        return None, None
    except Exception as e:
        print(f"[ERROR] Failed to load mastercode database from {db_path}: {e}")
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
    try:
        iso = _open_iso(iso_path)
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

