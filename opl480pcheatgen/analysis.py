"""ELF scanning helpers and pattern constants."""

from __future__ import annotations

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN
from capstone.mips import MIPS_OP_MEM
from elftools.elf.elffile import ELFFile

from typing import List, Tuple

from .helpers import find_pattern
from .aggressive import DISPLAY1_ADDR, DISPLAY2_ADDR, SMODE2_ADDR, scan_sd

# --- Signature constants ---
SCEGSRESETGRAPH_SIG = bytes([
    0xB0, 0xFF, 0xBD, 0x27, 0x00, 0x24, 0x04, 0x00, 0x30, 0x00,
    0xB3, 0xFF, 0x00, 0x2C, 0x05, 0x00, 0x20, 0x00, 0xB2, 0xFF,
    0x00, 0x34, 0x06, 0x00, 0x10, 0x00, 0xB1, 0xFF, 0x00, 0x3C,
    0x07, 0x00, 0x40, 0x00, 0xBF, 0xFF, 0x03, 0x24, 0x04, 0x00,
    0x00, 0x00, 0xB0, 0xFF, 0x03, 0x8C, 0x05, 0x00, 0x03, 0x94,
    0x06, 0x00,
])

SCEGSPUTDISPENV_SIG = bytes([
    0x2D, 0x80, 0x80, 0x00, 0x06, 0x00, 0x43, 0x84,
    0x01, 0x00, 0x02, 0x24, 0x11, 0x00, 0x62, 0x14,
])

CLOBBER_STR1 = b"sceGsExecStoreImage: Enough data does not reach VIF1"
CLOBBER_STR2 = b"sceGsExecStoreImage: DMA Ch.1 does not terminate"

VSYNC_HANDLER_SIG = bytes([
    0x00, 0x12, 0x02, 0x3C, 0x00, 0x10, 0x42, 0xDC,
    0x7A, 0x13, 0x02, 0x00, 0x01, 0x00, 0x42, 0x30,
    0x06, 0x00, 0x40, 0x14, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x42,
])

# Strings to look for when detecting supported modes
ELF_MODE_PATTERNS = [
    b"480p",
    b"240p",
    b"progressive",
    b"interlaced",
    b"60HZ",
    b"PAL60",
    b"60 HZ",
]


def analyze_display(insns, interlace_patch: bool = False, debug: bool = False):
    """Locate potential DISPLAY register writes."""
    matches = []
    details = []
    suspect_bases = {2, 3, 4, 5, 6, 7}
    for i, ins in enumerate(insns):
        if ins.mnemonic != "sd" or not ins.operands:
            continue
        mem_op = ins.operands[1]
        if mem_op.type != MIPS_OP_MEM:
            continue
        addr = mem_op.mem.disp
        base = getattr(mem_op.mem, "base", None)
        if addr in (0x80, 0xA0) and (base is None or base in suspect_bases):
            matches.append((i, ins))
            if debug:
                details.append(
                    f"[MATCH] Address: 0x{ins.address:08X}, Instruction: {ins.mnemonic}, Operands: {ins.op_str} -> Suspect write to DISPLAYx"
                )
        elif debug:
            why = []
            if addr not in (0x80, 0xA0):
                why.append(f"disp != 0x80/0xA0 (was 0x{addr:X})")
            if base not in suspect_bases:
                why.append(f"base={base} not in $v0-$a3")
            details.append(
                f"[SKIP] Address: 0x{ins.address:08X}, Instruction: {ins.mnemonic}, Operands: {ins.op_str} -> Reasons: {'; '.join(why)}"
            )
    return matches, details


def scan_elf_for_patterns(elf_path: str, interlace_patch: bool, aggressive: bool):
    """Scan *elf_path* for various patterns used by patch generation."""
    reset = None
    aggr_hits: List[tuple] = []
    smode2_hits: List[tuple] = []
    default_mode = None
    all_insns: List = []

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        endian_mode = CS_MODE_LITTLE_ENDIAN if elf.little_endian else CS_MODE_BIG_ENDIAN
        endian = "<" if elf.little_endian else ">"
        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + endian_mode)
        md.detail = True
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            data, vaddr = seg.data(), seg["p_vaddr"]
            if reset is None:
                off = find_pattern(data, SCEGSRESETGRAPH_SIG)
                if off >= 0:
                    reset = vaddr + off
            insns = list(md.disasm(data, vaddr))
            all_insns.extend(insns)
            matches, _dbg = analyze_display(insns, interlace_patch, aggressive)
            if aggressive:
                aggr_hits.extend(scan_sd(data, vaddr, DISPLAY1_ADDR, endian))
                aggr_hits.extend(scan_sd(data, vaddr, DISPLAY2_ADDR, endian))
            smode2_hits.extend(scan_sd(data, vaddr, SMODE2_ADDR, endian))

    return {
        "reset": reset,
        "aggr_hits": aggr_hits,
        "smode2_hits": smode2_hits,
        "all_insns": all_insns,
    }
