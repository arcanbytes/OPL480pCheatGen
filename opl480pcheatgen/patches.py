"""Core patch extraction and analysis logic."""

from __future__ import annotations

import os
import re
import struct
import sys
from typing import List, Tuple

from elftools.elf.elffile import ELFFile
from capstone import (
    Cs,
    CS_ARCH_MIPS,
    CS_MODE_MIPS64,
    CS_MODE_BIG_ENDIAN,
    CS_MODE_LITTLE_ENDIAN,
)
from capstone.mips import MIPS_OP_MEM

from .helpers import (
    find_pattern,
    fetch_mastercode,
    parse_elf_strings,
    extract_boot_id_from_iso,
)
from .aggressive import (
    DISPLAY1_ADDR,
    DISPLAY2_ADDR,
    SMODE2_ADDR,
    generate_display_patch,
    scan_sd,
    _sd,
)

SCEGSRESETGRAPH_SIG = bytes(
    [
        0xB0,
        0xFF,
        0xBD,
        0x27,
        0x00,
        0x24,
        0x04,
        0x00,
        0x30,
        0x00,
        0xB3,
        0xFF,
        0x00,
        0x2C,
        0x05,
        0x00,
        0x20,
        0x00,
        0xB2,
        0xFF,
        0x00,
        0x34,
        0x06,
        0x00,
        0x10,
        0x00,
        0xB1,
        0xFF,
        0x00,
        0x3C,
        0x07,
        0x00,
        0x40,
        0x00,
        0xBF,
        0xFF,
        0x03,
        0x24,
        0x04,
        0x00,
        0x00,
        0x00,
        0xB0,
        0xFF,
        0x03,
        0x8C,
        0x05,
        0x00,
        0x03,
        0x94,
        0x06,
        0x00,
    ]
)

SCEGSPUTDISPENV_SIG = bytes(
    [
        0x2D,
        0x80,
        0x80,
        0x00,
        0x06,
        0x00,
        0x43,
        0x84,
        0x01,
        0x00,
        0x02,
        0x24,
        0x11,
        0x00,
        0x62,
        0x14,
    ]
)

CLOBBER_STR1 = b"sceGsExecStoreImage: Enough data does not reach VIF1"
CLOBBER_STR2 = b"sceGsExecStoreImage: DMA Ch.1 does not terminate"

VSYNC_HANDLER_SIG = bytes(
    [
        0x00,
        0x12,
        0x02,
        0x3C,
        0x00,
        0x10,
        0x42,
        0xDC,
        0x7A,
        0x13,
        0x02,
        0x00,
        0x01,
        0x00,
        0x42,
        0x30,
        0x06,
        0x00,
        0x40,
        0x14,
        0x00,
        0x00,
        0x00,
        0x00,
        0x0F,
        0x00,
        0x00,
        0x00,
        0x38,
        0x00,
        0x00,
        0x42,
    ]
)

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


def generate_putdispenv_patch(
    dy_value: int,
    base_addr: int,
    orig_inst: int,
    patch_offset: int = 0x100,
    return_offset: int = 12,
    return_addr: int | None = None,
    patch_addr: int | None = None,
):
    """Return cheat codes overriding DY via ``sceGsPutDispEnv``."""
    fv = patch_addr if patch_addr is not None else base_addr + patch_offset
    ret = return_addr if return_addr is not None else fv + return_offset
    vals = [
        orig_inst,
        0x8C900018,
        0x3C02FF80,
        0x24420FFF,
        0x00501024,
        0x24100000 | dy_value,
        0x00108300,
        0x02028025,
        0x08000000 | (ret // 4),
        0xAC900018,
    ]
    return [
        ((0x20 << 24) | ((fv + i * 4) & 0x00FFFFFF), val) for i, val in enumerate(vals)
    ]


def extract_patches(
    elf_path: str,
    base_override: str | None = None,
    manual_mc: str | None = None,
    interlace_patch: bool = True,
    force_240p: bool = False,
    pal60: bool = False,
    new_dy: int | None = None,
    aggressive: bool = False,
    debug_aggr: bool = False,
    force_aggr_skip: bool = False,
    inject_hook: int | None = None,
    inject_handler: int | None = None,
    include_init_constants: bool = False,
):
    """Extract patch codes from an ELF file.

    Parameters
    ----------
    include_init_constants
        Always include the Init constants cheat block even if the values
        are already present in the ELF.
    """
    fname = os.path.basename(elf_path)
    if base_override:
        base = base_override
    elif re.match(r"^[A-Z]{4}_\d{3}\.\d{2}$", fname):
        base = fname
    else:
        base = os.path.splitext(fname)[0]

    title, mc = (manual_mc and (f'"{base} /ID {base}"', manual_mc)) or fetch_mastercode(
        base
    )

    if title:
        title = title.replace("\ufeff", "").replace("“", '"').replace("”", '"').strip()
    if title and not (title.startswith('"') and title.endswith('"')):
        title = '"' + title.strip('"') + '"'

    if not title or not mc:
        print("[WARN] Missing title or mastercode. Proceeding with generic values.")
        boot_id = None
        if elf_path.lower().endswith(".elf") and os.path.exists(elf_path):
            iso_path_guess = None
            for p in sys.argv:
                if p.lower().endswith(".iso") and os.path.exists(p):
                    iso_path_guess = p
                    break
            if iso_path_guess:
                boot_id = extract_boot_id_from_iso(iso_path_guess)
        if not title:
            fallback_id = boot_id or base
            title = f'"{fallback_id} /ID {fallback_id}"'
        if not mc:
            mc = "00000000 00000000"

    print(f"\n=== {base} Cheater Summary ===")
    print(f"Title: {title}")
    print(f"Mastercode: {mc}")
    modes = parse_elf_strings(elf_path, ELF_MODE_PATTERNS)
    if modes:
        print(f"Supported modes in ELF: {', '.join(modes)}")
    has_60hz = any(m.lower() in ("60hz", "pal60", "60 hz") for m in modes)
    prefix = base.split("_")[0]
    region = "PAL" if prefix in ("SLES", "SCES") else "NTSC"
    print(f"Region: {region}")

    cheats = [(title, mc)]

    if force_240p:
        print("[INFO] Forcing 240p mode as requested.")
        w, h = 640, 240
        val_wh = (h << 11) | w
        params = {11: 0x24110000 | val_wh, 12: 0x24120000 | val_wh, 15: 0x24130001}
        patch_title = "//Force 240p Progressive"
    else:
        params = {11: 0x24110000, 12: 0x24120050, 15: 0x24130001}
        patch_title = "//Force 480p Progressive"

    reset = None
    default_mode = None
    all_d2 = []
    aggr_hits = []
    smode2_hits = []

    if not os.path.isfile(elf_path):
        sys.exit(f"Error: File not found: {elf_path}")

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
                    print(f"[INFO] Detected sceGsResetGraph at 0x{reset:08X}")
            insns = list(md.disasm(data, vaddr))
            matches, dbg = analyze_display(insns, interlace_patch, aggressive)
            if aggressive or debug_aggr:
                for logline in dbg:
                    print(logline)
                endian = "<" if elf.little_endian else ">"
                aggr_hits.extend(scan_sd(data, vaddr, DISPLAY1_ADDR, endian))
                aggr_hits.extend(scan_sd(data, vaddr, DISPLAY2_ADDR, endian))
            smode2_hits.extend(scan_sd(data, vaddr, SMODE2_ADDR, endian))

        if aggressive or debug_aggr:
            print(
                f"[DEBUG] Aggressive hits: {len(aggr_hits)} potential display writes found"
            )
            for addr, b, reg, prev_addr, prev_bytes, _prev in aggr_hits:
                prev_name = f"0x{_prev:08X}" if _prev is not None else "None"
                print(
                    f"  [DEBUG] sd @ {addr:08X} — reg: ${reg} — prev opcode: {prev_name}"
                )

        dy_patch = None
        if new_dy is not None:
            clobber_addr = None
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                data, seg_base = seg.data(), seg["p_vaddr"]
                for pat in (CLOBBER_STR1, CLOBBER_STR2):
                    pos = data.find(pat)
                    if pos >= 0:
                        clobber_addr = seg_base + pos
                        print(f"[INFO] Found clobber string at 0x{clobber_addr:08X}")
                        break
                if clobber_addr is not None:
                    break

            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                data, seg_base = seg.data(), seg["p_vaddr"]
                off = find_pattern(data, SCEGSPUTDISPENV_SIG)
                if off >= 0:
                    print(
                        f"[INFO] DY override via sceGsPutDispEnv detected at 0x{seg_base+off:08X}"
                    )
                    from_off = off - 16
                    orig_inst = struct.unpack(
                        endian + "I", data[from_off + 4 : from_off + 8]
                    )[0]
                    hook_addr = seg_base + from_off + 4
                    patch_addr = clobber_addr if clobber_addr else seg_base + 0x100
                    j_code = 0x08000000 | ((patch_addr // 4) & 0x03FFFFFF)
                    hook_patch = [((0x20 << 24) | (hook_addr & 0x00FFFFFF), j_code)]
                    ret_addr = seg_base + from_off + 12
                    dy_vals = generate_putdispenv_patch(
                        new_dy,
                        seg_base,
                        orig_inst,
                        return_addr=ret_addr,
                        patch_addr=patch_addr,
                    )
                    dy_patch = (f"//Vertical Offset DY={new_dy}", hook_patch + dy_vals)
                    break

        aggr_patch = None
        if aggressive and aggr_hits:
            clobber2 = None
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                data, seg_base = seg.data(), seg["p_vaddr"]
                pos = data.find(CLOBBER_STR2)
                if pos >= 0:
                    clobber2 = seg_base + pos
                    print(f"[INFO] Found clobber string #2 at 0x{clobber2:08X}")
                    break
            patch_base = (
                clobber2
                if clobber2 is not None
                else (aggr_hits[0][0] & 0xFFFF0000) + 0x100
            )
            patch_lines = []
            offset = 0
            for addr, b, reg, prev_addr, prev_bytes, prev_word in aggr_hits:
                if prev_addr is None:
                    print(
                        f"[WARN] No preceding instruction for sd at {addr:08X}. Skipping patch generation for this instruction."
                    )
                    continue
                ret_addr = addr + 4
                delay_opcode = struct.unpack(endian + "I", prev_bytes)[0]
                use_store = True
                store_insn = _sd(6 if reg == 5 else 5, 29, -8)
                opr = (prev_word >> 26) & 0x3F
                rs = (prev_word >> 21) & 0x1F
                rt = (prev_word >> 16) & 0x1F
                if opr == 4 and rs == 0 and rt == 0:
                    off = prev_word & 0xFFFF
                    if off & 0x8000:
                        off |= -0x10000
                    ret_addr = prev_addr + 4 + ((off & 0xFFFFFFFF) << 2)
                    delay_opcode = store_insn
                    use_store = False
                elif opr in (1, 7, 6, 5):
                    if not force_aggr_skip:
                        continue
                patch_addr = patch_base + offset
                j_code = 0x08000000 | ((patch_addr // 4) & 0x03FFFFFF)
                patch_lines.append(((0x20 << 24) | (prev_addr & 0x00FFFFFF), j_code))
                patch_lines.append(((0x20 << 24) | (addr & 0x00FFFFFF), delay_opcode))
                if len(b) == 4:
                    orig = struct.unpack(endian + "I", b)[0]
                    patch_lines.extend(
                        generate_display_patch(
                            orig, reg, patch_addr, ret_addr, use_store
                        )
                    )
                offset += (7 if use_store else 6) * 4
            aggr_patch = ("//Aggressive DISPLAY patch", patch_lines)

        manual_patch = None
        if inject_hook and inject_handler:
            print("[INFO] Injecting fixed aggressive patch manually.")
            vals = [
                0x3C020010,
                0x344226DC,
                0x8C820000,
                0x38420001,
                0xAC820000,
                0x3C021700,
                0x3442FFFC,
                0x3C030000,
                0x3463000F,
                0xAC430038,
                0x0800E003,
                0x00000000,
            ]
            manual_lines = [
                ((0x20 << 24) | ((inject_handler + i * 4) & 0x00FFFFFF), v)
                for i, v in enumerate(vals)
            ]
            manual_lines.append(
                (
                    (0x20 << 24) | (inject_hook & 0x00FFFFFF),
                    0x08000000 | (inject_handler // 4),
                )
            )
            manual_lines.append(
                ((0x20 << 24) | ((inject_hook + 4) & 0x00FFFFFF), 0x00000000)
            )
            manual_patch = ("//Aggressive DISPLAY patch", manual_lines)

        persona_patch = None
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            data, seg_base = seg.data(), seg["p_vaddr"]
            off = find_pattern(data, VSYNC_HANDLER_SIG)
            if off >= 0:
                patch_loc = seg_base + off
                print(f"[INFO] Persona 3/4 VSync handler detected at 0x{patch_loc:08X}")
                vals = [
                    0x00000000,
                    0x00000000,
                    0x8C820000,
                    0x38420001,
                    0xAC820000,
                    0x000217FC,
                    0x000217FF,
                    0x0000000F,
                    0x42000038,
                    0x03E00008,
                    0x00000000,
                ]
                data_loc = patch_loc + len(vals) * 4
                vals[0] = 0x3C040000 | (data_loc >> 16)
                vals[1] = 0x34840000 | (data_loc & 0xFFFF)
                vals.append(0x00000001)
                persona_patch = (
                    "//Persona 3/4 frame rate fix",
                    [
                        ((0x20 << 24) | ((patch_loc + i * 4) & 0x00FFFFFF), v)
                        for i, v in enumerate(vals)
                    ],
                )
                break

    print("[INFO] Defaulting to 480i @ 640×448 if not overridden.")
    if default_mode:
        w0, h0, i0 = default_mode
        print(f"[INFO] Game default: {w0}×{h0} {'interlaced' if i0 else 'progressive'}")

    if reset:
        need_patch = (
            force_240p or not default_mode or (not default_mode[2] and not force_240p)
        )
        if need_patch:
            codes = [
                ((0x20 << 24) | ((reset + o * 4) & 0x00FFFFFF), v)
                for o, v in params.items()
            ]
            cheats.append((patch_title, codes))
            print(f"[INFO] Applying {patch_title[2:]}.")
        else:
            print(f"[INFO] Skipping {patch_title[2:]}.")

    if dy_patch:
        cheats.append(dy_patch)
    if manual_patch:
        cheats.append(manual_patch)
    elif aggr_patch:
        cheats.append(aggr_patch)
    if persona_patch:
        cheats.append(persona_patch)

    pal60_block = None
    if region == "PAL" and pal60:
        if smode2_hits:
            print(
                f"[DEBUG] Found SMODE2 write at 0x{smode2_hits[0][0]:08X} \u2192 generating PAL60 override"
            )
            patch_base = (smode2_hits[0][0] & 0xFFFF0000) + 0x200
            patch_lines = []
            offset = 0
            for addr, b, reg, prev_addr, prev_bytes, prev_word in smode2_hits:
                if prev_addr is None:
                    print(
                        f"[WARN] No preceding instruction for sd at {addr:08X}. Skipping PAL60 patch generation."
                    )
                    continue
                ret_addr = addr + 4
                delay_opcode = struct.unpack(endian + "I", prev_bytes)[0]
                use_store = True
                store_insn = _sd(6 if reg == 5 else 5, 29, -8)
                opr = (prev_word >> 26) & 0x3F
                rs = (prev_word >> 21) & 0x1F
                rt = (prev_word >> 16) & 0x1F
                if opr == 4 and rs == 0 and rt == 0:
                    off = prev_word & 0xFFFF
                    if off & 0x8000:
                        off |= -0x10000
                    ret_addr = prev_addr + 4 + ((off & 0xFFFFFFFF) << 2)
                    delay_opcode = store_insn
                    use_store = False
                patch_addr = patch_base + offset
                j_code = 0x08000000 | ((patch_addr // 4) & 0x03FFFFFF)
                patch_lines.append(((0x20 << 24) | (prev_addr & 0x00FFFFFF), j_code))
                patch_lines.append(((0x20 << 24) | (addr & 0x00FFFFFF), delay_opcode))
                if len(b) == 4:
                    orig = struct.unpack(endian + "I", b)[0]
                    patch_lines.extend(
                        generate_display_patch(orig, reg, patch_addr, ret_addr, use_store)
                    )
                offset += (7 if use_store else 6) * 4
            pal60_block = ("//PAL60 refresh patch", patch_lines)
        else:
            print("[WARN] No SMODE2 writes detected; skipping PAL60 override")

    if all_d2:
        cheats.append(("//NOP DISPLAY2 writes", all_d2))
        print(f"[INFO] Found {len(all_d2)} DISPLAY2 writes — patching to NOP.")
    if pal60_block:
        cheats.append(pal60_block)

    if region == "PAL" and reset and pal60:
        if has_60hz:
            print("[INFO] Skipping PAL60 patch (mode already present)")
        else:
            pal_val = params.get(12)
            if pal_val is not None:
                ntsc_val = (pal_val & 0xFFFFFF00) | 0x60
                addr_to_patch = (0x20 << 24) | ((reset + 12 * 4) & 0x00FFFFFF)
                patched = False
                for i in range(1, len(cheats)):
                    patch_lines = cheats[i][1]
                    for j, (a, v) in enumerate(patch_lines):
                        if a == addr_to_patch:
                            patch_lines[j] = (a, ntsc_val)
                            patched = True
                            print(
                                f"[INFO] PAL<->NTSC switch: updated existing patch at 0x{a:08X}"
                            )
                            break
                    if patched:
                        break
                if not patched:
                    cheats.append(
                        ("//PAL<->NTSC switch patch", [(addr_to_patch, ntsc_val)])
                    )
                    print(
                        f"[INFO] PAL<->NTSC switch added: 0x{pal_val:08X} --> 0x{ntsc_val:08X}"
                    )
            else:
                print(
                    "[WARN] Original PAL refresh constant not found; skipping region switch."
                )
    elif region == "PAL":
        print("[INFO] Skipping PAL<->NTSC switch.")

    table_vals = [
        0x4480E000,
        0x4480E800,
        0x4480F000,
        0x4480F800,
        0x46010018,
        0x0000040F,
        0x44C0F800,
        0x3C020076,
        0x3C030094,
        0x24424280,
        0x24638A00,
        0x3044000F,
        0x10800006,
        0x00000000,
        0xA0400000,
        0x24420001,
    ]
    tbl_addr = 0x00100100
    need_tbl_patch = True
    with open(elf_path, "rb") as f:
        elf2 = ELFFile(f)
        endian = "<" if elf2.little_endian else ">"
        for seg in elf2.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            seg_base, data = seg["p_vaddr"], seg.data()
            if seg_base <= tbl_addr < seg_base + len(data):
                off = tbl_addr - seg_base
                if off + 4 <= len(data):
                    val = struct.unpack(endian + "I", data[off : off + 4])[0]
                    if val != 0:
                        need_tbl_patch = False
                break

    if need_tbl_patch or include_init_constants:
        tbl_codes = [
            ((0x20 << 24) | ((tbl_addr + i * 4) & 0x00FFFFFF), v)
            for i, v in enumerate(table_vals)
        ]
        cheats.append(("//Init constants", tbl_codes))

    return cheats, base, title
