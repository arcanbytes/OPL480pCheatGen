"""Core patch extraction and analysis logic."""

from __future__ import annotations

import os
import re
import struct
import sys
from typing import List, Tuple

from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN
from capstone.mips import MIPS_OP_MEM

from .helpers import find_pattern, fetch_mastercode, parse_elf_strings, extract_boot_id_from_iso
from .aggressive import DISPLAY1_ADDR, DISPLAY2_ADDR, generate_display_patch, find_sd

SCEGSRESETGRAPH_SIG = bytes([
    0xB0, 0xFF, 0xBD, 0x27, 0x00, 0x24, 0x04, 0x00,
    0x30, 0x00, 0xB3, 0xFF, 0x00, 0x2C, 0x05, 0x00,
    0x20, 0x00, 0xB2, 0xFF, 0x00, 0x34, 0x06, 0x00,
    0x10, 0x00, 0xB1, 0xFF, 0x00, 0x3C, 0x07, 0x00,
    0x40, 0x00, 0xBF, 0xFF, 0x03, 0x24, 0x04, 0x00,
    0x00, 0x00, 0xB0, 0xFF, 0x03, 0x8C, 0x05, 0x00,
    0x03, 0x94, 0x06, 0x00,
])

SCEGSPUTDISPENV_SIG = bytes([
    0x2D, 0x80, 0x80, 0x00, 0x06, 0x00, 0x43, 0x84,
    0x01, 0x00, 0x02, 0x24, 0x11, 0x00, 0x62, 0x14,
])

CLOBBER_STR1 = b"sceGsExecStoreImage: Enough data does not reach VIF1"
CLOBBER_STR2 = b"sceGsExecStoreImage: DMA Ch.1 does not terminate"

ELF_MODE_PATTERNS = [
    b'480p',
    b'240p',
    b'progressive',
    b'interlaced',
    b'60HZ',
    b'PAL60',
    b'60 HZ',
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


def generate_putdispenv_patch(dy_value: int, base_addr: int, orig_inst: int, patch_offset: int = 0x100,
                               return_offset: int = 12, return_addr: int | None = None,
                               patch_addr: int | None = None):
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
    return [((0x20 << 24) | ((fv + i * 4) & 0x00FFFFFF), val) for i, val in enumerate(vals)]


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
):
    """Extract patch codes from an ELF file."""
    fname = os.path.basename(elf_path)
    if base_override:
        base = base_override
    elif re.match(r'^[A-Z]{4}_\d{3}\.\d{2}$', fname):
        base = fname
    else:
        base = os.path.splitext(fname)[0]

    title, mc = (manual_mc and (f'"{base} /ID {base}"', manual_mc)) or fetch_mastercode(base)

    if title:
        title = title.replace('\ufeff', '').replace("“", '"').replace("”", '"').strip()
    if title and not (title.startswith('"') and title.endswith('"')):
        title = '"' + title.strip('"') + '"'

    if not title or not mc:
        print("[WARN] Missing title or mastercode. Proceeding with generic values.")
        boot_id = None
        if elf_path.lower().endswith(".elf") and os.path.exists(elf_path):
            iso_path_guess = None
            for p in sys.argv:
                if p.lower().endswith('.iso') and os.path.exists(p):
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
    has_60hz = any(m.lower() in ('60hz', 'pal60', '60 hz') for m in modes)
    prefix = base.split('_')[0]
    region = 'PAL' if prefix in ('SLES', 'SCES') else 'NTSC'
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

    if not os.path.isfile(elf_path):
        sys.exit(f"Error: File not found: {elf_path}")

    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)
        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)
        md.detail = True
        for seg in elf.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
            data, vaddr = seg.data(), seg['p_vaddr']
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
            if aggressive or debug_aggr:
                aggr_hits.extend(find_sd(insns, include_all=debug_aggr))

        if aggressive or debug_aggr:
            print(f"[DEBUG] Aggressive hits: {len(aggr_hits)} potential display writes found")
            for addr, b, reg, prev_addr, prev_bytes, prev_ins in aggr_hits:
                prev_name = prev_ins.mnemonic if prev_ins else 'None'
                print(f"  [DEBUG] sd @ {addr:08X} — reg: ${reg} — prev: {prev_name}")

        dy_patch = None
        if new_dy is not None:
            clobber_addr = None
            for seg in elf.iter_segments():
                if seg['p_type'] != 'PT_LOAD':
                    continue
                data, seg_base = seg.data(), seg['p_vaddr']
                pos = data.find(CLOBBER_STR1)
                if pos >= 0:
                    clobber_addr = seg_base + pos
                    print(f"[INFO] Found clobber string at 0x{clobber_addr:08X}")
                    break

            for seg in elf.iter_segments():
                if seg['p_type'] != 'PT_LOAD':
                    continue
                data, seg_base = seg.data(), seg['p_vaddr']
                off = find_pattern(data, SCEGSPUTDISPENV_SIG)
                if off >= 0:
                    print(f"[INFO] DY override via sceGsPutDispEnv detected at 0x{seg_base+off:08X}")
                    from_off = off - 16
                    orig_inst = struct.unpack(">I", data[from_off + 4:from_off + 8])[0]
                    hook_addr = seg_base + from_off + 4
                    patch_addr = clobber_addr if clobber_addr else seg_base + 0x100
                    j_code = 0x08000000 | ((patch_addr // 4) & 0x03FFFFFF)
                    hook_patch = [((0x20 << 24) | (hook_addr & 0x00FFFFFF), j_code)]
                    ret_addr = seg_base + from_off + 12
                    dy_vals = generate_putdispenv_patch(new_dy, seg_base, orig_inst, return_addr=ret_addr, patch_addr=patch_addr)
                    dy_patch = (f"//Vertical Offset DY={new_dy}", hook_patch + dy_vals)
                    break

        aggr_patch = None
        if aggressive and aggr_hits:
            clobber2 = None
            for seg in elf.iter_segments():
                if seg['p_type'] != 'PT_LOAD':
                    continue
                data, seg_base = seg.data(), seg['p_vaddr']
                pos = data.find(CLOBBER_STR2)
                if pos >= 0:
                    clobber2 = seg_base + pos
                    print(f"[INFO] Found clobber string #2 at 0x{clobber2:08X}")
                    break
            patch_base = clobber2 if clobber2 is not None else (aggr_hits[0][0] & 0xFFFF0000) + 0x100
            patch_lines = []
            offset = 0
            for addr, b, reg, prev_addr, prev_bytes, prev_ins in aggr_hits:
                if prev_addr is None:
                    print(f"[WARN] No preceding instruction for sd at {addr:08X}. Skipping patch generation for this instruction.")
                    continue
                ret_addr = addr + 8
                delay_opcode = struct.unpack('>I', prev_bytes)[0]
                if prev_ins.mnemonic == 'beq' and len(prev_ins.operands) == 3:
                    if prev_ins.operands[0].reg == 0 and prev_ins.operands[1].reg == 0:
                        off = prev_ins.operands[2].imm
                        if off & 0x8000:
                            off |= -0x10000
                        ret_addr = prev_addr + 4 + ((off & 0xFFFFFFFF) << 2)
                        delay_opcode = 0
                elif prev_ins.mnemonic in ("bgez", "bgezal", "bltz", "bltzal", "bgtz", "blez", "bne"):
                    if not force_aggr_skip:
                        continue
                patch_addr = patch_base + offset
                j_code = 0x08000000 | ((patch_addr // 4) & 0x03FFFFFF)
                patch_lines.append(((0x20 << 24) | (prev_addr & 0x00FFFFFF), j_code))
                patch_lines.append(((0x20 << 24) | (addr & 0x00FFFFFF), delay_opcode))
                if len(b) == 4:
                    orig = struct.unpack('>I', b)[0]
                    patch_lines.extend(generate_display_patch(orig, reg, patch_addr, ret_addr))
                offset += 7 * 4
            aggr_patch = ("//Aggressive DISPLAY patch", patch_lines)

        manual_patch = None
        if inject_hook and inject_handler:
            print("[INFO] Injecting fixed aggressive patch manually.")
            vals = [
                0x3C020010, 0x344226DC, 0x8C820000, 0x38420001, 0xAC820000,
                0x3C021700, 0x3442FFFC, 0x3C030000, 0x3463000F, 0xAC430038,
                0x0800E003, 0x00000000,
            ]
            manual_lines = [((0x20 << 24) | ((inject_handler + i * 4) & 0x00FFFFFF), v) for i, v in enumerate(vals)]
            manual_lines.append(((0x20 << 24) | (inject_hook & 0x00FFFFFF), 0x08000000 | (inject_handler // 4)))
            manual_lines.append(((0x20 << 24) | ((inject_hook + 4) & 0x00FFFFFF), 0x00000000))
            manual_patch = ("//Aggressive DISPLAY patch", manual_lines)

    print("[INFO] Defaulting to 480i @ 640×448 if not overridden.")
    if default_mode:
        w0, h0, i0 = default_mode
        print(f"[INFO] Game default: {w0}×{h0} {'interlaced' if i0 else 'progressive'}")

    if reset:
        need_patch = force_240p or not default_mode or (not default_mode[2] and not force_240p)
        if need_patch:
            codes = [((0x20 << 24) | ((reset + o * 4) & 0x00FFFFFF), v) for o, v in params.items()]
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

    if all_d2:
        cheats.append(("//NOP DISPLAY2 writes", all_d2))
        print(f"[INFO] Found {len(all_d2)} DISPLAY2 writes — patching to NOP.")

    if region == 'PAL' and reset and pal60:
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
                            print(f"[INFO] PAL<->NTSC switch: updated existing patch at 0x{a:08X}")
                            break
                    if patched:
                        break
                if not patched:
                    cheats.append(("//PAL<->NTSC switch patch", [(addr_to_patch, ntsc_val)]))
                    print(f"[INFO] PAL<->NTSC switch added: 0x{pal_val:08X} --> 0x{ntsc_val:08X}")
            else:
                print("[WARN] Original PAL refresh constant not found; skipping region switch.")
    elif region == 'PAL':
        print("[INFO] Skipping PAL<->NTSC switch.")

    return cheats, base, title

