#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="pkg_resources")
import json
import sys, os, argparse, tempfile, re, struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN
from capstone.mips import MIPS_OP_MEM

# Optional imports
try:
    import pycdlib
except ImportError:
    pycdlib = None

# Constants
SCEGSRESETGRAPH_SIG = bytes([
    0xB0,0xFF,0xBD,0x27,0x00,0x24,0x04,0x00,
    0x30,0x00,0xB3,0xFF,0x00,0x2C,0x05,0x00,
    0x20,0x00,0xB2,0xFF,0x00,0x34,0x06,0x00,
    0x10,0x00,0xB1,0xFF,0x00,0x3C,0x07,0x00,
    0x40,0x00,0xBF,0xFF,0x03,0x24,0x04,0x00,
    0x00,0x00,0xB0,0xFF,0x03,0x8C,0x05,0x00,
    0x03,0x94,0x06,0x00
])
SCEGSPUTDISPENV_SIG = bytes([
    0x2D,0x80,0x80,0x00,0x06,0x00,0x43,0x84,
    0x01,0x00,0x02,0x24,0x11,0x00,0x62,0x14
])
CLOBBER_STR1 = b"sceGsExecStoreImage: Enough data does not reach VIF1"
CLOBBER_STR2 = b"sceGsExecStoreImage: DMA Ch.1 does not terminate"
DISPLAY1_ADDR = 0x12000080
DISPLAY2_ADDR = 0x120000A0
ELF_MODE_PATTERNS = [
    b'480p',
    b'240p',
    b'progressive',
    b'interlaced',
    b'60HZ',
    b'PAL60',
    b'60 HZ',
]

def extract_boot_id_from_iso(iso_path):
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
    except Exception as e:
        print(f"[WARN] Could not extract SYSTEM.CNF boot ID: {e}")
    finally:
        iso.close()
    return None

# Helpers
def find_pattern(data, pat):
    for off in range(0, len(data) - len(pat), 4):
        if data[off:off+len(pat)] == pat:
            return off
    return -1

def fetch_mastercode(base):

    if getattr(sys, 'frozen', False):
        app_dir = os.path.dirname(sys.executable)
    else:
        app_dir = os.path.dirname(__file__)
    db_path = os.path.join(app_dir, "mastercodes.json")
    if not os.path.exists(db_path):
        print("[WARN] Local mastercode database not found.")
        return None, None

    with open(db_path, 'r', encoding='utf-8') as f:
        db = json.load(f)

    entry = db.get(base)
    if entry:
        title = entry["title"]
        mc = entry["mastercode"]
        return title, mc

    return None, None

# Parse ELF for strings
def parse_elf_strings(path, patterns=ELF_MODE_PATTERNS):
    """Return list of supported video mode strings found in the ELF."""
    found = set()
    try:
        data = open(path, 'rb').read()
        for pat in patterns:
            if re.search(pat, data, re.IGNORECASE):
                found.add(pat.decode('ascii', 'ignore'))
    except:
        pass
    return sorted(found)

# Analyze GS DISPLAY writes
def analyze_display(insns, interlace_patch=True):
    regs, mode, d2 = {}, None, []
    for ins in insns:
        if ins.mnemonic == 'lui':
            regs[ins.operands[0].reg] = ins.operands[1].imm << 16
        elif ins.mnemonic == 'ori' and ins.operands[1].reg in regs:
            regs[ins.operands[0].reg] = regs[ins.operands[1].reg] | ins.operands[2].imm
        elif ins.mnemonic == 'sd':
            m = ins.operands[1]
            if m.type == MIPS_OP_MEM and m.base in regs:
                addr = (regs[m.base] + m.disp) & 0xFFFFFFFF
                if addr == DISPLAY1_ADDR and not mode:
                    val = regs.get(ins.operands[0].reg)
                    if val is not None:
                        w, h = val & 0x7FF, (val >> 11) & 0x7FF
                        i = (val >> 22) & 1
                        mode = (w, h, bool(i))
                        print(f"[INFO] Found DISPLAY1 write: {w}×{h}, {'interlaced' if i else 'progressive'}")
                elif addr == DISPLAY2_ADDR and interlace_patch:
                    code = (0x20 << 24) | (ins.address & 0x00FFFFFF)
                    d2.append((code, 0x00000000))
    return mode, d2

def generate_putdispenv_patch(dy_value, base_addr, orig_inst, patch_offset=0x100, return_offset=12, return_addr=None, patch_addr=None):
    """Return cheat codes to override DY via sceGsPutDispEnv.

    Parameters
    ----------
    dy_value : int
        Vertical offset value written to the DY field.
    base_addr : int
        Base address of the sceGsPutDispEnv function in memory.
    patch_offset : int, optional
        Offset from ``base_addr`` where the patch code will be placed when
        ``patch_addr`` is not specified.
    return_offset : int, optional
        Offset from ``fv`` to jump back after executing the patch when
        ``return_addr`` is not specified.
    orig_inst : int
        Instruction originally located at ``base_addr + 4`` that will be
        executed at the start of the patch.
    return_addr : int, optional
        Absolute address to return to after executing the patch.
    patch_addr : int, optional
        Absolute address where the DY patch code will be placed. If omitted,
        ``base_addr + patch_offset`` is used.

    Returns
    -------
    list of tuple
        Pairs of (address, value) ready for insertion into a ``.cht`` file.
    """

    fv = patch_addr if patch_addr is not None else base_addr + patch_offset
    ret = return_addr if return_addr is not None else fv + return_offset
    vals = [
        orig_inst,                   # original second instruction
        0x8C900018,                  # lw $s0, 0x18($a0)
        0x3C02FF80,                  # lui $v0, 0xFF80
        0x24420FFF,                  # addiu $v0, $v0, 0x0FFF
        0x00501024,                  # and $v0, $v0, $s0
        0x24100000 | dy_value,       # li $s0, DY
        0x00108300,                  # sll $s0, $s0, 0x0C
        0x02028025,                  # or $s0, $s0, $v0
        0x08000000 | (ret // 4),     # j ret
        0xAC900018                   # sw $s0, 0x18($a0)
    ]
    return [((0x20 << 24) | ((fv + i * 4) & 0x00FFFFFF), val) for i, val in enumerate(vals)]

# Aggressive progressive patch helpers
def _r(funct, rs, rt, rd, sa=0):
    return (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | funct

def _or(rd, rs, rt):
    return _r(0x25, rs, rt, rd)

def _addu(rd, rs, rt):
    return _r(0x21, rs, rt, rd)

def _lui(rt, imm):
    return (0x0F << 26) | (rt << 16) | (imm & 0xFFFF)

def _j(addr):
    return (0x02 << 26) | ((addr // 4) & 0x03FFFFFF)

def generate_display_patch(orig_insn, reg, patch_addr, ret_addr):
    """Build instructions that modify DISPLAY writes."""
    t0 = 8  # $t0 scratch
    at = 1
    vals = [
        _or(t0, reg, 0),             # or $t0, reg, $zero (save)
        _lui(at, 1),                 # lui $at, 0x0001
        _addu(reg, reg, at),         # addu reg, reg, $at
        orig_insn,                   # original sd instruction
        _or(reg, t0, 0),             # restore reg
        _j(ret_addr),                # jump back
        0x00000000                   # nop
    ]
    return [((0x20 << 24) | ((patch_addr + i * 4) & 0x00FFFFFF), v) for i, v in enumerate(vals)]

def find_sd(insns, include_all=False):
    """Locate DISPLAY register writes in a stream of instructions.

    The original implementation only handled ``addiu`` sequences. Some games
    build the DISPLAY address using ``daddiu`` in 64-bit code, so this function
    also recognises that pattern. The ``regs`` dictionary is updated whenever a
    register is loaded with an immediate using ``lui``/``ori`` or when an offset
    is added via ``addiu``/``daddiu``. Constants are additionally propagated
    through ``or``, ``addu`` and ``daddu`` so that more complex address
    construction sequences are understood. If a subsequent ``sd`` stores to
    ``DISPLAY1`` or ``DISPLAY2`` using a tracked base register, the instruction
    and its predecessor are returned so that a jump hook can be inserted.
    """

    matches = []
    regs = {0: 0}  # track known register constants, start with $zero
    prev = None
    for ins in insns:
        if ins.mnemonic == 'lui':
            regs[ins.operands[0].reg] = ins.operands[1].imm << 16
        elif ins.mnemonic == 'ori' and ins.operands[1].reg in regs:
            regs[ins.operands[0].reg] = regs[ins.operands[1].reg] | ins.operands[2].imm
        elif ins.mnemonic in ('addiu', 'daddiu') and ins.operands[1].reg in regs:
            regs[ins.operands[0].reg] = (regs[ins.operands[1].reg] + ins.operands[2].imm) & 0xFFFFFFFF
        # propagate constants via ``or``/``addu``/``daddu`` when both operands are known
        elif ins.mnemonic in ('or', 'addu', 'daddu'):
            rs = ins.operands[1].reg
            rt = ins.operands[2].reg
            if rs in regs and rt in regs:
                if ins.mnemonic == 'or':
                    regs[ins.operands[0].reg] = regs[rs] | regs[rt]
                else:
                    regs[ins.operands[0].reg] = (regs[rs] + regs[rt]) & 0xFFFFFFFF
        elif ins.mnemonic == 'sd':
            m = ins.operands[1]
            if m.type == MIPS_OP_MEM:
                base = m.mem.base
                disp = m.mem.disp
                if base in regs:
                    addr = (regs[base] + disp) & 0xFFFFFFFF
                    if addr in (DISPLAY1_ADDR, DISPLAY2_ADDR):
                        if prev is not None:
                            matches.append((ins.address, ins.bytes, ins.operands[0].reg,
                                            prev.address, prev.bytes, prev))
                        elif include_all:
                            matches.append((ins.address, ins.bytes, ins.operands[0].reg,
                                            None, None, None))
        prev = ins
    return matches

# Main extraction & patch logic
def extract_patches(elf_path, base_override=None, manual_mc=None, interlace_patch=True,
                    force_240p=False, pal60=False, new_dy=None, aggressive=False,
                    debug_aggr=False, force_aggr_skip=False,
                    inject_hook=None, inject_handler=None):
    fname = os.path.basename(elf_path)
    if base_override:
        base = base_override
    elif re.match(r'^[A-Z]{4}_\d{3}\.\d{2}$', fname):  # SLUS_123.45
        base = fname
    else:
        base = os.path.splitext(fname)[0]
    
    title, mc = (manual_mc and (f'"{base} /ID {base}"', manual_mc)) or fetch_mastercode(base)
    
    # Normalize and clean up the title string to avoid encoding errors
    if title:
        title = title.replace('\ufeff', '').replace("“", '"').replace("”", '"').strip()
    if title and not (title.startswith('"') and title.endswith('"')):
        title = '"' + title.strip('"') + '"'

    if not title or not mc:
        print("[WARN] Missing title or mastercode. Proceeding with generic values.")
        boot_id = None
        if elf_path.lower().endswith(".elf") and os.path.exists(elf_path):
            # Try to guess ISO path from temp ELF (gross, but works in context)
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

    # Summary
    print(f"\n=== {base} Cheater Summary ===")
    print(f"Title: {title}")
    print(f"Mastercode: {mc}")
    modes = parse_elf_strings(elf_path)
    if modes:
        print(f"Supported modes in ELF: {', '.join(modes)}")
    has_60hz = any(m.lower() in ('60hz', 'pal60', '60 hz') for m in modes)
    prefix = base.split('_')[0]
    region = 'PAL' if prefix in ('SLES','SCES') else 'NTSC'
    print(f"Region: {region}")

    cheats = [(title, mc)]

    # Determine reset-patch parameters
    if force_240p:
        print("[INFO] Forcing 240p mode as requested.")
        w, h = 640, 240
        val_wh = (h << 11) | w
        params = {11: 0x24110000 | val_wh,
                  12: 0x24120000 | val_wh,
                  15: 0x24130001}
        patch_title = "//Force 240p Progressive"
    else:
        params = {11: 0x24110000,
                  12: 0x24120050,
                  15: 0x24130001}
        patch_title = "//Force 480p Progressive"

    reset = None
    default_mode = None
    all_d2 = []
    aggr_hits = []
    
    if not os.path.isfile(elf_path):
        sys.exit(f"Error: File not found: {elf_path}")

    with open(elf_path,'rb') as f:
        elf = ELFFile(f)
        md  = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)
        md.detail = True
        for seg in elf.iter_segments():
            if seg['p_type'] != 'PT_LOAD': continue
            data, vaddr = seg.data(), seg['p_vaddr']
            if reset is None:
                off = find_pattern(data, SCEGSRESETGRAPH_SIG)
                if off >= 0:
                    reset = vaddr + off
                    print(f"[INFO] Detected sceGsResetGraph at 0x{reset:08X}")
            insns = list(md.disasm(data, vaddr))
            m, d2 = analyze_display(insns, interlace_patch)
            if m and not default_mode:
                default_mode = m
            all_d2 += d2
            if aggressive or debug_aggr:
                aggr_hits.extend(find_sd(insns, include_all=debug_aggr))

        if debug_aggr:
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
                    hook_patch = [
                        ((0x20 << 24) | (hook_addr & 0x00FFFFFF), j_code)
                    ]
                    ret_addr = seg_base + from_off + 12
                    dy_vals = generate_putdispenv_patch(new_dy, seg_base, orig_inst,
                                                     return_addr=ret_addr, patch_addr=patch_addr)
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
                    if debug_aggr:
                        print(f"[WARN] No preceding instruction for sd at {addr:08X}")
                    continue
                skip = False
                ret_addr = addr + 8
                delay_opcode = struct.unpack('>I', prev_bytes)[0]
                if prev_ins.mnemonic == 'beq' and len(prev_ins.operands) == 3:
                    if prev_ins.operands[0].reg == 0 and prev_ins.operands[1].reg == 0:
                        off = prev_ins.operands[2].imm
                        if off & 0x8000:
                            off |= -0x10000
                        ret_addr = prev_addr + 4 + ((off & 0xFFFFFFFF) << 2)
                        delay_opcode = 0
                    else:
                        skip = True
                elif prev_ins.mnemonic in ("bgez", "bgezal", "bltz", "bltzal", "bgtz", "blez", "bne"):
                    skip = True
                if skip:
                    if debug_aggr:
                        print(f"[WARN] Skipping complex branch at {prev_addr:08X}")
                    if not force_aggr_skip:
                        continue
                patch_addr = patch_base + offset
                j_code = 0x08000000 | ((patch_addr // 4) & 0x03FFFFFF)
                patch_lines.append(((0x20 << 24) | (prev_addr & 0x00FFFFFF), j_code))
                patch_lines.append(((0x20 << 24) | (addr & 0x00FFFFFF), delay_opcode))
                orig = struct.unpack('>I', b)[0]
                patch_lines.extend(generate_display_patch(orig, reg, patch_addr, ret_addr))
                offset += 7 * 4
            aggr_patch = ("//Aggressive DISPLAY patch", patch_lines)

        # Manual injection override
        manual_patch = None
        if inject_hook and inject_handler:
            print("[INFO] Injecting fixed aggressive patch manually.")
            vals = [
                0x3C020010, 0x344226DC, 0x8C820000, 0x38420001, 0xAC820000,
                0x3C021700, 0x3442FFFC, 0x3C030000, 0x3463000F, 0xAC430038,
                0x0800E003, 0x00000000
            ]
            manual_lines = [
                ((0x20 << 24) | ((inject_handler + i * 4) & 0x00FFFFFF), v)
                for i, v in enumerate(vals)
            ]
            manual_lines.append(
                ((0x20 << 24) | (inject_hook & 0x00FFFFFF), 0x08000000 | (inject_handler // 4))
            )
            manual_lines.append(
                ((0x20 << 24) | ((inject_hook + 4) & 0x00FFFFFF), 0x00000000)
            )
            manual_patch = ("//Aggressive DISPLAY patch", manual_lines)

    print("[INFO] Defaulting to 480i @ 640×448 if not overridden.")
    if default_mode:
        w0, h0, i0 = default_mode
        print(f"[INFO] Game default: {w0}×{h0} {'interlaced' if i0 else 'progressive'}")

    # Apply force patch
    if reset:
        need_patch = force_240p or not default_mode or (not default_mode[2] and not force_240p)
        if need_patch:
            codes = [((0x20<<24) | ((reset + o*4) & 0x00FFFFFF), v)
                     for o, v in params.items()]
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

    # No-interlace patch
    if all_d2:
        cheats.append(("//NOP DISPLAY2 writes", all_d2))
        print(f"[INFO] Found {len(all_d2)} DISPLAY2 writes — patching to NOP.")
    #else:
        #print("[INFO] DISPLAY2 writes not found or skipped — game likely doesn't re-enable interlace after boot.")

    # PAL<->NTSC switch patch via flag
    if region == 'PAL' and reset and pal60:
        if has_60hz:
            print("[INFO] Skipping PAL60 patch (mode already present)")
        else:
            pal_val = params.get(12)
            if pal_val is not None:
                ntsc_val = (pal_val & 0xFFFFFF00) | 0x60
                addr_to_patch = (0x20 << 24) | ((reset + 12*4) & 0x00FFFFFF)

                # Search for existing patch modifying this address
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

# Write cheat file
def write_cht(output_dir, cheats, game_id, title): 
    out_name = f"{game_id}.cht"

    # Determinar el directorio de salida real
    if getattr(sys, 'frozen', False):
        # Estamos en un ejecutable de PyInstaller, el directorio es el del ejecutable
        actual_output_dir = os.path.dirname(sys.executable)
    else:
        # Estamos ejecutando el script .py, el directorio es el del script
        actual_output_dir = os.path.join(output_dir)       
 
    out_path = os.path.join(actual_output_dir, out_name)

    print(f"\nGenerating {out_path}...")
    print(f"[INFO] Output filename: {out_name}")
    with open(out_path,'w',encoding='utf-8') as c:
        # header
        c.write(f"{cheats[0][0]}\nMastercode\n{cheats[0][1]}\n\n")
        # patches
        for hdr, codes in cheats[1:]:
            c.write(f"{hdr}\n")
            for a, v in codes:
                c.write(f"{a:08X} {v:08X}\n")
            c.write("\n")
    print(f"[INFO] Wrote: {out_path}\n")
    return out_path

# ISO extraction
def extract_from_iso(iso_path, elf_override=None):
    import pycdlib
    from pycdlib.pycdlibexception import PyCdlibInvalidInput

    iso = pycdlib.PyCdlib()
    try:
        iso.open(iso_path)
    except PyCdlibInvalidInput:
        print("[ERROR] Not a valid ISO file.")
        sys.exit(1)

    # Step 1: Parse SYSTEM.CNF for BOOT2 path
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
    except Exception as e:
        print(f"[WARN] Failed to read SYSTEM.CNF: {e}")

    if not boot_path:
        print("Error: Could not determine BOOT2 path from SYSTEM.CNF.")
        sys.exit(1)

    # Step 2: Extract ELF from BOOT2
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

def format_cht_text(cheats):
    lines = []
    lines.append(f"{cheats[0][0]}")
    lines.append("Mastercode")
    lines.append(f"{cheats[0][1]}\n")
    for hdr, codes in cheats[1:]:
        lines.append(hdr)
        for a, v in codes:
            lines.append(f"{a:08X} {v:08X}")
        lines.append("")
    return "\n".join(lines).strip()

# CLI
if __name__ == '__main__':
    p = argparse.ArgumentParser(description="Generate OPL .cht (ELF or ISO)")
    p.add_argument('input', help='ELF file or ISO image')
    p.add_argument('--elfpath', help='Path inside ISO to ELF (e.g. SLUS_123.45;1)')
    p.add_argument('--mastercode', help='Manual mastercode override', metavar='CODE')
    p.add_argument('--preview-only', dest='preview_only', action='store_true',
               help='Only generate .cht content to stdout, do not write any files')
    p.add_argument('--no-interlace-patch', dest='interlace_patch', action='store_false',
                   help='Disable No-Interlace patch (enabled by default)')
    p.add_argument('--force-240p', dest='force_240p', action='store_true',
                   help='Force the game into 240p progressive mode')
    p.add_argument('--pal60', dest='pal60', action='store_true',
                   help='Enable PAL 60Hz patch for PAL region games')
    p.add_argument('--dy', dest='dy', type=int, help='Override GS DY value')
    p.add_argument('--aggressive', dest='aggressive', action='store_true',
                   help='Aggressively patch DISPLAY writes')
    p.add_argument('--debug-aggr', dest='debug_aggr', action='store_true',
                   help='Print potential DISPLAY writes for analysis')
    p.add_argument('--force-aggr-skipcheck', dest='force_aggr_skip', action='store_true',
                   help='Override safety checks during aggressive patching')
    p.add_argument('--inject-hook', dest='inject_hook', type=lambda x: int(x, 16),
                   help='Manual hook address for aggressive patch')
    p.add_argument('--inject-handler', dest='inject_handler', type=lambda x: int(x, 16),
                   help='Manual handler address for aggressive patch')
    if len(sys.argv) == 1:
        p.print_help()
        sys.exit(0)  
    args = p.parse_args()
    if args.dy is not None and not (-100 <= args.dy <= 100):
        print("Error: --dy must be between -100 and 100.")
        sys.exit(1)    
    print(f"[INFO] OPL480pCheatGen starting on {args.input}")

    if args.input.lower().endswith('.iso'):
        elf, base = extract_from_iso(args.input, args.elfpath)
        cheats, game_id, title = extract_patches(
            elf,
            base_override=base,
            manual_mc=args.mastercode,
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
        if args.preview_only:
            print(format_cht_text(cheats))
        else:
            write_cht(os.path.dirname(__file__), cheats, game_id, title)
    else:
        cheats, game_id, title = extract_patches(
            args.input,
            manual_mc=args.mastercode,
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
        if args.preview_only:
            print(format_cht_text(cheats))
        else:
            write_cht(os.path.dirname(__file__), cheats, game_id, title)

