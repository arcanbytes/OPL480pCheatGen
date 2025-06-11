"""Helpers for aggressive DISPLAY patch generation."""

from typing import List, Tuple
import struct

DISPLAY1_ADDR = 0x12000080
DISPLAY2_ADDR = 0x120000A0
SMODE2_ADDR = 0x12000020


def _r(funct: int, rs: int, rt: int, rd: int, sa: int = 0) -> int:
    """Assemble an R-type MIPS instruction."""
    return (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | funct


def _or(rd: int, rs: int, rt: int) -> int:
    """Assemble an ``or`` instruction."""
    return _r(0x25, rs, rt, rd)


def _addu(rd: int, rs: int, rt: int) -> int:
    """Assemble an ``addu`` instruction."""
    return _r(0x21, rs, rt, rd)


def _daddu(rd: int, rs: int, rt: int) -> int:
    """Assemble a ``daddu`` instruction."""
    return _r(0x2D, rs, rt, rd)


def _addiu(rt: int, rs: int, imm: int) -> int:
    """Assemble an ``addiu`` instruction."""
    return (0x09 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def _sll(rd: int, rt: int, sa: int) -> int:
    """Assemble a ``sll`` instruction."""
    return _r(0x00, 0, rt, rd, sa)


def _sd(rt: int, base: int, disp: int) -> int:
    """Assemble an ``sd`` instruction."""
    return (0x3F << 26) | (base << 21) | (rt << 16) | (disp & 0xFFFF)


def _ld(rt: int, base: int, disp: int) -> int:
    """Assemble an ``ld`` instruction."""
    return (0x37 << 26) | (base << 21) | (rt << 16) | (disp & 0xFFFF)


def _lui(rt: int, imm: int) -> int:
    """Assemble a ``lui`` instruction."""
    return (0x0F << 26) | (rt << 16) | (imm & 0xFFFF)


def _j(addr: int) -> int:
    """Assemble a ``j`` instruction."""
    return (0x02 << 26) | ((addr // 4) & 0x03FFFFFF)


def generate_display_patch(orig_insn: int, reg: int, patch_addr: int, ret_addr: int, with_store: bool) -> List[Tuple[int, int]]:
    """Generate instructions matching ps2force480p's aggressive patch."""
    sp = 29
    temp = 6 if reg == 5 else 5

    vals = []
    if with_store:
        vals.append(_sd(temp, sp, -8))
    vals.extend([
        _addiu(temp, 0, 0x10),
        _sll(temp, temp, 12),
        _daddu(reg, temp, reg),
        _ld(temp, sp, -8),
        _j(ret_addr),
        orig_insn,
    ])

    return [((0x20 << 24) | ((patch_addr + i * 4) & 0x00FFFFFF), v) for i, v in enumerate(vals)]


def find_sd(insns, include_all: bool = False):
    """Locate DISPLAY writes and yield patchable information."""
    matches = []
    regs = {0: 0}
    prev = None
    for ins in insns:
        if ins.mnemonic == 'lui':
            regs[ins.operands[0].reg] = ins.operands[1].imm << 16
        elif ins.mnemonic == 'ori' and ins.operands[1].reg in regs:
            regs[ins.operands[0].reg] = regs[ins.operands[1].reg] | ins.operands[2].imm
        elif ins.mnemonic in ('addiu', 'daddiu') and ins.operands[1].reg in regs:
            regs[ins.operands[0].reg] = (regs[ins.operands[1].reg] + ins.operands[2].imm) & 0xFFFFFFFF
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
            if m.type == 3:
                base = m.mem.base
                disp = m.mem.disp
                if base in regs:
                    addr = (regs[base] + disp) & 0xFFFFFFFF
                    if addr in (DISPLAY1_ADDR, DISPLAY2_ADDR):
                        if prev is not None:
                            matches.append((ins.address, ins.bytes, ins.operands[0].reg, prev.address, prev.bytes, prev))
                        elif include_all:
                            matches.append((ins.address, ins.bytes, ins.operands[0].reg, None, None, None))
        prev = ins
    return matches


def scan_sd(
    data: bytes,
    base_addr: int,
    target: int,
    endian: str,
) -> List[tuple[int, bytes, int, int | None, bytes | None, int | None]]:
    """Raw search for ``sd`` instructions storing to *target* address."""
    matches = []
    regs = [0] * 32
    for off in range(0, len(data) - 4, 4):
        word = struct.unpack_from(endian + 'I', data, off)[0]
        opr = (word >> 26) & 0x3F
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        rd = (word >> 11) & 0x1F
        funct = word & 0x3F
        imm = word & 0xFFFF
        if opr == 0x0F:  # lui
            regs[rt] = (imm << 16) & 0xFFFFFFFF
        elif opr == 0x09:  # addiu
            if imm & 0x8000:
                imm |= -0x10000
            regs[rt] = (regs[rs] + imm) & 0xFFFFFFFF
        elif opr == 0x0D:  # ori
            regs[rt] = regs[rs] | imm
        elif opr == 0x00 and funct in (0x25, 0x21, 0x2D):  # or/addu/daddu
            if funct == 0x25:
                regs[rd] = regs[rs] | regs[rt]
            else:
                regs[rd] = (regs[rs] + regs[rt]) & 0xFFFFFFFF
        elif opr == 0x3F:  # sd
            if imm & 0x8000:
                imm |= -0x10000
            if (regs[rs] + imm) & 0xFFFFFFFF == target:
                prev_off = off - 4
                prev_bytes = data[prev_off:prev_off + 4] if prev_off >= 0 else None
                prev_word = (
                    struct.unpack_from(endian + 'I', data, prev_off)[0]
                    if prev_off >= 0
                    else None
                )
                matches.append(
                    (
                        base_addr + off,
                        data[off:off + 4],
                        rt,
                        base_addr + prev_off if prev_off >= 0 else None,
                        prev_bytes,
                        prev_word,
                    )
                )
    return matches

