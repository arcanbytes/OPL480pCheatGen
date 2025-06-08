"""Helpers for aggressive DISPLAY patch generation."""

from typing import List, Tuple

DISPLAY1_ADDR = 0x12000080
DISPLAY2_ADDR = 0x120000A0


def _r(funct: int, rs: int, rt: int, rd: int, sa: int = 0) -> int:
    """Assemble an R-type MIPS instruction."""
    return (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | funct


def _or(rd: int, rs: int, rt: int) -> int:
    """Assemble an ``or`` instruction."""
    return _r(0x25, rs, rt, rd)


def _addu(rd: int, rs: int, rt: int) -> int:
    """Assemble an ``addu`` instruction."""
    return _r(0x21, rs, rt, rd)


def _lui(rt: int, imm: int) -> int:
    """Assemble a ``lui`` instruction."""
    return (0x0F << 26) | (rt << 16) | (imm & 0xFFFF)


def _j(addr: int) -> int:
    """Assemble a ``j`` instruction."""
    return (0x02 << 26) | ((addr // 4) & 0x03FFFFFF)


def generate_display_patch(orig_insn: int, reg: int, patch_addr: int, ret_addr: int) -> List[Tuple[int, int]]:
    """Generate instructions that modify DISPLAY register writes."""
    t0 = 8
    at = 1
    vals = [
        _or(t0, reg, 0),
        _lui(at, 1),
        _addu(reg, reg, at),
        orig_insn,
        _or(reg, t0, 0),
        _j(ret_addr),
        0x00000000,
    ]
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

