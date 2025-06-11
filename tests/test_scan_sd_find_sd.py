import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import struct
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN
from opl480pcheatgen.aggressive import (
    scan_sd,
    find_sd,
    _lui,
    _addiu,
    _sd,
    DISPLAY1_ADDR,
    DISPLAY2_ADDR,
)


def _sample_block():
    insts = [
        _lui(8, 0x1200),
        (0x0D << 26) | (8 << 21) | (8 << 16) | 0x80,  # ori $t0, $t0, 0x80
        _sd(9, 8, 0),
        _lui(10, 0x1200),
        _addiu(10, 10, 0xA0),
        _sd(11, 10, 0),
        0,
    ]
    return b"".join(struct.pack(">I", i) for i in insts)


def test_scan_sd():
    data = _sample_block()
    base = 0x1000
    m1 = scan_sd(data, base, DISPLAY1_ADDR, ">")
    assert len(m1) == 1
    addr, bts, reg, prev_addr, prev_bytes, _ = m1[0]
    assert addr == base + 0x8
    assert reg == 9  # $t1
    assert prev_addr == base + 0x4
    assert prev_bytes == struct.pack(">I", (0x0D << 26) | (8 << 21) | (8 << 16) | 0x80)

    m2 = scan_sd(data, base, DISPLAY2_ADDR, ">")
    assert len(m2) == 1
    addr, bts, reg, prev_addr, prev_bytes, _ = m2[0]
    assert addr == base + 0x14
    assert reg == 11  # $t3
    assert prev_addr == base + 0x10
    assert prev_bytes == struct.pack(">I", _addiu(10, 10, 0xA0))


def test_find_sd():
    data = _sample_block()
    base = 0x1000
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)
    md.detail = True
    insns = list(md.disasm(data, base))

    res = find_sd(insns, include_all=False)
    res_all = find_sd(insns, include_all=True)
    assert res == res_all
    assert len(res) == 2

    a1, _, reg1, p1, _, _ = res[0]
    a2, _, reg2, p2, _, _ = res[1]
    assert a1 == base + 0x8
    assert reg1 == insns[2].operands[0].reg
    assert p1 == base + 0x4

    assert a2 == base + 0x14
    assert reg2 == insns[5].operands[0].reg
    assert p2 == base + 0x10
