import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from opl480pcheatgen.aggressive import generate_display_patch


def test_generate_display_patch_with_store():
    orig = 0xDEADBEEF
    patch_addr = 0x1000
    ret_addr = 0x2000
    codes = generate_display_patch(orig, 5, patch_addr, ret_addr, True)
    assert len(codes) == 7
    assert codes[0][0] == (0x20 << 24) | patch_addr
    assert codes[-1][1] == orig
    for i, (addr, _) in enumerate(codes):
        assert addr == (0x20 << 24) | (patch_addr + i * 4)


def test_generate_display_patch_no_store():
    orig = 0xCAFEBABE
    patch_addr = 0x2000
    ret_addr = 0x3000
    codes = generate_display_patch(orig, 4, patch_addr, ret_addr, False)
    assert len(codes) == 6
    assert codes[0][0] == (0x20 << 24) | patch_addr
    assert codes[-1][1] == orig
    for i, (addr, _) in enumerate(codes):
        assert addr == (0x20 << 24) | (patch_addr + i * 4)
