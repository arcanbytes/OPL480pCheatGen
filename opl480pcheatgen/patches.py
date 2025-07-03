"""Compatibility layer exposing patch generation helpers."""

from __future__ import annotations

from .analysis import analyze_display, SCEGSRESETGRAPH_SIG, SCEGSPUTDISPENV_SIG, CLOBBER_STR1, CLOBBER_STR2, VSYNC_HANDLER_SIG, ELF_MODE_PATTERNS
from .patch_generation import generate_putdispenv_patch, extract_patches

__all__ = [
    "analyze_display",
    "generate_putdispenv_patch",
    "extract_patches",
    "SCEGSRESETGRAPH_SIG",
    "SCEGSPUTDISPENV_SIG",
    "CLOBBER_STR1",
    "CLOBBER_STR2",
    "VSYNC_HANDLER_SIG",
    "ELF_MODE_PATTERNS",
]
