"""Command line interface for OPL480pCheatGen."""

import argparse
import os
import sys

from .helpers import extract_from_iso, write_cht, format_cht_text
from .patches import extract_patches


def build_arg_parser() -> argparse.ArgumentParser:
    """Return the argument parser."""
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
    p.add_argument('--dy', dest='dy', type=int, help='Override GS DY value (vertical offset)')
    p.add_argument('--aggressive', dest='aggressive', action='store_true',
                   help='Aggressively patch DISPLAY writes')
    p.add_argument('--debug-aggr', dest='debug_aggr', action='store_true',
                   help='Print potential DISPLAY writes for analysis')
    p.add_argument('--aggr-skipcheck', dest='force_aggr_skip', action='store_true',
                   help='Override safety checks during aggressive patching')
    p.add_argument('--injhook', dest='inject_hook', type=lambda x: int(x, 16),
                   help='Manual hook address for aggressive patch', metavar='HOOK')
    p.add_argument('--injhandler', dest='inject_handler', type=lambda x: int(x, 16),
                   help='Manual handler address for aggressive patch', metavar='HANDLER')
    return p


def main(argv: list[str] | None = None) -> int:
    """Program entry point."""
    parser = build_arg_parser()
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    if args.dy is not None and not (-100 <= args.dy <= 100):
        print("Error: --dy must be between -100 and 100.")
        return 1

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
    return 0


if __name__ == '__main__':  # pragma: no cover
    raise SystemExit(main())

