#!/usr/bin/env python3
"""List the static initialization functions of a PRX, one per source file.

SNC puts the static initialization of a file (`__sti__<file>`) after all the other
functions of that file and adds its address to `.cplinit` (probes/snc_sti.cpp).
Each `.cplinit` entry is therefore the last function of the own
code of one source file: a unit ends where that function ends. Files without
global objects to construct have no entry. Function ends come from the splat
assembly (asm/<version>/<module>).

Usage:
  python tools/psp/tu_ends.py
  python tools/psp/tu_ends.py --module <module>
"""

import argparse
import re
from pathlib import Path

import project
from prx import Prx

GLABEL = re.compile(r"^glabel (\S+)")
ENDLABEL = re.compile(r"^endlabel (\S+)")
INSN = re.compile(r"^\s*/\* [0-9A-F]+ ([0-9A-F]{8}) ")


def function_ends(asm_dir: Path) -> dict[int, int]:
    """{start: end} of every function of the splat assembly."""
    ends = {}
    for path in asm_dir.rglob("*.s"):
        start = last = None
        for line in path.read_text().splitlines():
            if GLABEL.match(line):
                start = last = None
            elif m := INSN.match(line):
                last = int(m.group(1), 16)
                if start is None:
                    start = last
            elif ENDLABEL.match(line) and start is not None:
                ends[start] = last + 4
    return ends


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", default=project.DEFAULT_VERSION)
    parser.add_argument("--module", default=project.DEFAULT_MODULE)
    args = parser.parse_args()

    prx = Prx(project.module_file(args.version, args.module))
    cplinit = prx.section(".cplinit")
    # Entries are (function, 0) pairs
    entries = [prx.u32(cplinit.addr + i) for i in range(0, cplinit.size, 8)]
    entries = [e for e in entries if e]
    ends = function_ends(project.asm_dir(args.version, args.module))
    print(f"{'#':>3} {'static init':>11} {'unit end':>10}")
    for i, addr in enumerate(entries):
        end = ends.get(addr)
        print(f"{i:3d} 0x{addr:08X} " + (f"0x{end:08X}" if end else "?"))
    order = "increasing" if entries == sorted(entries) else "NOT increasing"
    print(f"{len(entries)} entries in .cplinit ({cplinit.addr:#x}, {cplinit.size:#x} bytes), "
          f"addresses {order}")


if __name__ == "__main__":
    main()
