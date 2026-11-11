#!/usr/bin/env python3
"""List small functions still in assembly, as candidates for the next units.

Reads the splat assembly of the module (the `text*.s` pieces; functions already in
a `cpp` unit are not listed): for each function, its size, the direct calls it
makes (`jal`) and its callers. Calls through function pointers or vtables
(`jalr`) are not counted. Functions with VFPU instructions are skipped (they stay
assembly, see the project notes). Call-tree leaves come first, then by size. A function
whose callers are all close to it most likely shares their unit.

Usage:
  python tools/psp/unit_candidates.py              # 30 smallest leaves
  python tools/psp/unit_candidates.py -n 50 --max-calls 2
  python tools/psp/unit_candidates.py --start 0x00090000 --end 0x000A0000
"""

import argparse
import re
from pathlib import Path

import project
from vfpu_words import is_vfpu

GLABEL = re.compile(r"^glabel (\S+)")
INSN = re.compile(r"^\s*/\* [0-9A-F]+ ([0-9A-F]{8}) [0-9A-F]{8} \*/\s+([a-z0-9.]+)\s*(.*)$")


def read_functions(paths: list[Path]) -> list[dict]:
    funcs = []
    for path in paths:
        cur = None
        for line in path.read_text().splitlines():
            if m := GLABEL.match(line):
                cur = {"name": m.group(1), "addr": None, "size": 0, "calls": [], "vfpu": False}
                funcs.append(cur)
            elif cur is not None and (m := INSN.match(line)):
                if cur["addr"] is None:
                    cur["addr"] = int(m.group(1), 16)
                cur["size"] += 4
                mnemonic, operands = m.group(2), m.group(3)
                if mnemonic == "jal":
                    cur["calls"].append(operands.strip())
                if is_vfpu(mnemonic):
                    cur["vfpu"] = True
    return [f for f in funcs if f["addr"] is not None]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", default=project.DEFAULT_VERSION)
    parser.add_argument("--module", default=project.DEFAULT_MODULE)
    parser.add_argument("-n", type=int, default=30, help="rows to print")
    parser.add_argument("--max-calls", type=int, default=0, help="most outgoing calls (default 0: leaves)")
    parser.add_argument("--min-size", type=lambda x: int(x, 0), default=8,
                        help="smallest size in bytes (default 8: skips 'jr $ra; nop' stubs)")
    parser.add_argument("--start", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--end", type=lambda x: int(x, 0), default=1 << 32)
    args = parser.parse_args()

    asm_dir = project.asm_dir(args.version, args.module)
    funcs = read_functions(sorted(asm_dir.glob("text*.s")))
    # Callers also count from the functions already in units (their original assembly)
    unit_funcs = read_functions(sorted(asm_dir.glob("*matchings/*/*.s")))
    callers: dict[str, list[int]] = {}
    for f in funcs + unit_funcs:
        for target in f["calls"]:
            callers.setdefault(target, []).append(f["addr"])

    rows = []
    for f in funcs:
        if not args.start <= f["addr"] < args.end or f["size"] < args.min_size or f["vfpu"]:
            continue
        if len(f["calls"]) > args.max_calls:
            continue
        who = callers.get(f["name"], [])
        near = sum(1 for c in who if abs(c - f["addr"]) < 0x400)
        rows.append((len(f["calls"]), f["size"], f["addr"], f["name"], len(who), near))
    rows.sort()
    print(f"{'address':<11} {'size':>6} {'calls':>5} {'callers':>7} {'near':>4}  name")
    for n_calls, size, addr, name, n_callers, near in rows[:args.n]:
        print(f"0x{addr:08X} {size:>#6x} {n_calls:>5} {n_callers:>7} {near:>4}  {name}")
    print(f"{len(rows)} functions (calls <= {args.max_calls}, no VFPU) in assembly, "
          f"0x{args.start:08X}-0x{min(args.end, 0xFFFFFFFF):08X}; 'near' = callers within 0x400 bytes")


if __name__ == "__main__":
    main()
