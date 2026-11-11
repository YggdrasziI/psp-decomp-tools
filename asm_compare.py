#!/usr/bin/env python3
"""Show one function of a unit next to the original, from objdiff's own diff.

Runs `objdiff-cli diff` (rabbitizer disassembler, same matching as the objdiff GUI
and report) and prints the original (left) and our build (right) side by side:

  ' ' same   '|' argument differs   'o' opcode differs   'r' replaced
  '<' only in the original           '>' only in our build

Usage:
  python tools/psp/asm_compare.py unit_000960A4 func_000960D0
  python tools/psp/asm_compare.py text_0009630C func_0009630C      # assembly piece: original only
  python tools/psp/asm_compare.py --objects <original.o> <ours.o> func_000960D0

Needs `objdiff.json` (`python tools/configure.py`) and a built unit (`ninja`); with
--objects any two ELF objects are compared (e.g. a scratch variant against the
original functions of a unit, build/<version>/target/<unit>.o).
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

import project

ROOT = str(project.ROOT)
OBJDIFF = str(project.objdiff_cli())

MARKS = {
    None: " ",
    "DIFF_ARG_MISMATCH": "|",
    "DIFF_OP_MISMATCH": "o",
    "DIFF_REPLACE": "r",
    "DIFF_DELETE": "<",
    "DIFF_INSERT": ">",
}


def unit_name(short):
    """Full objdiff unit name from a short one (text -> asm/<module>/text)."""
    with open(os.path.join(ROOT, "objdiff.json"), encoding="utf-8") as f:
        names = [u["name"] for u in json.load(f)["units"]]
    if short in names:
        return short
    matches = [n for n in names if n.endswith("/" + short)]
    if len(matches) != 1:
        sys.exit(f"unit {short!r}: {len(matches)} matches in objdiff.json")
    return matches[0]


def rows(symbol_json):
    out = []
    for ins in symbol_json.get("instructions", []):
        text = ins.get("instruction", {}).get("formatted", "")
        out.append((ins.get("diff_kind"), text))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("args", nargs="+", help="<unit> <symbol>, or <symbol> with --objects")
    parser.add_argument("--objects", nargs=2, metavar=("ORIGINAL", "OURS"))
    opts = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        out_json = os.path.join(tmp, "diff.json")
        if opts.objects:
            if len(opts.args) != 1:
                sys.exit("with --objects give only the symbol")
            symbol = opts.args[0]
            cmd = [OBJDIFF, "diff", "-1", opts.objects[0], "-2", opts.objects[1]]
        else:
            if len(opts.args) != 2:
                sys.exit(__doc__)
            symbol = opts.args[1]
            cmd = [OBJDIFF, "diff", "-p", ROOT, "-u", unit_name(opts.args[0])]
        cmd += [symbol, "-o", out_json, "--format", "json"]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
        if res.returncode != 0 or not os.path.exists(out_json):
            sys.exit(res.stderr.strip() or "objdiff-cli diff failed")
        with open(out_json, encoding="utf-8") as f:
            diff = json.load(f)

    sides = []
    for side in ("left", "right"):
        # An assembly piece (asm/<module>/text*) has no right side.
        found = [s for s in diff.get(side, {}).get("symbols", []) if s.get("name") == symbol]
        sides.append(found[0] if found else {})
    if not sides[0] and not sides[1]:
        sys.exit(f"{symbol} not found")
    left, right = rows(sides[0]), rows(sides[1])
    pct = sides[1].get("match_percent", sides[0].get("match_percent"))
    print(f"{symbol}: {pct:.2f} %" if pct is not None else f"{symbol}: no match data")
    print(f"  {'original':<44} | ours")
    for i in range(max(len(left), len(right))):
        kind, a = left[i] if i < len(left) else (None, "")
        kind_b, b = right[i] if i < len(right) else (None, "")
        mark = MARKS.get(kind or kind_b, "?")
        print(f"{mark} {a[:44]:<44} | {b}")


if __name__ == "__main__":
    main()
