#!/usr/bin/env python3
"""Print what GCC's RTL passes did with one function of a library source: the
scheduler's trace, the register dispositions, or a whole pass dump.

To see why a function has the right instructions in another order or registers
exchanged: `--pass sched` shows, per block, each instruction's priority, cost and
reservation, the ready list at every cycle and the order chosen (`-fsched-verbose=5`);
`sched2` the same after reload; `lreg` / `greg` which pseudo got which register and
the "used N times across M insns" lines the local allocator ranks; any other name is
a dump suffix of `-da` (`expand`, `combine`, `flow2`...).

The source is compiled to assembly with the `[compiler.dirs."<dir>"]` entry of its
directory (decomp.toml), in a temporary folder, so the dumps do not land in the
sources; relative `-I` flags are resolved against the entry's `cwd`. `--cc` replaces
the compiler (a Linux program, `~/` allowed).

usage: gcc_rtl_trace.py <source> <function name part> [--pass sched|sched2|lreg|greg|...]
                        [--cc <compiler>] [--all] [--lines N]
(without --all: the trace lines only, not the RTL of every instruction)
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

import project


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", type=Path)
    parser.add_argument("function", help="part of the line `;; Function ...` (demangled name)")
    parser.add_argument("--pass", dest="rtl_pass", default="sched")
    parser.add_argument("--cc")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--lines", type=int, default=0)
    args = parser.parse_args()

    source = args.source.resolve()
    relative = source.relative_to(project.ROOT).as_posix()
    dirs = project.CONFIG.get("compiler", {}).get("dirs", {})
    found = [d for d in dirs if relative.startswith(d.rstrip("/") + "/")]
    if not found:
        sys.exit(f"decomp.toml: no [compiler.dirs] entry for {relative}")
    entry = dirs[max(found, key=len)]
    cwd = project.ROOT / entry.get("cwd", ".")
    flags = [f"-I{(cwd / f[2:]).resolve()}" if f.startswith("-I") and not Path(f[2:]).is_absolute() else f
             for f in entry["flags"].split()]
    with tempfile.TemporaryDirectory() as tmp:
        r = subprocess.run([*project.linux_command(args.cc or entry["linux"]), "-S", *flags, "-da",
                            "-fsched-verbose=5", "-o", "out.s", str(source)],
                           cwd=tmp, capture_output=True, text=True)
        dumps = [p for p in Path(tmp).iterdir() if p.name.endswith("." + args.rtl_pass)]
        if not dumps:
            sys.exit((r.stderr.strip() or "no dump") + f"\n(passes: "
                     f"{' '.join(sorted(p.suffix[1:] for p in Path(tmp).iterdir() if p.suffix != '.s'))})")
        text = dumps[0].read_text(encoding="utf-8", errors="replace")
    lines, on = [], False
    for line in text.splitlines():
        if line.startswith(";; Function"):
            on = args.function in line
        if on and (args.all or (line and not line.startswith(("(", " ")))):
            lines.append(line)
    if not lines:
        sys.exit(f"no function with `{args.function}` in the {args.rtl_pass} dump")
    print("\n".join(lines[:args.lines] if args.lines else lines))


if __name__ == "__main__":
    main()
