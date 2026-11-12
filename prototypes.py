#!/usr/bin/env python3
"""Check the prototypes of the functions declared or defined in the C sources.

Every C/C++ source of src/ is read for the declarations (`extern T f(...);`) and the
definitions (`T f(...) {`) of address-named functions (`func_XXXXXXXX`) and system
imports (`sce*`). Reported:

  - a function declared with different argument counts in different files, or with a
    count different from its C definition;
  - a declaration or definition with fewer integer arguments than the function
    reads (argument registers $a0-$a3, $t0-$t3 read before written anywhere in the
    function, see batch_units.Callees.reads): the missing ones are passed without
    being written in the C. That count is a lower bound (unused arguments are not
    seen); variadic functions are skipped;
  - a declaration without a prototype (`T f();`): the call shows no arguments.

The functions already in C are read from the built ELF: run it after a build that
matches (`ninja` ends with OK), or the counts come from the wrong code.

Usage (from the project):
  python tools/psp/prototypes.py
"""

import argparse
import collections
import re
import sys
from pathlib import Path

import project
from batch_units import Callees, Config
from unit_candidates import read_functions

NAME = r"(func_[0-9A-F]{8}|sce\w+)"
# `extern T f(args);` or `T f(args) {`, one per line
PROTO = re.compile(r"^(?:extern\s+)?((?:const\s+|unsigned\s+|signed\s+)?\w+[\s\*]*?)\s*\b" + NAME
                   + r"\(([^()]*)\)\s*([;{])", re.M)
FLOAT = re.compile(r"^(?:const\s+)?(float|double|f32|f64)\b(?![\s\w]*\*)")


class Proto:
    def __init__(self, ret: str, params: str, path: Path, line: int, definition: bool):
        self.ret = " ".join(ret.split()).replace(" *", "*")
        p = params.strip()
        self.known = p != ""  # `f()` in C: no prototype
        self.params = [] if p in ("", "void") else [x.strip() for x in p.split(",")]
        self.path, self.line, self.definition = path, line, definition

    @property
    def count(self) -> int:
        return len(self.params)

    @property
    def int_count(self) -> int:
        """Arguments passed in integer registers (floats go to $f12+)."""
        return sum(1 for x in self.params if not FLOAT.match(x) and x != "...")

    def where(self) -> str:
        return f"{self.path.relative_to(project.ROOT).as_posix()}:{self.line}"

    def text(self, name: str) -> str:
        return f"{self.ret} {name}({', '.join(self.params) or 'void'})"


def read_protos(src_dir: Path) -> dict[str, list[Proto]]:
    protos = collections.defaultdict(list)
    for path in sorted(src_dir.glob("*.c*")):
        text = path.read_text(encoding="utf-8")
        for m in PROTO.finditer(text):
            if m.group(1).strip() in ("return", "else"):
                continue
            line = text.count("\n", 0, m.start()) + 1
            protos[m.group(2)].append(Proto(m.group(1), m.group(3), path, line, m.group(4) == "{"))
    return protos


def check(protos: dict[str, list[Proto]], callees: Callees | None) -> list[str]:
    errors = []
    for name, ps in sorted(protos.items()):
        known = [p for p in ps if p.known]
        defs = [p for p in known if p.definition]
        counts = {p.count for p in known}
        if len(counts) > 1:
            ref = defs[0] if defs else None
            lines = [f"  {p.where()}: {p.text(name)}{'  (definition)' if p.definition else ''}"
                     for p in known if ref is None or p.count != ref.count or p is ref]
            errors.append(f"{name}: argument counts differ\n" + "\n".join(lines))
        if callees and name.startswith("func_"):
            low = callees.reads(name)
            for p in known:
                if low is not None and p.int_count < low:
                    errors.append(f"{name}: {p.where()} has {p.int_count} integer argument(s), "
                                  f"the function reads {low}")
        errors += [f"{name}: {p.where()} declared without a prototype" for p in ps if not p.known]
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", default=project.DEFAULT_VERSION)
    ap.add_argument("--module", default=project.DEFAULT_MODULE)
    args = ap.parse_args()

    protos = read_protos(project.ROOT / "src")
    cfg = Config(args.version, args.module)
    funcs = read_functions(sorted(project.asm_dir(cfg.version, cfg.module).glob("text*.s")))
    callees = Callees(cfg, funcs)
    callees.extern = {n: max(p.count for p in ps if p.known) for n, ps in protos.items()
                      if n.startswith("sce") and any(p.known for p in ps)}
    errors = check(protos, callees)
    for e in errors:
        print(e)
    n_decl = sum(len(v) for v in protos.values())
    print(f"{len(protos)} functions, {n_decl} declarations or definitions, {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
