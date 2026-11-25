#!/usr/bin/env python3
"""Compile every source of a library directory as the build does and count the
functions found identical in the original (find_functions.py).

The score of a compiler, a flag set or a source revision on a whole library: a change
is worth keeping when it adds identical functions and loses none.

The directory needs its `[compiler.dirs."<dir>"]` entry in decomp.toml (`linux`,
`flags`, optional `cwd`, `rename_sections`, `linkonce_symbols`); `unaligned_words` is
read from `[compiler]`. `--cc` replaces the compiler (a Linux program, `~/` allowed),
`--flags` the flags.

Writes `<out>/<file>.o`, `<out>/<file>.ff` (find_functions.py output) and
`<out>/identical.txt` (`<file>:<function>` lines), prints the total and the files that
did not compile. With `--base <identical.txt of another run>`: the functions gained
and lost against it.

usage: library_sweep.py <dir> <lo> <hi> --out <folder> [--cc <compiler>] [--flags "..."]
                        [--base <identical.txt>] [--only a,b] [--jobs N] [--version ID]
                        [--module M]
"""

import argparse
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import project

TOOLS = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dir")
    parser.add_argument("lo")
    parser.add_argument("hi")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc")
    parser.add_argument("--flags")
    parser.add_argument("--base", type=Path)
    parser.add_argument("--only", help="comma-separated file names without extension")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    parser.add_argument("--version", default=project.DEFAULT_VERSION)
    parser.add_argument("--module", default=project.DEFAULT_MODULE)
    args = parser.parse_args()

    compiler = project.CONFIG.get("compiler", {})
    key = args.dir.replace("\\", "/").rstrip("/")
    entry = compiler.get("dirs", {}).get(key)
    if not entry:
        sys.exit(f'decomp.toml: no [compiler.dirs."{key}"]')
    cc = project.linux_command(args.cc or entry["linux"])
    flags = (args.flags or entry["flags"]).split()
    options = ["--unaligned-words"] if compiler.get("unaligned_words") else []
    for rename in entry.get("rename_sections", []):
        options += ["--rename-section", rename]
    if entry.get("linkonce_symbols"):
        options.append("--linkonce-symbols")
    if "cwd" in entry:
        options += ["--cwd", entry["cwd"]]
    src = project.ROOT / key
    only = set(args.only.split(",")) if args.only else None
    files = sorted(p for p in src.rglob("*") if p.suffix in (".c", ".cpp") and (not only or p.stem in only))
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    def run(source: Path) -> tuple[str, str | None, str]:
        obj = out / (source.stem + ".o")
        obj.unlink(missing_ok=True)
        r = subprocess.run([sys.executable, str(TOOLS / "compile.py"), *options, str(project.binutil("objcopy")),
                            str(obj), *cc, "-c", *flags, "-o", str(obj), source.relative_to(project.ROOT).as_posix()],
                           cwd=project.ROOT, capture_output=True, text=True)
        if not obj.exists():
            return source.stem, None, ((r.stderr + r.stdout).strip().splitlines() or ["?"])[-1][:150]
        found = subprocess.run([sys.executable, str(TOOLS / "find_functions.py"), str(obj), args.lo, args.hi,
                                "--version", args.version, "--module", args.module],
                               cwd=project.ROOT, capture_output=True, text=True).stdout
        (out / (source.stem + ".ff")).write_text(found, encoding="utf-8")
        return source.stem, found, ""

    identical, total, errors = [], 0, []
    with ThreadPoolExecutor(args.jobs) as pool:
        for stem, found, error in pool.map(run, files):
            if found is None:
                errors.append(f"{stem}: {error}")
                continue
            for line in found.splitlines():
                if m := re.match(r"(OK|MISS)\s+(\S+)\s", line):
                    total += 1
                    if m.group(1) == "OK":
                        identical.append(f"{stem}:{m.group(2)}")
    identical.sort()
    (out / "identical.txt").write_text("\n".join(identical) + "\n", encoding="utf-8", newline="\n")
    line = f"identical {len(identical)}/{total}, {len(errors)} files not compiled"
    if args.base:
        base = set(args.base.read_text(encoding="utf-8").split())
        gained, lost = sorted(set(identical) - base), sorted(base - set(identical))
        line += f", +{len(gained)} -{len(lost)}"
        (out / "changes.txt").write_text("\n".join(["GAINED", *gained, "LOST", *lost]) + "\n",
                                         encoding="utf-8", newline="\n")
    print(line)
    for error in errors:
        print("  ", error)


if __name__ == "__main__":
    main()
