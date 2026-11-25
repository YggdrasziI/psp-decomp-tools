#!/usr/bin/env python3
"""Find each function of a compiled object in the original module by content.

For a library whose sources are known but whose place in the module is not: every
function of `.text` of the object is searched in an address range of the original,
relocated fields masked (R_MIPS_26: 26 bits; HI16, LO16 and GPREL16: 16 bits).

Prints, per function, `OK` with the address(es) where it is identical, or `MISS`
with the best partial match (same size, same first instruction) and its score; then
`<identical>/<functions> functions found exactly`.

usage: find_functions.py <obj.o> <lo> <hi> [--version ID] [--module M]
(<lo> and <hi> in hexadecimal, addresses of the module)
"""

import argparse
import re
import struct
import subprocess
from pathlib import Path

import project
from prx import Prx


def functions(obj: Path) -> dict[str, list[tuple[int, int]]]:
    """{name: [(word, compare mask), ...]} for the functions of `.text`, in order."""
    dump = subprocess.run([str(project.binutil("objdump")), "-dr", "-j", ".text", str(obj)],
                          capture_output=True, text=True, check=True).stdout
    found: dict[str, list[list[int]]] = {}
    cur = None
    for line in dump.splitlines():
        if m := re.match(r"^[0-9a-f]{8} <(.+)>:", line):
            cur = found.setdefault(m.group(1), [])
        elif cur is None:
            continue
        elif m := re.match(r"^\s+[0-9a-f]+:\s+([0-9a-f]{8})\s", line):
            cur.append([int(m.group(1), 16), 0xFFFFFFFF])
        elif (m := re.match(r"^\s+[0-9a-f]+: (R_MIPS_\w+)", line)) and cur:
            cur[-1][1] = 0xFC000000 if m.group(1) == "R_MIPS_26" else 0xFFFF0000
    return {name: [(w, k) for w, k in insns] for name, insns in found.items() if insns}


def search(insns: list[tuple[int, int]], words: list[int], lo: int) -> tuple[list[int], int, int | None]:
    """(addresses of the exact matches, best partial count, its address)."""
    n = len(insns)
    hits, best, best_at = [], 0, None
    first_word, first_mask = insns[0]
    for i in range(len(words) - n + 1):
        if (words[i] ^ first_word) & first_mask:
            continue
        ok = sum(1 for k in range(n) if not (words[i + k] ^ insns[k][0]) & insns[k][1])
        if ok == n:
            hits.append(lo + 4 * i)
        elif ok > best:
            best, best_at = ok, lo + 4 * i
    return hits, best, best_at


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("obj", type=Path)
    parser.add_argument("lo", type=lambda s: int(s, 16))
    parser.add_argument("hi", type=lambda s: int(s, 16))
    parser.add_argument("--version", default=project.DEFAULT_VERSION)
    parser.add_argument("--module", default=project.DEFAULT_MODULE)
    args = parser.parse_args()

    prx = Prx(project.module_file(args.version, args.module))
    offset = prx.segments[0].offset - prx.segments[0].vaddr
    words = list(struct.unpack_from(f"<{(args.hi - args.lo) // 4}I", prx.data, offset + args.lo))
    funcs = functions(args.obj)
    exact = 0
    for name, insns in funcs.items():
        hits, best, best_at = search(insns, words, args.lo)
        if hits:
            exact += 1
            print(f"OK    {name:40} {len(insns):5} insns at " + " ".join(f"{h:06X}" for h in hits[:3]))
        elif best_at is None:
            print(f"MISS  {name:40} {len(insns):5} insns no anchor")
        else:
            print(f"MISS  {name:40} {len(insns):5} insns best {100 * best / len(insns):5.1f}% at {best_at:06X}")
    print(f"{exact}/{len(funcs)} functions found exactly")


if __name__ == "__main__":
    main()
