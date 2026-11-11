#!/usr/bin/env python3
"""Replace VFPU and Allegrex-only instructions in splat assembly with `.word` directives.

GNU as (assembling for mips32r2) has no VFPU support and encodes some Allegrex
instructions differently, so such an instruction becomes the raw word that
splat writes in the comment of each instruction line
(`/* <rom> <vram> <bytes> */`, bytes in file order). Same approach as
sotn-decomp's tools/pspas (README.md). NaN and infinity floats of the data
become their original bytes too (GNU as writes the canonical NaN). The bytes stay identical as
long as the layout does not move, which a matching build guarantees.
"""

import re
import sys
from pathlib import Path

# splat data line with a NaN or infinity float: /* <rom> <vram> <bytes> */ .double nan
SPECIAL_FLOAT = re.compile(r"^(\s*/\* [0-9A-F]+ [0-9A-F]{8} ([0-9A-F]{8}|[0-9A-F]{16}) \*/\s+)"
                           r"(\.(?:float|double)\s+-?(?:nan|inf)\w*)\s*$", re.I)
LINE = re.compile(r"^(\s*/\* [0-9A-F]+ [0-9A-F]{8} ([0-9A-F]{8}) \*/\s+)([a-z0-9.]+)\b.*$")

# VFPU opcodes: everything that starts with "v", the VFPU load/stores, the
# VFPU branches and the GPR <-> VFPU moves
VFPU_PREFIXES = ("v", "lv.", "sv.", "lvl.", "lvr.", "svl.", "svr.")
VFPU_OPS = {"bvf", "bvt", "bvfl", "bvtl", "mfv", "mtv", "mfvc", "mtvc", "vsync"}
# Allegrex instructions missing from mips32r2 or encoded differently there
# (clz/clo/madd/msub live in SPECIAL on Allegrex, SPECIAL2 on mips32)
ALLEGREX_OPS = {"min", "max", "clz", "clo", "bitrev", "mfic", "mtic", "halt",
                "madd", "maddu", "msub", "msubu", "wsbw"}


def is_vfpu(mnemonic: str) -> bool:
    return mnemonic in VFPU_OPS or mnemonic in ALLEGREX_OPS or mnemonic.startswith(VFPU_PREFIXES)


def convert(text: str) -> str:
    out = []
    for line in text.splitlines():
        m = LINE.match(line)
        if m and is_vfpu(m.group(3)):
            word = int.from_bytes(bytes.fromhex(m.group(2)), "little")
            line = f"{m.group(1)}.word 0x{word:08X} /* {m.group(3)} */"
        elif m := SPECIAL_FLOAT.match(line):
            # GNU as writes the canonical NaN, not the original payload
            data = bytes.fromhex(m.group(2))
            line = f"{m.group(1)}.byte " + ", ".join(f"0x{b:02X}" for b in data) + f" /* {m.group(3)} */"
        out.append(line)
    return "\n".join(out) + "\n"


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: vfpu_words.py <in.s> <out.s>")
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(convert(src.read_text()), newline="\n")


if __name__ == "__main__":
    main()
