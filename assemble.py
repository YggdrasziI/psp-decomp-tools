#!/usr/bin/env python3
"""Assemble a splat .s file: VFPU instructions to .word (vfpu_words.py), `.double`
to two `.word`, then GNU as.

GNU as aligns a `.double` on 8 bytes and raises the alignment of its section to 8.
A data piece that starts at an address which is not a multiple of 8 (next to a
unit's own data) would then be padded by the linker, and its doubles moved. The
bytes are in splat's comment, so the directive is written as two words.

usage: assemble.py <as> <in.s> <out.o> [as flags...]
"""

import re
import subprocess
import sys
from pathlib import Path

from vfpu_words import convert

# `/* <offset> <address> <16 hex digits: the 8 bytes in file order> */ .double <value>`
DOUBLE = re.compile(r"^(\s*/\* [0-9A-Fa-f]+ [0-9A-Fa-f]+ ([0-9A-Fa-f]{16}) \*/\s*)\.double\b.*$", re.M)


def double_words(text: str) -> str:
    def words(m: re.Match) -> str:
        data = bytes.fromhex(m.group(2))
        low, high = (int.from_bytes(data[i:i + 4], "little") for i in (0, 4))
        return f"{m.group(1)}.word 0x{low:08X}, 0x{high:08X}"
    return DOUBLE.sub(words, text)


def main() -> None:
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    assembler, src, out, flags = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4:]
    out.parent.mkdir(parents=True, exist_ok=True)
    filtered = out.with_suffix(".vfpu.s")
    filtered.write_text(double_words(convert(src.read_text())), newline="\n")
    # Windows CreateProcess does not find a relative path written with '/'
    result = subprocess.run([str(Path(assembler).resolve()), *flags, "-o", str(out), str(filtered)])
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
