#!/usr/bin/env python3
"""Assemble a splat .s file: VFPU instructions to .word (vfpu_words.py), then GNU as.

usage: assemble.py <as> <in.s> <out.o> [as flags...]
"""

import subprocess
import sys
from pathlib import Path

from vfpu_words import convert


def main() -> None:
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    assembler, src, out, flags = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4:]
    out.parent.mkdir(parents=True, exist_ok=True)
    filtered = out.with_suffix(".vfpu.s")
    filtered.write_text(convert(src.read_text()), newline="\n")
    # Windows CreateProcess does not find a relative path written with '/'
    result = subprocess.run([str(Path(assembler).resolve()), *flags, "-o", str(out), str(filtered)])
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
