#!/usr/bin/env python3
"""Compile one C/C++ file with SNC, then drop its empty allocated sections and make
its static initialization global.

SNC always emits `.rodata` and `.data`, 8-byte aligned, even when empty; GNU ld
still aligns the location counter for them, which moves everything after. The
original link shows no such padding, so empty sections are removed.

The static initialization of a file (`__sti__<file>_cpp`) is a local symbol, but the
`.cplinit` table, still assembly, refers to it by name (config/<version>/
symbol_addrs.txt): it is made global.

usage: compile.py <objcopy> <out.o> <compiler command...>
(the compiler command must write <out.o>)
"""

import struct
import subprocess
import sys
from pathlib import Path

SHF_ALLOC = 0x2


def empty_alloc_sections(path: Path) -> list[str]:
    d = path.read_bytes()
    shoff, = struct.unpack_from("<I", d, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x2E)
    headers = [struct.unpack_from("<10I", d, shoff + i * shentsize) for i in range(shnum)]
    strtab = headers[shstrndx][4]
    names = []
    for name, _type, flags, _addr, _off, size, *_ in headers:
        if flags & SHF_ALLOC and size == 0:
            names.append(d[strtab + name:d.index(b"\0", strtab + name)].decode())
    return names


def main() -> None:
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    objcopy, out, command = sys.argv[1], Path(sys.argv[2]), sys.argv[3:]
    out.parent.mkdir(parents=True, exist_ok=True)
    # Windows CreateProcess does not find a relative path written with '/'
    command[0] = str(Path(command[0]).resolve())
    result = subprocess.run(command)
    if result.returncode:
        sys.exit(result.returncode)
    args = [str(Path(objcopy).resolve()), "--wildcard", "--globalize-symbol=__sti__*"]
    for name in empty_alloc_sections(out):
        args += ["--remove-section", name]
    subprocess.run(args + [str(out)], check=True)


if __name__ == "__main__":
    main()
