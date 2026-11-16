#!/usr/bin/env python3
"""Compile one C/C++ file with SNC, then drop its empty allocated sections and make
its static initialization global.

SNC always emits `.rodata` and `.data`, 8-byte aligned, even when empty; GNU ld
still aligns the location counter for them, which moves everything after. The
original link shows no such padding, so empty sections are removed.

The static initialization of a file (`__sti__<file>_cpp`) is a local symbol, but the
`.cplinit` table, still assembly, refers to it by name (config/<version>/
symbol_addrs.txt): it is made global.

A game whose link merged the read-only data into `.data` (no `.rodata` in the
image) needs the same in each unit before its data can sit at its own place in the
linker script: `--rename-section .rodata=.data` renames every section of that name
(switch jump tables, constants) and makes it writable data.

usage: compile.py [--rename-section <old>=<new>]... <objcopy> <out.o> <compiler command...>
(the compiler command must write <out.o>)
"""

import struct
import os
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
    # Metrowerks drivers warn and stop without it; includes come from -I flags
    os.environ.setdefault("MWCIncludes", ".")
    argv = sys.argv[1:]
    renames = []
    while len(argv) >= 2 and argv[0] == "--rename-section":
        if "=" not in argv[1]:
            sys.exit(f"compile.py: --rename-section {argv[1]}: expected <old>=<new>")
        renames.append(argv[1])
        argv = argv[2:]
    if len(argv) < 3:
        sys.exit(__doc__)
    objcopy, out, command = argv[0], Path(argv[1]), argv[2:]
    out.parent.mkdir(parents=True, exist_ok=True)
    # Windows CreateProcess does not find a relative path written with '/'
    command[0] = str(Path(command[0]).resolve())
    result = subprocess.run(command)
    if result.returncode:
        sys.exit(result.returncode)
    args = [str(Path(objcopy).resolve()), "--wildcard", "--globalize-symbol=__sti__*"]
    for name in empty_alloc_sections(out):
        args += ["--remove-section", name]
    for rename in renames:
        # an empty section of the old name is removed above, not renamed
        args += ["--rename-section", f"{rename},alloc,load,data,contents"]
    subprocess.run(args + [str(out)], check=True)


if __name__ == "__main__":
    main()
