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

A third-party source kept unmodified may hold functions the original link dropped
(unused ones): `--drop-function <name>` removes the function's own section from the
object, with its relocations and the sections that only describe it. It needs a
compiler that gives each function its own section (Metrowerks does).

usage: compile.py [--rename-section <old>=<new>]... [--drop-function <name>]...
                  <objcopy> <out.o> <compiler command...>
(the compiler command must write <out.o>)
"""

import struct
import os
import subprocess
import sys
from pathlib import Path

SHF_ALLOC = 0x2
SHT_SYMTAB, SHT_REL = 2, 9
STT_FUNC = 2
# suffix of the sections to remove: several sections of an object can share a name
# (Metrowerks: one `.text` per function), so they are renamed one by one, by header,
# and objcopy removes that name
DROPPED = ".dropped"


def mark_dropped(path: Path, functions: list[str]) -> bool:
    """Rename to `<name>.dropped` the sections objcopy must remove; False if none.

    - every empty allocated section;
    - the section that holds each of `functions`, the relocation sections that apply
      to a marked section, and the non-allocated sections whose relocations refer to
      a symbol of a marked section (Metrowerks' per-function `.mwcats`). An allocated
      section that refers to a dropped function is an error: the function is used."""
    d = bytearray(path.read_bytes())
    shoff, = struct.unpack_from("<I", d, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x2E)
    headers = [list(struct.unpack_from("<10I", d, shoff + i * shentsize)) for i in range(shnum)]

    def string(table: int, offset: int) -> str:
        start = headers[table][4] + offset
        return d[start:d.index(b"\0", start)].decode()

    marked = {i for i, h in enumerate(headers) if h[2] & SHF_ALLOC and h[5] == 0}
    if functions:
        symtab = next(i for i, h in enumerate(headers) if h[1] == SHT_SYMTAB)
        symbols = [struct.unpack_from("<IIIBBH", d, headers[symtab][4] + k * 16)
                   for k in range(headers[symtab][5] // 16)]
        code = {}  # section -> names of its functions
        for name, _value, _size, info, _other, shndx in symbols:
            if info & 0xF == STT_FUNC and 0 < shndx < shnum:
                code.setdefault(shndx, []).append(string(headers[symtab][6], name))
        for function in functions:
            found = [shndx for shndx, names in code.items() if function in names]
            if len(found) != 1:
                sys.exit(f"compile.py: --drop-function {function}: {len(found)} function symbols in {path}")
            if len(code[found[0]]) != 1:
                sys.exit(f"compile.py: --drop-function {function}: its section holds other functions")
            marked.add(found[0])
        grown = True
        while grown:
            grown = False
            for i, h in enumerate(headers):
                if h[1] != SHT_REL or i in marked:
                    continue
                if h[7] in marked:
                    marked.add(i)
                    grown = True
                    continue
                for k in range(h[5] // 8):
                    _offset, info = struct.unpack_from("<II", d, h[4] + k * 8)
                    if symbols[info >> 8][5] not in marked:
                        continue
                    if headers[h[7]][2] & SHF_ALLOC:
                        sys.exit(f"compile.py: --drop-function: section {string(shstrndx, headers[h[7]][0])} "
                                 f"of {path} refers to a dropped function")
                    marked.update((i, h[7]))
                    grown = True
                    break
    if not marked:
        return False
    # new section name table: the old one, then the names of the marked sections
    names = bytearray(d[headers[shstrndx][4]:headers[shstrndx][4] + headers[shstrndx][5]])
    for i in sorted(marked):
        new = string(shstrndx, headers[i][0]) + DROPPED
        headers[i][0] = len(names)
        names += new.encode() + b"\0"
    headers[shstrndx][4], headers[shstrndx][5] = len(d), len(names)
    d += names
    for i, h in enumerate(headers):
        struct.pack_into("<10I", d, shoff + i * shentsize, *h)
    path.write_bytes(d)
    return True


def main() -> None:
    # Metrowerks drivers warn and stop without it; includes come from -I flags
    os.environ.setdefault("MWCIncludes", ".")
    argv = sys.argv[1:]
    renames = []
    dropped = []
    while argv and argv[0] in ("--rename-section", "--drop-function"):
        if len(argv) < 2 or not argv[1]:
            sys.exit(f"compile.py: {argv[0]}: value missing")
        if argv[0] == "--drop-function":
            dropped.append(argv[1])
        elif "=" not in argv[1]:
            sys.exit(f"compile.py: --rename-section {argv[1]}: expected <old>=<new>")
        else:
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
    try:
        args = [str(Path(objcopy).resolve()), "--wildcard", "--globalize-symbol=__sti__*"]
        if mark_dropped(out, dropped):
            args += ["--remove-section", f"*{DROPPED}"]
        for rename in renames:
            # an empty section of the old name is removed above, not renamed
            args += ["--rename-section", f"{rename},alloc,load,data,contents"]
        subprocess.run(args + [str(out)], check=True)
    except BaseException:
        # never leave the compiler's raw object behind as an up-to-date output
        out.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    main()
