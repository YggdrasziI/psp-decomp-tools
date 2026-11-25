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
(switch jump tables, constants) and makes it writable data. Flags after the new
name (`--rename-section <old>=<new>,<flags>`, objcopy's) replace those: the same name
with `alloc,load,readonly,data,contents` keeps a section where it is but drops its
merge flag, for a link that did not merge constants and strings
(`.rodata.cst4`, `.rodata.str1.4`) where GNU ld would.

A file compiled in another directory than the build's (its `__FILE__` strings and
include paths as the original build had them): `--cwd <dir>` runs the compiler there.
An argument naming an existing path under `<dir>` (the source) is given relative to
it, any other existing path (the compiler, a script) absolute, `<out.o>` absolute;
flags are passed as they are, so their paths must be relative to `<dir>`.

Header dependencies, for a GCC-compatible compiler: `--depfile <file>` adds `-MD -MF`
to the compilation and writes `<file>` in the form ninja reads (`depfile = $out.d`,
`deps = gcc`): the headers the source includes, as paths relative to the build's
directory wherever the compiler ran (`--cwd`, a Linux compiler under WSL: `/mnt/<x>/`
becomes `<X>:/`). Headers that do not exist on this machine (the compiler's own, in
its Linux install) are left out.

A third-party source kept unmodified may hold functions the original link dropped
(unused ones): `--drop-function <name>` removes the function's own section from the
object, with its relocations and the sections that only describe it. It needs a
compiler that gives each function its own section (Metrowerks does).

A GCC built with the Sony binutils 2.14 assembler of the PSP SDK 1.3.1 (`allegrex
(mips2)`) cannot assemble the unaligned loads and stores `lwl`, `lwr`, `swl`, `swr`
that GCC emits for copies of unaligned structures, though the Allegrex has them:
`--unaligned-words` compiles to assembly (`-S`), writes each of them as its `.word`
encoding, then assembles with the same compiler command. The assembler expands none
of them (a numeric offset that fits) and moves none of them inside `.set noreorder`;
under `.set reorder` it only moves the instruction just before a branch or jump into
its delay slot, which a `.word` would not fill: an unaligned access there, or any
other form, stops the build. So the bytes are the same.

GCC describes a function of a `.gnu.linkonce.t.<name>` section in `.eh_frame` with a
relocation against the section itself. When the link keeps another object's copy of
the function, GNU ld writes 0 there; the linker of a game whose `.eh_frame` entries of
the discarded copies hold the kept copy's address used the kept section instead.
`--linkonce-symbols` gives the same bytes: each `R_MIPS_32` against the section
symbol of a `.gnu.linkonce.t.<name>` section, from another section, is made a
relocation against the global or weak symbol `<name>` when that symbol is defined at
the start of the section, so the link resolves it to the copy it keeps.

usage: compile.py [--rename-section <old>=<new>[,<flags>]]... [--drop-function <name>]...
                  [--unaligned-words] [--linkonce-symbols] [--cwd <dir>]
                  <objcopy> <out.o> <compiler command...>
(the compiler command must write <out.o>; with --unaligned-words it must be
`<compiler> ... -c ... -o <out.o> ... <source>`, the source last)
"""

import re
import struct
import os
import subprocess
import sys
from pathlib import Path

SHF_ALLOC = 0x2
SHT_SYMTAB, SHT_REL = 2, 9
STT_FUNC, STT_SECTION = 2, 3
STB_GLOBAL, STB_WEAK = 1, 2
R_MIPS_32 = 2
# suffix of the sections to remove: several sections of an object can share a name
# (Metrowerks: one `.text` per function), so they are renamed one by one, by header,
# and objcopy removes that name
DROPPED = ".dropped"

UNALIGNED_OPS = {"lwl": 0x22, "lwr": 0x26, "swl": 0x2A, "swr": 0x2E}
GPR_NAMES = ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4",
             "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9",
             "k0", "k1", "gp", "sp", "fp", "ra"]
GPRS = {f"${i}": i for i in range(32)} | {f"${n}": i for i, n in enumerate(GPR_NAMES)} | {"$s8": 30}
UNALIGNED = re.compile(r"^(\s*)(lwl|lwr|swl|swr)\s+(\$\w+)\s*,\s*(-?\d+)\s*\(\s*(\$\w+)\s*\)\s*$")


def next_is_branch(lines: list[str]) -> bool:
    """Whether the next instruction is a branch or jump (a label in between: no)."""
    for line in lines:
        s = line.split("#")[0].strip()
        if not s or (s.startswith(".") and not s.endswith(":")):
            continue
        if s.endswith(":"):
            return False
        return s.split()[0].startswith(("b", "j"))
    return False


def unaligned_words(text: str, name: str) -> str:
    """Write GCC's lwl/lwr/swl/swr as their `.word` encoding (module docstring)."""
    noreorder = False
    out = []
    lines = text.splitlines(keepends=True)
    for n, line in enumerate(lines, 1):
        words = line.split()
        if words and words[0] == ".set" and len(words) > 1:
            noreorder = {"noreorder": True, "reorder": False}.get(words[1], noreorder)
        if not words or words[0] not in UNALIGNED_OPS:
            out.append(line)
            continue
        m = UNALIGNED.match(line.rstrip("\r\n"))
        if not m or m.group(3) not in GPRS or m.group(5) not in GPRS:
            sys.exit(f"compile.py: {name}:{n}: unexpected form: {line.strip()}")
        if not noreorder and next_is_branch(lines[n:]):
            sys.exit(f"compile.py: {name}:{n}: {m.group(2)} before a branch under .set reorder")
        offset = int(m.group(4))
        if not -0x8000 <= offset < 0x8000:
            sys.exit(f"compile.py: {name}:{n}: offset out of range")
        word = (UNALIGNED_OPS[m.group(2)] << 26 | GPRS[m.group(5)] << 21
                | GPRS[m.group(3)] << 16 | offset & 0xFFFF)
        out.append(f"{m.group(1)}.word\t0x{word:08x}\t# {line.strip()}\n")
    return "".join(out)


def in_dir(command: list[str], out: Path, cwd: Path) -> list[str]:
    """The command's paths for a compiler run in `cwd` (module docstring)."""
    base = cwd.resolve()
    result = []
    for arg in command:
        path = Path(arg)
        if path == out:
            result.append(str(out.resolve()))
        elif not arg.startswith("-") and path.exists():
            full = path.resolve()
            result.append(full.relative_to(base).as_posix() if full.is_relative_to(base) else str(full))
        else:
            result.append(arg)
    return result


def write_depfile(raw: Path, depfile: Path, target: str, cwd: Path | None) -> None:
    """Turn the compiler's dependency file into ninja's (module docstring)."""
    text = raw.read_text(encoding="utf-8", errors="replace").replace("\\\n", " ")
    raw.unlink(missing_ok=True)
    names = re.findall(r"(?:[^\s\\]|\\.)+", text.partition(": ")[2])
    root = Path.cwd().resolve()
    base = (cwd or root).resolve()
    deps = []
    for name in names:
        name = name.replace("\\ ", " ")
        if m := re.match(r"^/mnt/([a-z])/(.*)$", name):
            path = Path(f"{m.group(1).upper()}:/{m.group(2)}")
        else:
            path = Path(name) if Path(name).is_absolute() else base / name
        if not path.exists():
            continue
        path = path.resolve()
        shown = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
        if shown not in deps:
            deps.append(shown)
    depfile.write_text(target + ": " + " ".join(d.replace(" ", "\\ ") for d in deps) + "\n",
                       encoding="utf-8", newline="\n")


def compile_unaligned_words(command: list[str], out: Path, cwd: Path | None = None) -> int:
    """Compile to assembly, rewrite the unaligned accesses, assemble (module docstring)."""
    if command.count("-c") != 1 or command.count("-o") != 1:
        sys.exit("compile.py: --unaligned-words: the command needs one -c and one -o")
    asm = out.with_name(out.name + ".s")
    o = command.index("-o")
    first = [a if a != "-c" else "-S" for a in command]
    first[o + 1] = str(asm)
    result = subprocess.run(first, cwd=cwd)
    if result.returncode:
        return result.returncode
    try:
        text = asm.read_text(encoding="utf-8")
        asm.write_text(unaligned_words(text, str(asm)), encoding="utf-8", newline="\n")
        return subprocess.run(command[:-1] + [str(asm)], cwd=cwd).returncode
    finally:
        asm.unlink(missing_ok=True)


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


def linkonce_symbols(path: Path) -> None:
    """Retarget the data relocations against `.gnu.linkonce.t.<name>` section symbols
    at the symbol `<name>` (module docstring)."""
    d = bytearray(path.read_bytes())
    shoff, = struct.unpack_from("<I", d, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x2E)
    headers = [struct.unpack_from("<10I", d, shoff + i * shentsize) for i in range(shnum)]

    def string(table: int, offset: int) -> str:
        start = headers[table][4] + offset
        return d[start:d.index(b"\0", start)].decode()

    symtab = next(i for i, h in enumerate(headers) if h[1] == SHT_SYMTAB)
    symbols = [struct.unpack_from("<IIIBBH", d, headers[symtab][4] + k * 16)
               for k in range(headers[symtab][5] // 16)]
    prefix = ".gnu.linkonce.t."
    named = {}  # linkonce section -> index of the global or weak symbol it is named after
    for k, (name, value, _size, info, _other, shndx) in enumerate(symbols):
        if info >> 4 not in (STB_GLOBAL, STB_WEAK) or value or not 0 < shndx < shnum:
            continue
        if string(shstrndx, headers[shndx][0]) == prefix + string(headers[symtab][6], name):
            named[shndx] = k
    changed = False
    for h in headers:
        if h[1] != SHT_REL:
            continue
        for k in range(h[5] // 8):
            _offset, info = struct.unpack_from("<II", d, h[4] + k * 8)
            symbol = symbols[info >> 8]
            section = symbol[5]
            if info & 0xFF == R_MIPS_32 and symbol[3] & 0xF == STT_SECTION and section in named and section != h[7]:
                struct.pack_into("<I", d, h[4] + k * 8 + 4, named[section] << 8 | R_MIPS_32)
                changed = True
    if changed:
        path.write_bytes(d)


def main() -> None:
    # Metrowerks drivers warn and stop without it; includes come from -I flags
    os.environ.setdefault("MWCIncludes", ".")
    argv = sys.argv[1:]
    renames = []
    dropped = []
    unaligned = False
    linkonce = False
    cwd = None
    depfile = None
    while argv and argv[0] in ("--rename-section", "--drop-function", "--unaligned-words",
                               "--linkonce-symbols", "--cwd", "--depfile"):
        if argv[0] in ("--unaligned-words", "--linkonce-symbols"):
            unaligned = unaligned or argv[0] == "--unaligned-words"
            linkonce = linkonce or argv[0] == "--linkonce-symbols"
            argv = argv[1:]
            continue
        if len(argv) < 2 or not argv[1]:
            sys.exit(f"compile.py: {argv[0]}: value missing")
        if argv[0] == "--drop-function":
            dropped.append(argv[1])
        elif argv[0] == "--depfile":
            depfile = Path(argv[1]).resolve()
        elif argv[0] == "--cwd":
            cwd = Path(argv[1])
            if not cwd.is_dir():
                sys.exit(f"compile.py: --cwd {argv[1]}: not a directory")
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
    if cwd:
        out = out.resolve()
        command = in_dir(command, Path(argv[1]), cwd)
    if depfile:
        # with -c (the command may start with a runner and the compiler's path); the
        # first step of --unaligned-words keeps every flag
        if "-c" not in command:
            sys.exit("compile.py: --depfile: the command needs -c")
        raw = depfile.with_name(depfile.name + ".raw")
        at = command.index("-c")
        command[at:at] = ["-MD", "-MF", str(raw)]
    code = (compile_unaligned_words(command, out, cwd) if unaligned
            else subprocess.run(command, cwd=cwd).returncode)
    if code:
        sys.exit(code)
    if depfile:
        write_depfile(raw, depfile, Path(argv[1]).as_posix(), cwd)
    try:
        if linkonce:
            linkonce_symbols(out)
        args = [str(Path(objcopy).resolve()), "--wildcard", "--globalize-symbol=__sti__*"]
        if mark_dropped(out, dropped):
            args += ["--remove-section", f"*{DROPPED}"]
        for rename in renames:
            # an empty section of the old name is removed above, not renamed
            args += ["--rename-section", rename if "," in rename else f"{rename},alloc,load,data,contents"]
        subprocess.run(args + [str(out)], check=True)
    except BaseException:
        # never leave the compiler's raw object behind as an up-to-date output
        out.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    main()
