"""Minimal reader for PSP modules: PRX (relocatable ELF, type 0xFFA0) and static
executables (ET_EXEC, e.g. BOOT.BIN). Addresses are virtual addresses of the first
program header (0 for a PRX).

Only what the project needs: section and program headers, the module info,
import stubs (by NID) and the PSP relocation tables (SHT_PRXRELOC).
"""

import struct
from dataclasses import dataclass
from pathlib import Path

SHT_NOBITS = 8
SHT_PRXRELOC = 0x700000A0

R_MIPS_32 = 2
R_MIPS_26 = 4
R_MIPS_HI16 = 5
R_MIPS_LO16 = 6
RELOC_NAMES = {R_MIPS_32: "R_MIPS_32", R_MIPS_26: "R_MIPS_26",
               R_MIPS_HI16: "R_MIPS_HI16", R_MIPS_LO16: "R_MIPS_LO16"}


@dataclass
class Section:
    index: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    align: int
    entsize: int

    @property
    def has_file_data(self) -> bool:
        return self.type != SHT_NOBITS


@dataclass
class Segment:
    type: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    align: int


@dataclass
class Reloc:
    offset: int      # relative to the base of segment `offset_seg`
    type: int
    offset_seg: int  # program header the offset is relative to
    addr_seg: int    # program header the target address is relative to
    section: str     # section the relocation table applies to


@dataclass
class Import:
    library: str
    version: int
    flags: int
    nids: list[int]
    stub_addrs: list[int]   # address of each function stub (8 bytes each)
    var_count: int


class Prx:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ValueError(f"{path}: not an ELF file (encrypted EBOOT?)")
        (self.type, self.machine, _, self.entry, phoff, shoff, self.flags,
         _, phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(
            "<HHIIIIIHHHHHH", d, 0x10)
        self.phoff, self.shoff = phoff, shoff
        self.segments = [Segment(*struct.unpack_from("<8I", d, phoff + i * phentsize))
                         for i in range(phnum)]
        raw = [struct.unpack_from("<10I", d, shoff + i * shentsize) for i in range(shnum)]
        strtab = raw[shstrndx][4]

        def name(off: int) -> str:
            end = d.index(b"\0", strtab + off)
            return d[strtab + off:end].decode()

        self.sections = [Section(i, name(r[0]), *r[1:]) for i, r in enumerate(raw)]
        self.shstrndx = shstrndx

    def section(self, name: str) -> Section:
        for s in self.sections:
            if s.name == name:
                return s
        raise KeyError(name)

    def read(self, addr: int, size: int) -> bytes:
        """Read `size` bytes at a virtual address of the first segment."""
        seg = self.segments[0]
        start = seg.offset + addr - seg.vaddr
        return self.data[start:start + size]

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def cstr(self, addr: int) -> str:
        seg = self.segments[0]
        start = seg.offset + addr - seg.vaddr
        return self.data[start:self.data.index(b"\0", start)].decode("latin-1")

    def module_info(self) -> dict:
        s = self.section(".rodata.sceModuleInfo")
        o = s.offset
        attr, ver = struct.unpack_from("<HH", self.data, o)
        name = self.data[o + 4:o + 32].split(b"\0")[0].decode()
        gp, ent, ent_end, stub, stub_end = struct.unpack_from("<5I", self.data, o + 32)
        return {"attr": attr, "version": ver, "name": name, "gp": gp,
                "ent_top": ent, "ent_end": ent_end, "stub_top": stub, "stub_end": stub_end}

    def imports(self) -> list[Import]:
        info = self.module_info()
        result = []
        addr = info["stub_top"]
        while addr < info["stub_end"]:
            name_ptr, version, flags = struct.unpack("<IHH", self.read(addr, 8))
            entsize, var_count, func_count = struct.unpack("<BBH", self.read(addr + 8, 4))
            nid_ptr, stub_ptr = struct.unpack("<II", self.read(addr + 12, 8))
            nids = [self.u32(nid_ptr + 4 * i) for i in range(func_count)]
            stubs = [stub_ptr + 8 * i for i in range(func_count)]
            result.append(Import(self.cstr(name_ptr), version, flags, nids, stubs, var_count))
            addr += entsize * 4
        return result

    def relocs(self) -> list[Reloc]:
        result = []
        for s in self.sections:
            if s.type != SHT_PRXRELOC:
                continue
            target = self.sections[s.info].name
            for i in range(s.size // 8):
                off, info = struct.unpack_from("<II", self.data, s.offset + 8 * i)
                result.append(Reloc(off, info & 0xFF, (info >> 8) & 0xFF,
                                    (info >> 16) & 0xFF, target))
        return result
