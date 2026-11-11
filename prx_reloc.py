#!/usr/bin/env python3
"""Move the segment-1 references of a PRX between relative and absolute form.

In the PRX file, every address that points into program header 1 (.sdata,
.sbss, .bss) is stored relative to that segment's base, and the PSP loader adds
the base at load time. Disassembling that form gives wrong symbols (0x170 in
.text instead of .bss 0x140A18), so the build works on an "absolute" image:

    --absolute: add the base of segment 1 at those relocation sites
                (original PRX -> image that splat disassembles)
    --relative: subtract it again
                (linked image -> PRX, compared with the original)

The arithmetic follows the PSP loader as implemented in PPSSPP
(Core/ELF/ElfReader.cpp, ElfReader::LoadRelocations): a HI16 pairs with the
next relocation of the table that is not a HI16, and every value is computed
from the words as they were before patching.
"""

import argparse
import struct
import sys
from pathlib import Path

from prx import R_MIPS_26, R_MIPS_32, R_MIPS_HI16, R_MIPS_LO16, Prx


def s16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def shift_segment_refs(prx: Prx, delta: int, segment: int = 1) -> bytes:
    """Return the PRX bytes with `delta` added to every reference to `segment`."""
    data = bytearray(prx.data)
    file_base = [seg.offset - seg.vaddr for seg in prx.segments]

    for name in {r.section for r in prx.relocs()}:
        table = [r for r in prx.relocs() if r.section == name]
        # Words before patching, as the loader reads them first
        words = [struct.unpack_from("<I", data, file_base[r.offset_seg] + r.offset)[0]
                 if r.offset % 4 == 0 or r.type == R_MIPS_32 else 0 for r in table]
        for i, r in enumerate(table):
            if r.addr_seg != segment:
                continue
            pos = file_base[r.offset_seg] + r.offset
            op = words[i]
            if r.type == R_MIPS_32:
                op = (op + delta) & 0xFFFFFFFF
            elif r.type == R_MIPS_LO16:
                op = (op & 0xFFFF0000) | ((op + delta) & 0xFFFF)
            elif r.type == R_MIPS_HI16:
                lo = next((j for j in range(i + 1, len(table)) if table[j].type != R_MIPS_HI16), None)
                if lo is None:
                    sys.exit(f"{name}: HI16 at {r.offset:#x} has no matching LO16")
                full = ((op & 0xFFFF) << 16) + s16(words[lo]) + delta
                op = (op & 0xFFFF0000) | (((full + 0x8000) >> 16) & 0xFFFF)
            elif r.type == R_MIPS_26:
                op = (op & 0xFC000000) | ((op + (delta >> 2)) & 0x03FFFFFF)
            else:
                sys.exit(f"{name}: unsupported relocation type {r.type} at {r.offset:#x}")
            struct.pack_into("<I", data, pos, op)
    return bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--absolute", action="store_true")
    mode.add_argument("--relative", action="store_true")
    args = parser.parse_args()

    prx = Prx(args.input)
    base = prx.segments[1].vaddr
    out = shift_segment_refs(prx, base if args.absolute else -base)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(out)


if __name__ == "__main__":
    main()
