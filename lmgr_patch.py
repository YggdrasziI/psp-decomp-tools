#!/usr/bin/env python3
"""Let a Metrowerks compiler run natively on Windows: make the FLEXlm license
library (LMGR*.DLL next to mwcc*.exe) report a successful checkout.

Run natively, mwccpsp opens the "FLEXlm License Finder" window and waits. wibo
(Linux, macOS) answers the license calls itself; this does the same on Windows by
replacing the start of `lp_checkout` and `lp_checkin` with `xor eax, eax; ret`
(return 0, success). The original DLL is kept as <name>.orig.

usage: lmgr_patch.py <compiler folder>
"""

import struct
import sys
from pathlib import Path

STUB = b"\x31\xC0\xC3"  # xor eax, eax; ret
FUNCTIONS = ("lp_checkout", "lp_checkin")


def exports(d: bytes) -> dict[str, int]:
    """{name: file offset} of the exported functions of a PE32 DLL."""
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    opt = pe + 24
    exp_rva = struct.unpack_from("<I", d, opt + 96)[0]
    secs = []
    for i in range(nsec):
        vsize, va, rsize, raw = struct.unpack_from("<IIII", d, opt + optsz + 40 * i + 8)
        secs.append((va, max(vsize, rsize), raw))

    def off(rva: int) -> int:
        for va, size, raw in secs:
            if va <= rva < va + size:
                return rva - va + raw
        raise ValueError(f"RVA {rva:#x} outside the sections")

    e = off(exp_rva)
    _, nnames, afuncs, anames, aords = struct.unpack_from("<IIIII", d, e + 20)
    result = {}
    for i in range(nnames):
        o = off(struct.unpack_from("<I", d, off(anames) + 4 * i)[0])
        name = d[o:d.index(0, o)].decode()
        idx = struct.unpack_from("<H", d, off(aords) + 2 * i)[0]
        result[name] = off(struct.unpack_from("<I", d, off(afuncs) + 4 * idx)[0])
    return result


def patch_dll(path: Path) -> bool:
    data = bytearray(path.read_bytes())
    table = exports(data)
    if not all(f in table for f in FUNCTIONS):
        return False
    if all(data[table[f]:table[f] + len(STUB)] == STUB for f in FUNCTIONS):
        return True  # already patched
    backup = path.with_name(path.name + ".orig")
    if not backup.exists():
        backup.write_bytes(data)
    for f in FUNCTIONS:
        data[table[f]:table[f] + len(STUB)] = STUB
    path.write_bytes(data)
    return True


def patch_folder(folder: Path) -> list[Path]:
    return [dll for dll in sorted(folder.iterdir())
            if dll.suffix.lower() == ".dll" and dll.name.lower().startswith("lmgr") and patch_dll(dll)]


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    patched = patch_folder(Path(sys.argv[1]))
    print("patched: " + (", ".join(p.name for p in patched) or "nothing"))


if __name__ == "__main__":
    main()
