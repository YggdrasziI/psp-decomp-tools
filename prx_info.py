#!/usr/bin/env python3
"""Print the layout of a PSP PRX: headers, sections, module info, imports and
relocation statistics."""

import argparse
from collections import Counter
from pathlib import Path

import project
from prx import RELOC_NAMES, Prx


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prx", type=Path, nargs="?",
                        default=project.module_file(project.DEFAULT_VERSION, project.DEFAULT_MODULE))
    parser.add_argument("--imports", action="store_true", help="List every imported NID")
    args = parser.parse_args()

    prx = Prx(args.prx)
    print(f"{args.prx.name}: {len(prx.data):#x} bytes, type {prx.type:#x}, "
          f"entry {prx.entry:#x}, flags {prx.flags:#x}")
    print(f"program headers at {prx.phoff:#x}, section headers at {prx.shoff:#x}")
    for i, seg in enumerate(prx.segments):
        print(f"  seg{i}: off {seg.offset:#08x} vaddr {seg.vaddr:#08x} paddr {seg.paddr:#08x} "
              f"filesz {seg.filesz:#x} memsz {seg.memsz:#x} align {seg.align}")

    print("sections (file order):")
    for s in sorted(prx.sections[1:], key=lambda s: (s.offset, s.index)):
        end = s.offset + (s.size if s.has_file_data else 0)
        print(f"  [{s.index:2}] {s.name:28} type {s.type:#010x} addr {s.addr:#08x} "
              f"off {s.offset:#08x}-{end:#08x} size {s.size:#08x} align {s.align}")

    info = prx.module_info()
    print("module info: " + ", ".join(
        f"{k} {v:#x}" if isinstance(v, int) else f"{k} {v!r}" for k, v in info.items()))

    imports = prx.imports()
    print(f"imports: {len(imports)} libraries, {sum(len(i.nids) for i in imports)} functions")
    for imp in imports:
        print(f"  {imp.library:20} ver {imp.version:#06x} flags {imp.flags:#06x} "
              f"funcs {len(imp.nids):3} vars {imp.var_count} stubs {imp.stub_addrs[0]:#x}"
              if imp.nids else f"  {imp.library:20} (no functions)")
        if args.imports:
            for nid, stub in zip(imp.nids, imp.stub_addrs):
                print(f"    {stub:#08x} {nid:#010x}")

    by_section: dict[str, Counter] = {}
    for r in prx.relocs():
        by_section.setdefault(r.section, Counter())[(RELOC_NAMES.get(r.type, r.type),
                                                     r.offset_seg, r.addr_seg)] += 1
    print("relocations (type, offset segment, address segment): count")
    for name, counts in by_section.items():
        print(f"  {name}: " + ", ".join(f"{t}/{o}/{a}: {n}" for (t, o, a), n in sorted(counts.items())))


if __name__ == "__main__":
    main()
