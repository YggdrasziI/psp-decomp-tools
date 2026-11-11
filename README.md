psp-decomp-tools
================

> [!IMPORTANT]
> AI Disclosure:
> AI was used for the following tasks:
> - Writing commentary (primarily translating into English and formatting).
> - Documenting and citing the various sources used in the project.
> - Writing code (C, C++, Python, etc.—I used it as a tool) and reviewing my own work (yes, some code was written by AI, but it was verified by a human; I didn't simply type "Claude, decompile this for me").

Shared tooling for matching decompilations of PSP games built with
[splat](https://github.com/ethteck/splat), GNU binutils and
[objdiff](https://github.com/encounter/objdiff). It is meant to be used as a git
submodule at `tools/psp/` of a project.

Projects using it:

- [mhfu-decomp](https://github.com/YggdrasziI/mhfu-decomp): Monster Hunter Freedom Unite

Setup
=====

```sh
git submodule add https://github.com/YggdrasziI/psp-decomp-tools.git tools/psp
python tools/psp/check_traces.py --install-hooks
```

The tools find the project from the current directory upwards through a
`decomp.toml` (see `project.py` for every key):

```toml
title = "Game title"
versions = ["ULES01213"]

[modules.boot]
file = "BOOT.BIN"          # orig/<version>/BOOT.BIN
splat = "splat.boot.yaml"  # config/<version>/splat.boot.yaml
relocatable = false        # true for a PRX
```

Tools
=====

| Tool | Purpose |
|---|---|
| `prx.py` | Minimal reader for PSP modules: PRX (type 0xFFA0) and static executables (`BOOT.BIN`) |
| `prx_info.py` | Print headers, sections, module info, imports and relocations of a module |
| `prx_symbols.py` | splat symbols proven by the module tables: imports named from their NID, exports |
| `prx_reloc.py` | Move PRX segment-relative references to absolute form and back (splat, then the build) |
| `reloc_overrides.py` | `MIPS_NONE` overrides for constants spimdisasm mistook for addresses (PRX only) |
| `vfpu_words.py`, `assemble.py` | Assemble splat output with GNU as: VFPU and Allegrex-only instructions become `.word` |
| `compile.py` | Run a compiler, then drop empty allocated sections |
| `lmgr_patch.py` | Let Metrowerks compilers run natively on Windows (FLEXlm checkout stubbed, as wibo does); applied by `download_tool.py` |
| `compiler_probe.py` | Compile a probe file and compare its `func_XXXXXXXX` functions with the original |
| `asm_compare.py` | One function side by side, from `objdiff-cli diff` |
| `report_diff.py` | Regression gate between two objdiff reports |
| `progress_badges.py` | README badges, progress card and history from the objdiff report |
| `unit_candidates.py`, `tu_ends.py` | Find the next functions to decompile and translation-unit ends |
| `batch_units.py` | Decompile small functions in batches (m2c drafts, tail-call forwarders), keep the matching ones as units (`[batch]` in `decomp.toml`) |
| `ghidra_sync.py`, `ghidra/SyncSymbols.java` | Push the splat symbols to a Ghidra project (ghidra-allegrex) headless |
| `check_traces.py` | Pre-commit / CI guard against local paths, attribution trailers and private files |
| `download_tool.py`, `get_platform.py`, `ninja_syntax.py`, `sha1.py` | Build helpers |
| `nids.txt` | NID → function name, extracted from PPSSPP's HLE tables (`prx_symbols.py --ppsspp`) |
| `probes/` | Compiler probe sources |

Provenance
==========

- `ninja_syntax.py` comes from [ninja](https://github.com/ninja-build/ninja) (Apache-2.0,
  header kept); `get_platform.py` and `download_tool.py` come from
  [Yotona/twewy](https://github.com/Yotona/twewy) (CC0-1.0), modified.
- `nids.txt` holds only the NID → name facts from PPSSPP's `Core/HLE/*.cpp`
  (GPL-2.0-or-later), no code.
- `vfpu_words.py` follows the idea of sotn-decomp's `tools/pspas` (AGPL-3.0), written
  from scratch; the HI16/LO16 pairing of `prx_reloc.py` follows the behaviour of
  PPSSPP's `ElfReader::LoadRelocations`, written from scratch.
- Everything else is original work released under CC0-1.0 (`LICENSE`).
