"""Project settings shared by the tools, read from `decomp.toml` at the project root.

The tools live in a git submodule (usually `tools/psp/`) of a decompilation project.
The project root is the first folder, from the current directory upwards, that holds
a `decomp.toml`; set DECOMP_ROOT to override it.

decomp.toml:

    title = "Game title"                  # progress card
    versions = ["ULES01213", ...]         # first one is the default version
    binutils_prefix = "mips-ps2-decompals-"

    [modules.boot]                        # first module is the default module
    file = "BOOT.BIN"                     # in orig/<version>/
    splat = "splat.boot.yaml"             # in config/<version>/
    relocatable = false                   # true for a PRX (prx_reloc.py)

    [regions.ULES01213]                   # optional: code regions of the progress card
    "Game" = [[0x08804000, 0x0890DE38]]

    [compiler]                            # optional: compiler of the C/C++ units
    name = "mwccpsp_3.0.1_219"            # tools/compilers/<name>/ (decomp.me archive)
    exe = "mwccpsp.exe"
    flags = "-O4"                         # code generation flags, no include paths

    [batch]                               # optional: batch_units.py
    splits = "notes/SPLITS.md"            # table of units to add rows to
    [batch.ranges]                        # address ranges to scan, per version
    ULES01213 = [[0x08811C00, 0x08904000]]
"""

import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

TOOLS = Path(__file__).resolve().parent


def find_root() -> Path:
    if env := os.environ.get("DECOMP_ROOT"):
        return Path(env).resolve()
    here = Path.cwd().resolve()
    for d in (here, *here.parents):
        if (d / "decomp.toml").is_file():
            return d
    sys.exit("decomp.toml not found (run from inside the project, or set DECOMP_ROOT)")


ROOT = find_root()
CONFIG = tomllib.loads((ROOT / "decomp.toml").read_text(encoding="utf-8"))

TITLE: str = CONFIG.get("title", ROOT.name)
VERSIONS: list[str] = CONFIG["versions"]
DEFAULT_VERSION: str = VERSIONS[0]
BINUTILS_PREFIX: str = CONFIG.get("binutils_prefix", "mips-ps2-decompals-")


@dataclass
class Module:
    name: str
    file: str
    splat: str
    relocatable: bool


MODULES: dict[str, Module] = {
    name: Module(name, m["file"], m["splat"], m.get("relocatable", False))
    for name, m in CONFIG.get("modules", {}).items()
}
DEFAULT_MODULE: str = next(iter(MODULES), "")


def regions(version: str) -> list:
    """[(label, [(start, end), ...])] code regions of the progress card."""
    return [(label, [tuple(r) for r in ranges])
            for label, ranges in CONFIG.get("regions", {}).get(version, {}).items()]


def orig_dir(version: str) -> Path:
    return ROOT / "orig" / version


def config_dir(version: str) -> Path:
    return ROOT / "config" / version


def build_dir(version: str) -> Path:
    return ROOT / "build" / version


def asm_dir(version: str, module: str) -> Path:
    return ROOT / "asm" / version / module


def module_file(version: str, module: str) -> Path:
    return orig_dir(version) / MODULES[module].file


def binutil(name: str) -> Path:
    exe = ".exe" if os.name == "nt" else ""
    return ROOT / "tools" / "binutils" / f"{BINUTILS_PREFIX}{name}{exe}"


def compiler() -> tuple[list[str], list[str]]:
    """([command], [flags]) of the [compiler] of decomp.toml, wibo first off Windows.
    The flags are the code generation ones; include paths are added by the caller."""
    cc = CONFIG.get("compiler")
    if not cc:
        sys.exit("decomp.toml: no [compiler] section")
    exe = ROOT / "tools" / "compilers" / cc["name"] / cc["exe"]
    command = [str(exe)] if os.name == "nt" else [str(ROOT / "tools" / "wibo"), str(exe)]
    return command, cc.get("flags", "").split()


def objdiff_cli() -> Path:
    return ROOT / ("objdiff-cli.exe" if os.name == "nt" else "objdiff-cli")
