#!/usr/bin/env python3
"""Sync the Ghidra project with the splat symbol files, without the Ghidra GUI.

Runs Ghidra's analyzeHeadless with ghidra/SyncSymbols.java on the imported module:
every symbol of config/<version>/symbol_addrs*.txt is named at its address (link
address + the program's image base), and a function is created for `type:func`
symbols. Names set by hand in Ghidra are kept and listed. Needs Ghidra 12.2 with the
ghidra-allegrex v21.5 extension and a JDK 25 (README.md). The Ghidra
install, JDK and project folders come from --ghidra, --jdk and --project, or from the
DECOMP_GHIDRA_INSTALL_DIR, DECOMP_GHIDRA_JDK and DECOMP_GHIDRA_PROJECT environment
variables.

Usage:
  python tools/psp/ghidra_sync.py --import    # first time: create the project, import
                                          # and analyze the PRX, then sync
  python tools/psp/ghidra_sync.py             # sync
  python tools/psp/ghidra_sync.py --dry-run   # report what would change, change nothing
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

import glob

import project

ROOT = str(project.ROOT)
TOOLS = str(project.TOOLS)
DEFAULT_GHIDRA = os.environ.get("DECOMP_GHIDRA_INSTALL_DIR")
DEFAULT_JDK = os.environ.get("DECOMP_GHIDRA_JDK")
DEFAULT_PROJECT = os.environ.get("DECOMP_GHIDRA_PROJECT")
PROJECT_NAME = project.ROOT.name.replace("-", "_")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", default=project.DEFAULT_VERSION, help="game version (default: %(default)s)")
    parser.add_argument("--module", default=project.DEFAULT_MODULE, help="module (default: %(default)s)")
    parser.add_argument("--ghidra", default=DEFAULT_GHIDRA, help="Ghidra install dir")
    parser.add_argument("--jdk", default=DEFAULT_JDK, help="JDK 25 dir (Ghidra 12.2 needs it)")
    parser.add_argument("--project", default=DEFAULT_PROJECT, help="Ghidra project dir")
    parser.add_argument("--import", dest="do_import", action="store_true",
                        help="import and analyze the PRX first")
    parser.add_argument("--dry-run", action="store_true", help="change nothing")
    args = parser.parse_args()
    if not args.ghidra or not args.jdk or not args.project:
        parser.error("set --ghidra, --jdk and --project, or DECOMP_GHIDRA_INSTALL_DIR, "
                     "DECOMP_GHIDRA_JDK and DECOMP_GHIDRA_PROJECT")

    headless = os.path.join(args.ghidra, "support",
                            "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if not os.path.isfile(headless):
        sys.exit(f"{headless} not found (--ghidra)")
    os.makedirs(args.project, exist_ok=True)

    # analyzeHeadless is a batch file on Windows: cmd.exe splits arguments at the
    # "&" of the project folder, so every input is copied to a temporary folder
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copy(os.path.join(TOOLS, "ghidra", "SyncSymbols.java"), tmp)
        prx = project.MODULES[args.module].file
        symbols = []
        for path in sorted(glob.glob(os.path.join(ROOT, "config", args.version, "symbol_addrs*.txt"))):
            symbols.append(shutil.copy(path, tmp))
        cmd = [headless, args.project, f"{PROJECT_NAME}_{args.version}"]
        if args.do_import:
            # The PSP PRX loader of ghidra-allegrex is picked by its file format
            cmd += ["-import", shutil.copy(os.path.join(ROOT, "orig", args.version, prx), tmp)]
        else:
            cmd += ["-process", prx, "-noanalysis"]
        cmd += ["-scriptPath", tmp, "-postScript", "SyncSymbols.java", *symbols]
        if args.dry_run:
            cmd.append("dry")
        env = dict(os.environ, JAVA_HOME=args.jdk)
        out = subprocess.run(cmd, capture_output=True, text=True, env=env)
    lines = [line.strip() for line in (out.stdout + out.stderr).splitlines()]
    for line in lines:
        if "SyncSymbols" in line or line.startswith(("ERROR", "INFO  REPORT", "INFO  IMPORTING")):
            print(line)
    # Ghidra log lines start with their level; symbol names may contain "ERROR".
    errors = [line for line in lines if line.startswith("ERROR")]
    return 0 if out.returncode == 0 and not errors else 1


if __name__ == "__main__":
    sys.exit(main())
