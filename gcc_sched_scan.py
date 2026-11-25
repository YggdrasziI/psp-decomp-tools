#!/usr/bin/env python3
"""Find the instruction latencies of a retail GCC: build one compiler per variant of
the scheduling description and score each on a library (library_sweep.py).

A rebuilt GCC that gives the right instructions in another order, or with two
registers exchanged, may only lack the original's scheduling description: the first
scheduling pass also decides the life lengths the local register allocator ranks.
A description change rebuilds `cc1plus` in seconds, so every value can be tried on
every file of a library whose sources are known. Keep a value when it adds identical
functions and loses none; scan one instruction type at a time, then again around the
best result (gains add up, and a type can do nothing alone).

Each variant is `<tag>:<spec>;<spec>...`, appended to the base description as
`define_insn_reservation`s for the cpu:

    <types>[/<mode>]=<latency>[:<reservation>]     fmul,fmadd/SF=4   xfer=3   fdiv/SF=20:alu

(`type` attribute values of the machine description; reservation `alu` by default.)
A type the base description already reserves cannot be changed this way: give
another base file. An empty spec (`v0:`) builds the base itself, the control.

The variants are built `--parallel` at a time by gcc_sched_build.sh (through
tools/common/linux_run.py on Windows) and installed as `<installed compiler>-<tag>`;
each is then scored on `<dir>` and compared with `--base-run`, the identical.txt of
the reference compiler (library_sweep.py). Results in `<out>/<tag>/`.

usage: gcc_sched_scan.py --work <built GCC work tree> --md <description path in it>
                         --base-md <description file to extend> --installed <compiler folder>
                         --dir <library dir> --range <lo> <hi> --out <folder>
                         [--base-run <identical.txt>] [--cpu allegrex] [--parallel 6]
                         [--cc-path bin/psp-gcc] <tag>:<specs>...
(--work, --installed: Linux paths, `~/` allowed)
"""

import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import project

TOOLS = Path(__file__).resolve().parent


def description(base: str, specs: str, cpu: str) -> str:
    """The base description plus one reservation per spec."""
    out = [base.rstrip("\n")]
    for i, spec in enumerate(s for s in specs.split(";") if s):
        types, _, value = spec.partition("=")
        latency, _, reservation = value.partition(":")
        if not latency.isdigit():
            sys.exit(f"gcc_sched_scan.py: {spec}: expected <types>[/<mode>]=<latency>[:<reservation>]")
        types, _, mode = types.partition("/")
        cond = f'(eq_attr "type" "{types}")'
        if mode:
            cond = f'(and {cond} (eq_attr "mode" "{mode}"))'
        out.append(f'(define_insn_reservation "scan_{i}" {latency}\n'
                   f'  (and (eq_attr "cpu" "{cpu}") {cond})\n  "{reservation or "alu"}")')
    return "\n".join(out) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--work", required=True)
    parser.add_argument("--md", required=True)
    parser.add_argument("--base-md", type=Path, required=True)
    parser.add_argument("--installed", required=True)
    parser.add_argument("--dir", required=True)
    parser.add_argument("--range", nargs=2, required=True, metavar=("LO", "HI"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--base-run", type=Path)
    parser.add_argument("--cpu", default="allegrex")
    parser.add_argument("--parallel", type=int, default=6)
    parser.add_argument("--cc-path", default="bin/psp-gcc", help="compiler inside the install folder")
    parser.add_argument("variants", nargs="+", metavar="tag:specs")
    args = parser.parse_args()

    out = args.out.resolve()
    base = args.base_md.read_text(encoding="utf-8")
    variants = [v.partition(":")[::2] for v in args.variants]
    for tag, specs in variants:
        (out / tag).mkdir(parents=True, exist_ok=True)
        (out / tag / "sched.md").write_text(description(base, specs, args.cpu), encoding="utf-8", newline="\n")
    installed = args.installed.rstrip("/")

    def build(job: tuple[int, tuple[str, str]]) -> tuple[str, str]:
        slot, (tag, _specs) = job
        r = subprocess.run([*project.linux_command("bash"), str(TOOLS / "gcc_sched_build.sh"), args.work, args.md,
                            installed, f"{installed}-{tag}", str(out / tag / "sched.md"), str(slot)],
                           capture_output=True, text=True)
        return tag, "" if "BUILD_OK" in r.stdout else ((r.stdout + r.stderr).strip() or "build failed")

    for start in range(0, len(variants), args.parallel):
        batch = variants[start:start + args.parallel]
        with ThreadPoolExecutor(args.parallel) as pool:
            failed = dict(pool.map(build, enumerate(batch, 1)))
        for tag, specs in batch:
            if failed[tag]:
                print(f"{tag:8} {specs:44} BUILD FAILED: {failed[tag].splitlines()[-1][:120]}", flush=True)
                continue
            command = [sys.executable, str(TOOLS / "library_sweep.py"), args.dir, *args.range,
                       "--out", str(out / tag), "--cc", f"{installed}-{tag}/{args.cc_path}"]
            if args.base_run:
                command += ["--base", str(args.base_run)]
            r = subprocess.run(command, cwd=project.ROOT, capture_output=True, text=True)
            print(f"{tag:8} {specs:44} {(r.stdout.strip().splitlines() or [r.stderr.strip()[-120:]])[0]}", flush=True)


if __name__ == "__main__":
    main()
