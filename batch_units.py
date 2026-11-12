#!/usr/bin/env python3
"""Decompile small functions in batches and turn the matching ones into units.

For every assembly function of the module in the configured address ranges (no VFPU
or FPU, no jump table, size and call count within limits), C sources are tried:

  - the m2c draft (`--valid-syntax`), field accesses written `*(type *)(p + off)`,
    with variants: indexed accesses as arrays, unsigned stores, `int` arguments
    used as pointers, C++ instead of C, explicit casts where the compiler asks;
  - when m2c calls a function without arguments because the caller passes its own
    incoming registers, the caller's first arguments, as many as the callee reads
    (argument registers $a0-$a3, $t0-$t3 read before written, straight-line scan
    with delay slots, following tail jumps);
  - for straight-line functions that end in a tail jump (`j f` + delay slot), a
    source written from the assembly (m2c misses the delay-slot arguments).

Each source is compiled with the [compiler] of decomp.toml and compared with the
original: same length, same instructions, relocated fields masked but checked when
the symbol carries its address (`func_XXXXXXXX`, `D_XXXXXXXX`: jump target, low and
high halves with their addends). Sources that still call a function without a
prototype are rejected (the call would not show the arguments really passed).
Contiguous matching functions are grouped into units; each unit file is compiled
again as a whole and checked (functions of one file can be inlined into each other),
after a mechanical clean-up.

The bounds of such units are no more than "contiguous functions that match", the
code is m2c-level, and the argument count of a pass-through call is a reading aid
(the code is the same whatever the count). The full build (`ninja`, SHA-1 check) is
the real proof.

Usage (from the project, after `python tools/configure.py`):
  python tools/psp/batch_units.py                        # dry run: what would match
  python tools/psp/batch_units.py --write                # src/, splat yaml, table rows
  python tools/psp/batch_units.py --max-size 0x100 --max-calls 3
  python tools/psp/batch_units.py --show func_0884FF24   # sources tried, with results

decomp.toml ([compiler] as in project.py):

    [batch]
    splits = "notes/SPLITS.md"      # optional: table of units to add rows to
    [batch.ranges]                  # address ranges to scan, per version
    ULES01213 = [[0x08811C00, 0x08904000]]

Needs m2c (tools/requirements.txt) and, for the argument counts of callees already
in C, the built ELF of the module (build/<version>/<module>.elf).
"""

import argparse
import itertools
import os
import re
import struct
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

import project
from prx import Prx
from unit_candidates import read_functions

TYPES = {"s8": "signed char", "u8": "unsigned char", "s16": "short", "u16": "unsigned short",
         "s32": "int", "u32": "unsigned int", "f32": "float", "s64": "long long",
         "u64": "unsigned long long", "f64": "double"}
SIZES = {"s8": 1, "u8": 1, "s16": 2, "u16": 2, "s32": 4, "u32": 4, "f32": 4, "char": 1, "char*": 4}
# left to hand work: FPU, jumps through registers
SKIP_OPS = re.compile(r"^(lwc1|swc1|mtc1|mfc1|c\.|bc1|cvt|add\.s|sub\.s|mul\.s|div\.s|mov\.s|neg\.s|"
                      r"abs\.s|sqrt\.s|trunc|floor|ceil|round|jalr|\.word)")
# a function declared without a prototype: `int f();`
KR_DECL = re.compile(r"^(?:extern )?\w[\w ]*?\**\s*(\w+)\(\);$", re.M)
# argument registers, EABI: $a0-$a3 then $t0-$t3
AREGS = ["$a0", "$a1", "$a2", "$a3", "$t0", "$t1", "$t2", "$t3"]
NO_DEST = {"mult", "multu", "div", "divu", "madd", "maddu", "msub", "msubu", "mthi", "mtlo"}
ADDR_SYM = re.compile(r"_([0-9A-F]{8})$")


# ---------------------------------------------------------------- configuration

class Config:
    def __init__(self, version: str, module: str):
        self.version, self.module = version, module
        self.cc, flags = project.compiler()
        self.flags = flags + ["-I" + str(project.ROOT / "include"), "-I" + str(project.ROOT / "src")]
        batch = project.CONFIG.get("batch", {})
        self.ranges = [tuple(r) for r in batch.get("ranges", {}).get(version, [])]
        self.splits = batch.get("splits")
        self.objdump = str(project.binutil("objdump"))
        prx = Prx(project.module_file(version, module))
        self.data = prx.data
        self.off = prx.segments[0].offset - prx.segments[0].vaddr
        self.yaml = project.config_dir(version) / project.MODULES[module].splat

    def word(self, addr: int) -> int:
        return struct.unpack_from("<I", self.data, self.off + addr)[0]


def eligible(f: dict, cfg: Config, args) -> bool:
    if not f["name"].startswith("func_") or not any(lo <= f["addr"] < hi for lo, hi in cfg.ranges):
        return False
    if not (args.min_size <= f["size"] <= args.max_size) or len(f["calls"]) > args.max_calls:
        return False
    return not f["vfpu"] and not any(SKIP_OPS.match(op) or (op == "jr" and ops != ["$ra"])
                                     for op, ops in f["ins"])


def m2c_draft(f: dict) -> str:
    src = ".set noat\n.set noreorder\n.section .text\n" + "\n".join(
        re.sub(r"/\* [0-9A-F ]+\*/", "", l) for l in f["lines"] if not l.startswith("nonmatching")) + "\n"
    with tempfile.TemporaryDirectory() as t:
        p = Path(t) / "f.s"
        p.write_text(src, encoding="utf-8")
        r = subprocess.run([sys.executable, "-m", "m2c.main", "--target", "mips", "--valid-syntax", str(p)],
                           capture_output=True, text=True)
    return r.stdout


# ---------------------------------------------------------------- m2c draft -> C

def strip_parens(s: str) -> str:
    s = s.strip()
    while s.startswith("(") and s.endswith(")"):
        depth = 0
        for i, c in enumerate(s):
            depth += {"(": 1, ")": -1}.get(c, 0)
            if depth == 0 and i < len(s) - 1:
                return s
        s = s[1:-1].strip()
    return s


def split_top(s: str, op: str) -> list[str]:
    parts, depth, cur, i = [], 0, "", 0
    while i < len(s):
        c = s[i]
        depth += {"(": 1, ")": -1}.get(c, 0)
        if depth == 0 and s.startswith(op, i):
            parts.append(cur)
            cur = ""
            i += len(op)
            continue
        cur += c
        i += 1
    parts.append(cur)
    return [p.strip() for p in parts]


def index_form(e: str):
    """'((X) * K) + B' -> (X, K, B)"""
    p = split_top(strip_parens(e), " + ")
    if len(p) != 2:
        return None
    num = re.compile(r"0x[0-9A-F]+|\d+")
    for a, b in (p, p[::-1]):
        m = split_top(strip_parens(a), " * ")
        if len(m) == 2 and num.fullmatch(m[1]) and not num.fullmatch(b) and int(m[1], 0) > 1:
            return strip_parens(m[0]), int(m[1], 0), strip_parens(b)
    return None


def field(e: str, t: str, off: str, array: bool) -> str:
    """M2C_FIELD(e, t, off) as C: *(t)(e + off), or an array access."""
    e = e.strip()
    idx = index_form(e) if array else None
    if idx:
        x, k, b = idx
        b = b if re.fullmatch(r"\w+", b) else f"({b})"
        base = b if off in ("0", "0x0") else f"{b} + {off}"
        if SIZES.get(t.replace(" ", "").removesuffix("*")) == k:  # t is a pointer to the element
            return f"(({t})({base}))[{x}]"
        return f"*({t})((E{k} *)({base}))[{x}].b"
    if re.fullmatch(r"\w+", e):
        return f"*({t})({e} + {off})"
    return f"*({t})((char *)({e}) + {off})"


def expand_fields(code: str, array: bool) -> str:
    out, i = "", 0
    while (j := code.find("M2C_FIELD(", i)) >= 0:
        out += code[i:j]
        k = j + len("M2C_FIELD(")
        depth, parts, cur = 1, [], ""
        while True:
            c = code[k]
            depth += {"(": 1, ")": -1}.get(c, 0)
            if depth == 0:
                break
            if c == "," and depth == 1:
                parts.append(cur)
                cur = ""
            else:
                cur += c
            k += 1
        parts.append(cur)
        f = field(expand_fields(parts[0], array), parts[1].strip().replace("void *", "char *"),
                  parts[2].strip(), array)
        rest = code[k + 1:].lstrip(" ")
        out += f if not re.match(r"(\[|\.|->|\+\+|--|\()", rest) else f"({f})"
        i = k + 1
    return out + code[i:]


def declaration(l: str) -> str:
    """m2c declaration -> C: unknown types become int / s32 / char."""
    if m := re.match(r"^M2C_UNK (\w+)\((.*)\);$", l):
        params = m.group(2).strip()
        if params:  # prototype inferred by m2c: keep the arguments
            params = ", ".join("s32" if p.strip() == "M2C_UNK" else p.strip() for p in params.split(","))
        return f"extern int {m.group(1)}({params});"
    if re.match(r"^\w[\w ]*?\**\s*\w+\(.*\);$", l) and not l.startswith("extern "):
        l = "extern " + l
    return l.replace("extern M2C_UNK", "extern char")


def convert(name: str, text: str, array: bool):
    """m2c output -> (declarations, body), or None."""
    if not text.strip() or "M2C_ERROR" in text:
        return None
    text = re.sub(r"\s*/\* extern \*/", "", text)
    text = expand_fields(text, array).replace("void *", "char *")
    text = re.sub(r"\bNULL\b", "0", text)
    decls, body = [], []
    for l in text.strip("\n").splitlines():
        if not body and l.rstrip().endswith(";") and not l.startswith(" "):
            decls.append(declaration(re.sub(r"\s+", " ", l.strip()).replace("( ", "(")))
        elif l.strip() or body:
            body.append(l)
    body = "\n".join(body)
    # other unknown types (locals, arguments, partial prototypes): int, or char *
    decls = [re.sub(r"\bM2C_UNK\b", "s32", d.replace("M2C_UNK *", "char *")) for d in decls]
    body = re.sub(r"\bM2C_UNK\b", "s32", body.replace("M2C_UNK *", "char *"))
    # m2c leaves out unused arguments below the last used one
    m = re.search(r"^(.*?\b" + name + r")\((.*)\) \{$", body, re.M)
    if m and m.group(2) not in ("", "void"):
        ps = [p.strip() for p in m.group(2).split(",")]
        idx = {int(n.group(1)): p for p in ps if (n := re.search(r"arg(\d+)$", p))}
        if len(idx) == len(ps):
            full = [idx.get(i, f"s32 arg{i}") for i in range(max(idx) + 1)]
            body = body.replace(m.group(0), f"{m.group(1)}({', '.join(full)}) {{", 1)
    if "M2C_" in body or "M2C_" in "".join(decls):
        return None
    return decls, body


# ---------------------------------------------------------------- compile and compare

def typedefs(src: str) -> list[str]:
    tds = [f"typedef {v} {k};" for k, v in TYPES.items() if re.search(r"\b" + k + r"\b", src)]
    strides = sorted({int(x) for x in re.findall(r"\bE(\d+)\b", src)})
    return tds + [f"typedef struct {{ char b[{k}]; }} E{k};" for k in strides]


def assemble_source(decls: list[str], body: str, lang: str) -> str:
    code = ("\n".join(decls) + "\n\n" if decls else "") + body + "\n"
    tds = typedefs(code)
    head = "\n".join(tds) + "\n\n" if tds else ""
    if lang == "cpp":
        return head + 'extern "C" {\n\n' + code + "\n}\n"
    return head + code


def disassemble(cfg: Config, obj: str) -> dict:
    """{name: [[word, mask, reloc type, symbol], ...]}"""
    dump = subprocess.run([cfg.objdump, "-dr", obj], capture_output=True, text=True).stdout
    funcs, cur = {}, None
    for line in dump.splitlines():
        if m := re.match(r"^[0-9a-f]+ <(.*)>:", line):
            cur = funcs.setdefault(m.group(1), [])
        elif cur is None:
            continue
        elif m := re.match(r"^\s+[0-9a-f]+:\s+([0-9a-f]{8})\s", line):
            cur.append([int(m.group(1), 16), 0xFFFFFFFF, None, None])
        elif (m := re.match(r"^\s+[0-9a-f]+: (R_MIPS_\w+)\s+(\S+)", line)) and cur:
            cur[-1][1] = 0xFC000000 if m.group(1) == "R_MIPS_26" else 0xFFFF0000
            cur[-1][2:] = [m.group(1), m.group(2)]
    return funcs


def compile_source(cfg: Config, src: str, lang: str, fix_casts: bool = True):
    """-> (object functions or None, final source, error text)"""
    msg = ""
    with tempfile.TemporaryDirectory() as t:
        p, o = os.path.join(t, "u." + lang), os.path.join(t, "u.o")
        for _ in range(6):
            Path(p).write_text(src, encoding="utf-8")
            r = subprocess.run([*cfg.cc, "-c", *cfg.flags, "-o", o, p], capture_output=True, text=True,
                               cwd=t, env={**os.environ, "MWCIncludes": "."})
            if not r.returncode:
                return disassemble(cfg, o), src, ""
            msg = r.stdout + r.stderr
            # "illegal implicit conversion from 'int' to 'char *'": add the cast
            m = re.search(r"#\s+(\d+):.*?illegal implicit conversion from '[^']*' to\s*#\s*'([^']*)'",
                          msg, re.S)
            if not (fix_casts and m):
                break
            lines = src.split("\n")
            ln, to = int(m.group(1)) - 1, m.group(2)
            g = re.match(r"^(\s*)(return )(.+);$", lines[ln]) or re.match(r"^(\s*)(.+? = )(.+);$", lines[ln])
            if not g:
                break
            lines[ln] = f"{g.group(1)}{g.group(2)}({to}) ({g.group(3)});"
            src = "\n".join(lines)
    return None, src, msg


def s16(x: int) -> int:
    return x - 0x10000 if x & 0x8000 else x


def reloc_ok(cfg: Config, insns: list, addr: int, i: int) -> bool:
    """A relocated field against a symbol that carries its address: same target."""
    word, _, rtype, sym = insns[i]
    m = ADDR_SYM.search(sym or "")
    if not m:
        return True
    s, orig = int(m.group(1), 16), cfg.word(addr + 4 * i)
    if rtype == "R_MIPS_26":
        return (s + ((word & 0x3FFFFFF) << 2)) & 0x0FFFFFFF == ((orig & 0x3FFFFFF) << 2)
    if rtype == "R_MIPS_LO16":
        return (s + s16(word & 0xFFFF)) & 0xFFFF == orig & 0xFFFF
    if rtype == "R_MIPS_HI16":
        lo = next((w for w, _, t, y in insns[i + 1:] if t == "R_MIPS_LO16" and y == sym), None)
        if lo is None:
            return True
        full = s + ((word & 0xFFFF) << 16) + s16(lo & 0xFFFF)
        return ((full + 0x8000) >> 16) & 0xFFFF == orig & 0xFFFF
    return True


def compare(cfg: Config, funcs: dict, name: str, size: int) -> str:
    f = funcs.get(name)
    if f is None:
        return "missing"
    if len(f) != size // 4:
        return f"length {4 * len(f):#x}"
    addr = int(name[5:], 16)
    bad = [i for i, (w, m, _, _) in enumerate(f) if (cfg.word(addr + 4 * i) ^ w) & m]
    bad += [i for i in range(len(f)) if f[i][2] and not reloc_ok(cfg, f, addr, i)]
    return "OK" if not bad else "differs at " + ",".join(map(str, sorted(set(bad))))


def try_source(cfg: Config, name: str, size: int, decls: list[str], body: str, lang: str):
    funcs, src, err = compile_source(cfg, assemble_source(decls, body, lang), lang)
    if funcs is None:
        return "error", src, err
    return compare(cfg, funcs, name, size), src, ""


# ---------------------------------------------------------------- argument counts

def regs_of(ops: list[str]) -> list[str]:
    return re.findall(r"\$\w+", " ".join(ops))


class Callees:
    """Argument count of a function: argument registers read before written."""

    def __init__(self, cfg: Config, asm_funcs: list[dict]):
        self.ins = {f["name"]: f["ins"] for f in asm_funcs}
        self.extern = {}  # argument counts of imports, set by the caller
        elf = project.build_dir(cfg.version) / f"{cfg.module}.elf"
        if not elf.exists():
            return
        dump = subprocess.run([cfg.objdump, "-d", "--no-show-raw-insn", "-M", "no-aliases", str(elf)],
                              capture_output=True, text=True).stdout
        cur = None
        for line in dump.splitlines():
            if m := re.match(r"^[0-9a-f]+ <(.*)>:", line):
                cur = None if m.group(1) in self.ins else self.ins.setdefault(m.group(1), [])
            elif cur is not None and (m := re.match(r"^\s+[0-9a-f]+:\s+(\S+)\s*(.*)$", line)):
                # objdump writes registers without '$' and jump targets as '<func_X>'
                text = re.sub(r"\b(zero|at|v[01]|a[0-3]|t[0-9]|s[0-8]|k[01]|gp|sp|fp|ra)\b", r"$\1",
                              m.group(2))
                ops = [x.strip() for x in text.split(",")] if text else []
                if t := re.search(r"<(\w+)>", m.group(2)):
                    ops = [t.group(1)]
                cur.append((m.group(1), ops))

    def count(self, name: str, depth: int = 0):
        ins = self.ins.get(name)
        if not ins or depth > 3 or self.variadic(ins):
            return None
        written, read = set(), set()

        def step(op, ops):
            if not ops:
                return
            if op.startswith("b") or op in ("sb", "sh", "sw", "jr") or op in NO_DEST:
                srcs, dst = ops, []
            else:
                srcs, dst = ops[1:], ops[:1]
            read.update(r for r in regs_of(srcs) if r in AREGS and r not in written)
            written.update(regs_of(dst))

        for k, (op, ops) in enumerate(ins):
            if op in ("jal", "j", "jr"):
                if k + 1 < len(ins):
                    step(*ins[k + 1])  # the delay slot runs first
                if op == "jr":
                    step(op, ops)
                else:
                    n = self.count(ops[0], depth + 1) if ops and ops[0].startswith("func_") else None
                    if n is None:
                        return None  # what the next callee reads is not known
                    read.update(r for r in AREGS[:n] if r not in written)
                break
            step(op, ops)
        return max([AREGS.index(r) + 1 for r in read] + [0])

    def reads(self, name: str, depth: int = 0):
        """Argument registers read anywhere before written (in code order): a lower
        bound of the argument count of a function, None for a variadic one.

        Unlike count(), the scan goes on past calls, so arguments read on a path
        that skips the first call are seen; a tail jump (`j func_X`) adds what that
        function reads, when known.
        """
        ins = self.ins.get(name)
        if not ins or depth > 3 or self.variadic(ins):
            return None
        written, read = set(), set()

        def step(op, ops):
            if not ops or op in ("jal", "jr", "j"):
                return
            if op.startswith("b") or op in ("sb", "sh", "sw") or op in NO_DEST:
                srcs, dst = ops, []
            else:
                srcs, dst = ops[1:], ops[:1]
            read.update(r for r in regs_of(srcs) if r in AREGS and r not in written)
            written.update(regs_of(dst))

        for k, (op, ops) in enumerate(ins):
            if op == "j" and ops and not ops[0].startswith("."):
                if k + 1 < len(ins):
                    step(*ins[k + 1])  # the delay slot runs before the jump
                n = (self.reads(ops[0], depth + 1) if ops[0].startswith("func_")
                     else self.extern.get(ops[0])) or 0
                read.update(r for r in AREGS[:n] if r not in written)
                continue
            step(op, ops)
        return max([AREGS.index(r) + 1 for r in read] + [0])

    @staticmethod
    def variadic(ins) -> bool:
        """A variadic function stores the unnamed argument registers, up to $t3, on
        the stack: its fixed argument count cannot be read from the code."""
        return any(op == "sw" and len(ops) == 2 and ops[0] == "$t3" and "($sp)" in ops[1]
                   for op, ops in ins[:24])


def pass_arguments(src: str, name: str, callees: Callees):
    """Give K&R calls `f()` the caller's first arguments, as many as f reads."""
    m = re.search(r"^(\w[\w ]*?\**)\s*(" + name + r")\(([^)]*)\) \{$", src, re.M)
    if not m:
        return None
    params = [] if m.group(3).strip() in ("", "void") else [p.strip() for p in m.group(3).split(",")]
    pnames = [re.search(r"(\w+)$", p).group(1) for p in params]
    after = src[m.start():]
    for f in KR_DECL.findall(src):
        if re.search(r"\b" + f + r"\((?!\))", after):
            return None  # called with arguments too
        n = callees.count(f) if f.startswith("func_") else None
        if n is None:
            return None
        while len(params) < n:
            params.append(f"s32 arg{len(params)}")
            pnames.append(f"arg{len(pnames)}")
        if pnames[:n] != [f"arg{i}" for i in range(n)]:
            return None
        types = ", ".join(params[i][:-len(pnames[i])].strip() for i in range(n)) or "void"
        used = re.search(r"([=(,!]|return)\s*" + f + r"\(\)", after)
        src = re.sub(r"^(?:extern )?\w[\w ]*?\**\s*" + f + r"\(\);$",
                     f"extern {'int' if used else 'void'} {f}({types});", src, flags=re.M)
        src = re.sub(r"\b" + f + r"\(\)", f"{f}({', '.join(pnames[:n])})", src)
    head = f"{m.group(1)} {name}({', '.join(params) or 'void'}) {{".replace("* ", "*")
    src = src.replace(m.group(0), head, 1)
    missing = [t for t in typedefs(src) if t not in src]
    return "\n".join(missing) + "\n" + src if missing else src


# ---------------------------------------------------------------- tail calls

LOADS = {"lb": "s8", "lbu": "u8", "lh": "s16", "lhu": "u16", "lw": "s32"}
STORES = {"sb": "s8", "sh": "s16", "sw": "s32"}


def tail_sources(f: dict, callees: Callees):
    """C sources for a straight-line function ending in `j target`, or []."""
    ins = f["ins"]
    if f["label"] or len(ins) < 2 or ins[-2][0] != "j":
        return []
    target = ins[-2][1][0]
    if not re.fullmatch(r"func_[0-9A-F]{8}|sce\w+", target):
        return []
    regs = {r: ("arg", i) for i, r in enumerate(AREGS)}
    regs["$zero"] = ("imm", 0)
    used, ptr, stmts, globs = set(), set(), [], {}

    def hexs(n):
        return f"{n:#x}" if n > 9 else str(n) if n >= 0 else f"-{-n:#x}"

    def ex(r, as_ptr=False):
        v = regs[r]
        if v[0] in ("arg", "argoff"):
            used.add(v[1])
            if as_ptr or v[0] == "argoff":
                ptr.add(v[1])
            if v[0] == "arg":
                return f"arg{v[1]}"
            return f"arg{v[1]} + {v[2]:#x}" if v[2] >= 0 else f"arg{v[1]} - {-v[2]:#x}"
        if v[0] == "imm":
            return hexs(v[1])
        if v[0] == "expr":
            return v[1]
        raise ValueError(v)

    def mem(opnd):
        m = re.match(r"^(-?0x[0-9A-F]+|-?\d+|%lo\((\w+)\))\((\$\w+)\)$", opnd)
        if not m:
            raise ValueError(opnd)
        if m.group(2):
            if regs.get(m.group(3)) != ("hi", m.group(2)):
                raise ValueError(opnd)
            return ("sym", m.group(2))
        off, v = int(m.group(1), 0), regs.get(m.group(3))
        if v and v[0] == "argoff":
            used.add(v[1])
            ptr.add(v[1])
            return ("ptr", f"arg{v[1]}", off + v[2])
        if v and v[0] == "arr":
            return ("arr", v[1], v[2], v[3], off)
        return ("ptr", ex(m.group(3), True), off)

    def lval(mm, t):
        if mm[0] == "sym":
            globs[mm[1]] = t
            return mm[1]
        if mm[0] == "arr":
            _, b, x, k, off = mm
            b = b if re.fullmatch(r"\w+", b) else f"({b})"
            base = f"{b} + {off:#x}" if off else b
            if SIZES[t] == k:
                return f"(({t} *)({base}))[{x}]"
            return f"*({t} *)((E{k} *)({base}))[{x}].b"
        base, off = mm[1], mm[2]
        base = base if re.fullmatch(r"\w+", base) else f"({base})"
        return f"*({t} *)({base} + {off:#x})" if off else f"*({t} *){base}"

    def argoff(v, n):
        return ("argoff", v[1], (v[2] if v[0] == "argoff" else 0) + n)

    try:
        for op, o in ins[:-2] + [ins[-1]]:  # the delay slot runs before the jump
            kind = lambda r: regs.get(r, ("",))[0]  # noqa: E731
            if op == "addiu" and o[1] == "$zero":
                regs[o[0]] = ("imm", int(o[2], 0))
            elif op == "ori" and o[1] == "$zero" and not o[2].startswith("("):
                regs[o[0]] = ("imm", int(o[2], 0))
            elif op == "addu" and "$zero" in (o[1], o[2]):
                regs[o[0]] = regs[o[2] if o[1] == "$zero" else o[1]]
            elif op == "addiu" and o[2].startswith("%lo("):
                s = re.match(r"%lo\((\w+)\)", o[2]).group(1)
                if regs.get(o[1]) != ("hi", s):
                    return []
                globs.setdefault(s, "char")
                regs[o[0]] = ("expr", f"&{s}")
            elif op == "addiu" and kind(o[1]) == "imm":
                regs[o[0]] = ("imm", regs[o[1]][1] + int(o[2], 0))
            elif op == "addiu" and kind(o[1]) in ("arg", "argoff"):
                regs[o[0]] = argoff(regs[o[1]], int(o[2], 0))
            elif op == "lui" and o[1].startswith("%hi("):
                regs[o[0]] = ("hi", re.match(r"%hi\((\w+)\)", o[1]).group(1))
            elif op == "lui" and (m := re.match(r"\((0x[0-9A-F]+) >> 16\)", o[1])):
                regs[o[0]] = ("imm", int(m.group(1), 16) & 0xFFFF0000)
            elif op == "ori" and (m := re.match(r"\((0x[0-9A-F]+) & 0xFFFF\)", o[2])) and kind(o[1]) == "imm":
                regs[o[0]] = ("imm", regs[o[1]][1] | (int(m.group(1), 16) & 0xFFFF))
            elif op == "sll" and o[1] in regs:
                regs[o[0]] = ("idx", ex(o[1]), 1 << int(o[2], 0))
            elif op == "addu":
                a, b = regs[o[1]], regs[o[2]]
                if "idx" in (a[0], b[0]):
                    i_, base = (a, o[2]) if a[0] == "idx" else (b, o[1])
                    regs[o[0]] = ("arr", ex(base, True), i_[1], i_[2])
                elif b[0] == "imm" and a[0] in ("arg", "argoff"):
                    regs[o[0]] = argoff(a, b[1])
                elif a[0] == "imm" and b[0] in ("arg", "argoff"):
                    regs[o[0]] = argoff(b, a[1])
                else:
                    regs[o[0]] = ("expr", f"{ex(o[1])} + {ex(o[2])}")
            elif op in LOADS:
                regs[o[0]] = ("expr", lval(mem(o[1]), LOADS[op]))
            elif op in STORES:
                stmts.append(f"{lval(mem(o[1]), STORES[op])} = {ex(o[0])};")
            else:
                return []
        n_set = max([i + 1 for i, r in enumerate(AREGS) if regs[r] != ("arg", i)] + [0])
        if target.startswith("func_"):
            n_callee = callees.count(target)
            if n_callee is None:
                return []  # the arguments passed through are not known
            n = max(n_set, n_callee)
        else:
            n = n_set  # imports: the registers set here (a pass-through one would be missed)
        cargs = [ex(r) for r in AREGS[:n]]
    except (ValueError, KeyError):
        return []
    nparams = max(used) + 1 if used else 0
    params = ", ".join(("char *" if i in ptr else "s32 ") + f"arg{i}" for i in range(nparams)) or "void"
    ptypes = ["char *" if ((m := re.match(r"^arg(\d+)", a)) and int(m.group(1)) in ptr) or a.startswith("&")
              else "s32" for a in cargs]
    decls = [f"extern void {target}({', '.join(ptypes) or 'void'});"]
    decls += [f"extern {t} {s};" for s, t in sorted(globs.items())]
    out = []
    orders = itertools.permutations(stmts) if len(stmts) <= 3 else [tuple(stmts)]
    for order in orders:
        body = f"void {f['name']}({params}) {{\n" + "".join(f"    {s}\n" for s in order)
        body += f"    {target}({', '.join(cargs)});\n}}"
        out.append((decls, body))
    return out


# ---------------------------------------------------------------- one function

def candidates(f: dict, callees: Callees):
    """Yield (declarations, body, lang) to try, best guesses first."""
    for decls, body in tail_sources(f, callees):
        yield decls, body, "c"
    text = m2c_draft(f)
    plain, arr = convert(f["name"], text, False), convert(f["name"], text, True)
    if plain is None:
        return
    decls = plain[0]
    bodies = [plain[1]] + ([arr[1]] if arr and arr[1] != plain[1] else [])
    bodies += [b.replace("(s16 *)", "(u16 *)").replace("(s8 *)", "(u8 *)") for b in bodies
               if "(s16 *)" in b or "(s8 *)" in b]
    m = re.search(r"^.*\b" + f["name"] + r"\(([^)]*)\) \{$", bodies[0], re.M)
    if m and "s32 arg" in m.group(1):
        bodies.append(bodies[0].replace(m.group(0), re.sub(r"s32 (arg\d)", r"char *\1", m.group(0))))
    kr = KR_DECL.search("\n".join(decls + bodies))
    for lang in ("c", "cpp"):
        if lang == "cpp" and kr:  # C++ reads `f()` as taking no arguments
            break
        for b in bodies:
            yield decls, b, lang


def solve(f: dict, cfg: Config, callees: Callees, verbose: bool = False):
    """-> (state, source, lang) of the first matching source, else the first try."""
    first = None
    for decls, body, lang in candidates(f, callees):
        state, src, err = try_source(cfg, f["name"], f["size"], decls, body, lang)
        if state == "OK" and KR_DECL.search(src):
            fixed = pass_arguments(src, f["name"], callees)
            if fixed is None:
                state = "unknown arguments"
            else:
                funcs, src2, err = compile_source(cfg, fixed, lang)
                state = compare(cfg, funcs, f["name"], f["size"]) if funcs else "error"
                if state == "OK":
                    src = src2
        if verbose:
            print(f"--- {lang}: {state}\n{src}{err[-400:]}")
        if state == "OK":
            return state, src, lang
        first = first or (state, src, lang)
    return first or ("no draft", "", "c")


# ---------------------------------------------------------------- units

def split_source(src: str, lang: str):
    """-> (typedef lines, declaration lines, body)"""
    if lang == "cpp":
        src = src.replace('extern "C" {\n\n', "").rstrip()
        src = src[:-1].rstrip() + "\n"
    lines = src.split("\n")
    tds = [l for l in lines if l.startswith("typedef ")]
    rest = [l for l in lines if not l.startswith("typedef ")]
    decls = []
    while rest and (rest[0].startswith("extern ") or not rest[0].strip()):
        if rest[0].strip():
            decls.append(rest[0])
        rest.pop(0)
    return tds, decls, "\n".join(rest).strip("\n")


def symbol(decl: str) -> str:
    return re.search(r"(\w+)\s*(\(|\[|;)", decl).group(1)


def tidy(src: str) -> str:
    # (char *)(*(char **)(X)) -> (*(char **)(X))
    while (i := src.find("(char *)(*(char **)(")) >= 0:
        j, depth = i + len("(char *)(*(char **)("), 1
        while depth:
            depth += {"(": 1, ")": -1}.get(src[j], 0)
            j += 1
        if src[j] != ")":
            break
        src = src[:i] + "(" + src[i + len("(char *)("):j] + ")" + src[j + 1:]
    src = re.sub(r"\((\w+) \+ 0\)", r"\1", src)
    return re.sub(r"\{\n\n\}", "{\n}", src)


def render(cfg: Config, unit: dict) -> str:
    name = f"unit_{unit['start']:08X}"
    n = len(unit["funcs"])
    text = (f"/* {name}: 0x{unit['start']:08X}-0x{unit['end']:08X} ({cfg.version})\n *\n"
            f" * Bounds (hypothesis): {n} small function{'s' if n > 1 else ''} between code still in"
            f" assembly.\n")
    if unit["lang"] == "cpp":
        text += " *\n * C++: the code only matches when compiled as C++.\n"
    text += " */\n\n"
    order = list(TYPES)
    tds = sorted(unit["tds"], key=lambda t: (order.index(t.split()[-1].rstrip(";"))
                                             if t.split()[-1].rstrip(";") in order else 99, len(t), t))
    text += "\n".join(tds) + "\n\n" if tds else ""
    if unit["lang"] == "cpp":
        text += 'extern "C" {\n\n'
    decls = sorted(unit["syms"].values(), key=symbol)
    text += "\n".join(decls) + "\n\n" if decls else ""
    text += "\n\n".join(unit["bodies"]) + "\n"
    if unit["lang"] == "cpp":
        text += "\n}\n"
    return tidy(text)


def check_unit(cfg: Config, unit: dict, src: str) -> bool:
    funcs, _, _ = compile_source(cfg, src, unit["lang"], fix_casts=False)
    if funcs is None or {k for k in funcs if k.startswith("func_")} != set(unit["funcs"]):
        return False
    return all(compare(cfg, funcs, n, s) == "OK" for n, s in unit["funcs"].items())


def new_unit(f: dict, src: str, lang: str) -> dict:
    tds, decls, body = split_source(src, lang)
    return {"start": f["addr"], "end": f["addr"] + f["size"], "lang": lang, "funcs": {f["name"]: f["size"]},
            "syms": {symbol(d): d for d in decls}, "tds": set(tds), "bodies": [body]}


def group(cfg: Config, matched: list, seg_starts: set) -> list:
    units = []
    for f, src, lang in matched:
        u = new_unit(f, src, lang)
        last = units[-1] if units else None
        if (last and last["end"] == u["start"] and last["lang"] == lang and u["start"] not in seg_starts
                and all(last["syms"].get(k, v) == v for k, v in u["syms"].items())):
            last["end"] = u["end"]
            last["funcs"].update(u["funcs"])
            last["syms"].update(u["syms"])
            last["tds"] |= u["tds"]
            last["bodies"] += u["bodies"]
        else:
            units.append(u)
    final = []
    for u in units:
        src = render(cfg, u)
        if check_unit(cfg, u, src):
            final.append((u, src))
            continue
        # the whole file does not match: one unit per function
        for f, fsrc, lang in matched:
            if f["name"] in u["funcs"]:
                v = new_unit(f, fsrc, lang)
                vsrc = render(cfg, v)
                if check_unit(cfg, v, vsrc):
                    final.append((v, vsrc))
                else:
                    print(f"{f['name']}: does not match in its own file, left out")
    return final


SEG = re.compile(r"^(\s+- \[)(0x[0-9A-F]+), (\w+), (\w+)\](.*)$")


def segment_base(cfg: Config) -> int:
    """vram - file offset of the code segment holding the subsegments."""
    for seg in yaml.safe_load(cfg.yaml.read_text(encoding="utf-8"))["segments"]:
        if isinstance(seg, dict) and "vram" in seg and seg.get("subsegments"):
            return seg["vram"] - seg["start"]
    sys.exit(f"{cfg.yaml}: no code segment with vram and subsegments")


def new_yaml(cfg: Config, units: list, base: int) -> str:
    lines = cfg.yaml.read_text(encoding="utf-8").split("\n")
    for u, _ in units:
        so, eo = u["start"] - base, u["end"] - base
        idx = max(i for i, l in enumerate(lines) if (m := SEG.match(l)) and int(m.group(2), 16) <= so)
        m = SEG.match(lines[idx])
        if m.group(3) != "asm":
            sys.exit(f"{cfg.yaml}: {lines[idx].strip()} is not an asm piece (rerun tools/configure.py?)")
        line = f"{m.group(1)}0x{so:X}, {u['lang']}, unit_{u['start']:08X}]"
        if int(m.group(2), 16) == so:
            lines[idx] = line + m.group(5)
        else:
            idx += 1
            lines.insert(idx, line)
        nxt = next(SEG.match(l) for l in lines[idx + 1:] if SEG.match(l))
        if int(nxt.group(2), 16) != eo:
            lines.insert(idx + 1, f"{m.group(1)}0x{eo:X}, asm, text_{u['end']:08X}]")
    return "\n".join(lines)


def new_rows(path: Path, units: list):
    """The table text with the rows of the new units, or None if it has no units table:
    | `unit_X` | start-end | content | 100 % |"""
    lines = path.read_text(encoding="utf-8").split("\n")
    row = re.compile(r"^\| `unit_([0-9A-F]{8})`")
    idx = [i for i, l in enumerate(lines) if row.match(l)]
    if not idx:
        return None
    table = lines[idx[0]:idx[-1] + 1]
    for u, _ in units:
        n = len(u["funcs"])
        what = f"{n} small function{'s' if n > 1 else ''}" + (" (C++)" if u["lang"] == "cpp" else "")
        table.append(f"| `unit_{u['start']:08X}` | 0x{u['start']:08X}-0x{u['end']:08X} | {what} | 100 % |")
    table.sort(key=lambda l: int(row.match(l).group(1), 16))
    lines[idx[0]:idx[-1] + 1] = table
    return "\n".join(lines)


def write(cfg: Config, units: list, base: int) -> None:
    """Everything is prepared and checked first, then written."""
    src_dir = project.ROOT / "src"
    paths = [(src_dir / f"unit_{u['start']:08X}.{u['lang']}", text) for u, text in units]
    if existing := [str(p) for p, _ in paths if p.exists()]:
        sys.exit("already exist: " + ", ".join(existing))
    yaml_text = new_yaml(cfg, units, base)
    rows = None
    if cfg.splits:
        rows = new_rows(project.ROOT / cfg.splits, units)
        if rows is None:
            print(f"{cfg.splits}: no units table, rows not added")
    for p, text in paths:
        p.write_text(text, encoding="utf-8", newline="\n")
    cfg.yaml.write_text(yaml_text, encoding="utf-8", newline="\n")
    if rows is not None:
        (project.ROOT / cfg.splits).write_text(rows, encoding="utf-8", newline="\n")


# ---------------------------------------------------------------- main

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    num = lambda x: int(x, 0)  # noqa: E731
    parser.add_argument("--version", default=project.DEFAULT_VERSION)
    parser.add_argument("--module", default=project.DEFAULT_MODULE)
    parser.add_argument("--min-size", type=num, default=8)
    parser.add_argument("--max-size", type=num, default=0x80)
    parser.add_argument("--max-calls", type=int, default=2)
    parser.add_argument("--start", type=num, help="scan from this address (default: decomp.toml ranges)")
    parser.add_argument("--end", type=num)
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 4)
    parser.add_argument("--write", action="store_true", help="write src/, the splat yaml and table rows")
    parser.add_argument("--show", metavar="FUNC", help="print the sources tried for one function")
    args = parser.parse_args()

    cfg = Config(args.version, args.module)
    if args.start is not None:
        cfg.ranges = [(args.start, args.end or 1 << 32)]
    if not cfg.ranges:
        sys.exit(f"decomp.toml: no [batch.ranges] for {args.version} (or give --start/--end)")
    funcs = sorted(read_functions(sorted(project.asm_dir(args.version, args.module).glob("text*.s"))),
                   key=lambda f: f["addr"])
    callees = Callees(cfg, funcs)
    if args.show:
        f = next((f for f in funcs if f["name"] == args.show), None)
        if f is None:
            sys.exit(f"{args.show}: not in the assembly pieces")
        print(solve(f, cfg, callees, verbose=True)[0])
        return
    todo = [f for f in funcs if eligible(f, cfg, args)]
    print(f"{len(todo)} functions to try")
    with ThreadPoolExecutor(args.jobs) as pool:
        results = list(pool.map(lambda f: (f, *solve(f, cfg, callees)), todo))
    states = {}
    for _, state, _, _ in results:
        key = state.split(" at ")[0].split(" 0x")[0]
        states[key] = states.get(key, 0) + 1
    print(", ".join(f"{k}: {v}" for k, v in sorted(states.items(), key=lambda x: -x[1])))

    base = segment_base(cfg)
    seg_starts = {int(m.group(2), 16) + base for l in cfg.yaml.read_text(encoding="utf-8").split("\n")
                  if (m := SEG.match(l))}
    matched = [(f, src, lang) for f, state, src, lang in results if state == "OK"]
    units = group(cfg, matched, seg_starts)
    print(f"{len(units)} units, {sum(len(u['funcs']) for u, _ in units)} functions, "
          f"{sum(u['end'] - u['start'] for u, _ in units)} bytes")
    if args.write and units:
        write(cfg, units, base)
        print("written; next: python tools/configure.py && ninja")


if __name__ == "__main__":
    main()
