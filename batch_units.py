#!/usr/bin/env python3
"""Decompile small functions in batches and turn the matching ones into units.

For every assembly function of the module in the configured address ranges (no VFPU
or FPU, no jump table, size and call count within limits), C sources are tried:

  - the m2c draft (`--valid-syntax`), field accesses written `*(type *)(p + off)`,
    with variants: indexed accesses as arrays, unsigned stores, `int` arguments
    used as pointers, C++ instead of C, explicit casts where the compiler asks,
    dereferences of untyped values (`*temp`, `*(0x10000 + (s32) p)`, `*f(...)`)
    given the widths the function loads or stores (typed_derefs), an allocation
    result kept in a temporary (alloc_temps), pointer sums passed uncast to `void *`
    parameters (pointer_args), structure array elements `&((E<K> *) (p + off))[i]`
    (stride_arrays), `goto`s of merged block tails written out (inline_gotos).
    m2c also runs with its `mipsee` target ($t0-$t3 renamed $a4-$a7) so that calls
    keep arguments 5-8 (PSP EABI). An `if` whose block returns, followed by a
    `return`, is also tried inverted (mwccpsp keeps the source order of blocks;
    comparisons are negated by their operator, `!(a < b)` compiles differently).
    m2c is given the prototypes of the functions already declared in src/ as
    context (pointers as `void *`, see known_prototypes) and, for functions still
    in assembly, as many `s32` arguments as they read (guess_prototypes); then it
    runs with the first set only, then without context; drafts that give a
    function of src/ another argument count are dropped;
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
    jobs = 8                        # optional: parallel workers (default: all CPUs)
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
from concurrent.futures import ProcessPoolExecutor
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
        self.jobs = batch.get("jobs")
        self.objdump = str(project.binutil("objdump"))
        self.protos = known_prototypes()
        self.guessed = {}  # functions still in assembly, see guess_prototypes
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


C_TYPES = {"void", "char", "int", "short", "float", "double", "signed char", "unsigned char",
           "unsigned short", "unsigned int"}


def known_prototypes() -> dict[str, str]:
    """{name: prototype} of the functions declared or defined in src/, one per function
    (the definition, else the most common declaration). Pointers become `void *`, which
    C converts to and from any pointer without a cast (the pointed types of the
    sources are m2c guesses); other unknown types become `s32`."""
    from prototypes import read_protos  # prototypes imports this module

    def norm(t: str) -> str:
        t = re.sub(r"\bconst\b", "", t)
        base = " ".join(t.replace("*", " ").split())
        if "*" in t:
            return "void *"
        return base if base in TYPES or base in C_TYPES else "s32"

    out = {}
    for name, ps in read_protos(project.ROOT / "src").items():
        known = [p for p in ps if p.known]
        if not known or len({p.count for p in known}) > 1 or any("..." in p.params for p in known):
            continue
        p = next((p for p in known if p.definition), None) or max(
            known, key=lambda p: sum(q.text(name) == p.text(name) for q in known))
        # drop parameter names: `char *p` -> `char *`, `int a` -> `int`
        params = [norm(re.sub(r"(?<=[\s*])\w+$", "", x) if re.search(r"[\s*]\w+$", x) and
                       x.strip() not in C_TYPES else x) for x in p.params]
        out[name] = f"{norm(p.ret)} {name}({', '.join(params) or 'void'})".replace("* ", "*")
    return out


# PSP calls pass arguments 5-8 in $t0-$t3 (EABI); m2c's `mipsee` target knows that
# ABI under its n32 register names: $t0-$t3 -> $a4-$a7, $t4-$t7 -> $t0-$t3
EE_REGS = {**{f"t{i}": f"a{i + 4}" for i in range(4)}, **{f"t{i}": f"t{i - 4}" for i in range(4, 8)}}


def m2c_draft(f: dict, protos: dict[str, str] | None = None, eabi: bool = False) -> str:
    """m2c output; the prototypes of the functions it calls are given as context.
    eabi: `mipsee` target, so that calls keep their arguments in $t0-$t3."""
    src = ".set noat\n.set noreorder\n.section .text\n" + "\n".join(
        re.sub(r"/\* [0-9A-F ]+\*/", "", l) for l in f["lines"] if not l.startswith("nonmatching")) + "\n"
    if eabi:
        src = re.sub(r"\$(t[0-7])\b", lambda m: "$" + EE_REGS[m.group(1)], src)
    with tempfile.TemporaryDirectory() as t:
        p = Path(t) / "f.s"
        p.write_text(src, encoding="utf-8")
        cmd = [sys.executable, "-m", "m2c.main", "--target", "mipsee" if eabi else "mips", "--valid-syntax"]
        used = [n for n in (protos or {}) if n != f["name"] and n in src]
        if used:
            ctx = Path(t) / "ctx.h"
            ctx.write_text("\n".join(f"typedef {v} {k};" for k, v in TYPES.items()) + "\n"
                           + "".join(protos[n] + ";\n" for n in used), encoding="utf-8")
            cmd += ["--context", str(ctx)]
        r = subprocess.run(cmd + [str(p)], capture_output=True, text=True)
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


def field(e: str, t: str, off: str, array) -> str:
    """M2C_FIELD(e, t, off) as C: *(t)(e + off), or an array access (array True), with
    the offset added to a `char *` base (array "char": `(char *)b + off`; `b + off`
    on an `s32` base is an integer sum, one more instruction). Byte accesses through
    a sum of two terms `x + b` (stride 1, no `* k` to tell the index) become
    `((t)((char *)b + off))[x]` with array "byte", `[b]` on `x` with "byte_r"."""
    e = e.strip()
    idx = index_form(e) if array else None
    char_base = array in ("char", "byte", "byte_r")
    elem = SIZES.get(t.replace(" ", "").removesuffix("*"))
    if not idx and array in ("byte", "byte_r") and elem == 1:
        p = split_top(strip_parens(e), " + ")
        num = re.compile(r"-?(?:0x[0-9A-Fa-f]+|\d+)")
        if len(p) == 2 and not any(num.fullmatch(x) for x in p):
            x, b = (p[0], p[1]) if array == "byte" else (p[1], p[0])
            idx = strip_parens(x), 1, strip_parens(b)
    if idx:
        x, k, b = idx
        b = b if re.fullmatch(r"\w+", b) else f"({b})"
        base = b if off in ("0", "0x0") else f"(char *){b} + {off}" if char_base else f"{b} + {off}"
        if elem == k:  # t is a pointer to the element
            return f"(({t})({base}))[{x}]"
        return f"*({t})((E{k} *)({base}))[{x}].b"
    if re.fullmatch(r"\w+", e):
        return f"*({t})({e} + {off})"
    return f"*({t})((char *)({e}) + {off})"


def expand_fields(code: str, array) -> str:
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


def convert(name: str, text: str, array):
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
    """-> (object functions or None, final source, error text). On "illegal implicit
    conversion from 'A' to 'B'", the cast to B is added: to a call argument (each
    argument of the call the compiler points at is tried in turn, pointer-looking
    ones first, until the error leaves that line), else to a `return` or assigned
    value."""
    msg = ""
    pending, last = [], None
    with tempfile.TemporaryDirectory() as t:
        p, o = os.path.join(t, "u." + lang), os.path.join(t, "u.o")
        for _ in range(48):
            Path(p).write_text(src, encoding="utf-8")
            r = subprocess.run([*cfg.cc, "-c", *cfg.flags, "-o", o, p], capture_output=True, text=True,
                               cwd=t, env={**os.environ, "MWCIncludes": "."})
            if not r.returncode:
                return disassemble(cfg, o), src, ""
            msg = r.stdout + r.stderr
            m = re.search(r"#\s+(\d+):.*?illegal implicit conversion from '([^']*)' to\s*#\s*'([^']*)'",
                          msg, re.S)
            if fix_casts and not m and (c := CALL_MISMATCH.search(msg)):
                ln = int(c.group(1)) - 1
                key = (ln, "call", c.group(2))
                if key == last:  # the last fill did not remove the error: next one
                    if not pending:
                        break
                    src = pending.pop(0)
                    continue
                lines = src.split("\n")
                fills = call_fills(lines, ln, c.group(2), n_types(c.group(3)), n_types(c.group(4)))
                if not fills:
                    break
                srcs = ["\n".join(lines[:ln] + [x] + lines[ln + 1:]) for x in fills]
                src, pending, last = srcs[0], srcs[1:] + pending, key
                continue
            if fix_casts and not m and (c := ILLEGAL_OPS.search(msg)):
                ln = int(c.group(1)) - 1
                key = (ln, "ops", c.group(2))
                if key == last:
                    if not pending:
                        break
                    src = pending.pop(0)
                    continue
                srcs = int_operands(src, ln)
                if not srcs:
                    break
                src, pending, last = srcs[0], srcs[1:] + pending, key
                continue
            if not (fix_casts and m):
                break
            ln, frm, to = int(m.group(1)) - 1, m.group(2), m.group(3)
            if (ln, frm, to) == last:  # the last cast did not remove the error: next one
                if not pending:
                    break
                src = pending.pop(0)
                continue
            lines = src.split("\n")
            cands = call_casts(lines[ln], msg, frm, to)
            g = re.match(r"^(\s*)(return )(.+);$", lines[ln]) or re.match(r"^(\s*)(.+? = )(.+);$", lines[ln])
            if g:
                cands.append(f"{g.group(1)}{g.group(2)}({to}) ({g.group(3)});")
            if not cands:
                break
            srcs = ["\n".join(lines[:ln] + [c] + lines[ln + 1:]) for c in cands]
            src, pending, last = srcs[0], srcs[1:], (ln, frm, to)
    return None, src, msg


# mwcc: the argument types of a call, then the prototype it does not match (both may
# wrap onto `#   ` continuation lines)
_TYPES = r"((?:[^)]|\)(?!'))*)"
CALL_MISMATCH = re.compile(r"#\s+(\d+):[^\n]*\n#\s+Error:[^\n]*\n#\s+function call '(\w+)\(" + _TYPES
                           + r"\)' does not match\s*#\s*'\w+\(" + _TYPES + r"\)'")


def n_types(text: str) -> int:
    text = re.sub(r"\s*\n#\s*", " ", text).strip()
    if text in ("", "void"):
        return 0
    depth, n = 0, 1
    for c in text:
        depth += {"(": 1, ")": -1}.get(c, 0)
        n += c == "," and not depth
    return n


def call_fills(lines: list[str], ln: int, fname: str, given: int, wanted: int) -> list[str]:
    """Lines with the call to `fname` on line `ln` given `wanted` arguments instead of
    `given`. m2c leaves out arguments the caller passes on unchanged (`$a0` still
    holding its own first argument) and those it passes on the stack: each missing
    one is tried at each position, as the caller's argument of the same index, then
    as 0. Extra arguments are dropped from the end."""
    line = lines[ln]
    for m in re.finditer(r"\b" + fname + r"\(", line):
        close = matching(line, m.end() - 1)
        if close < 0:
            continue
        inner = line[m.end():close - 1]
        args, k, depth = [], 0, 0
        for j, c in enumerate(inner + ","):
            depth += {"(": 1, "[": 1, ")": -1, "]": -1}.get(c, 0)
            if c == "," and not depth:
                args.append(inner[k:j].strip())
                k = j + 1
        if args == [""]:
            args = []
        if len(args) == given:
            break
    else:
        return []
    head = next((h for h in (re.match(r"^\w[\w *]*?\b\w+\(([^)]*)\) \{$", lines[i]) for i in range(ln, -1, -1))
                 if h), None)
    params = set(re.findall(r"\b(arg\d+)\s*(?:,|$)", head.group(1))) if head else set()

    def call(a):
        return line[:m.end()] + ", ".join(a) + line[close - 1:]
    if wanted < given:
        return [call(args[:wanted])]
    d = wanted - given
    spots = list(itertools.combinations(range(wanted), d))
    # the missing ones together at the end or at the start first
    spots.sort(key=lambda s: (s != tuple(range(given, wanted)), s != tuple(range(d)), s))
    out = []
    for s in spots:
        for zeros in itertools.product((False, True), repeat=d):
            vals = [("0" if z or f"arg{p}" not in params else f"arg{p}") for p, z in zip(s, zeros)]
            it, filled = iter(args), []
            for p in range(wanted):
                filled.append(vals[s.index(p)] if p in s else next(it))
            text = call(filled)
            if text not in out:
                out.append(text)
    return out[:24]


# mwcc: an arithmetic operator given a pointer (caret at the end of the expression)
ILLEGAL_OPS = re.compile(r"#\s+(\d+):[^\n]*\n#\s+Error:[^\n]*\n#\s+illegal operands ('[^']*\*' \S+ '[^']*'"
                         r"|'[^']*' \S+ '[^']*\*')")


def int_operands(src: str, ln: int) -> list[str]:
    """Sources with one pointer or array name of line `ln` read as an integer: m2c
    types as `char *` a value the code also masks, scales or subtracts from
    (`arg1 & 0xFF`, `i - D_X`). A `char *` parameter or local is first declared
    `s32`; then each occurrence alone is cast, then every occurrence of the name."""
    lines = src.split("\n")
    line = lines[ln]
    ptrs = set(re.findall(r"\*\s*(\w+)\s*(?=[,;)=\[])", src))
    ptrs |= set(re.findall(r"^\s*(?:extern\s+)?\w[\w ]*?\b(\w+)\[[^\]]*\];", src, re.M))
    name_at = r"(?<![\w.>*])" + "{}" + r"\b(?!\s*\()"  # not a member, a dereference or a call
    names = [n for n in dict.fromkeys(re.findall(name_at.format(r"([A-Za-z_]\w*)"), line)) if n in ptrs]
    head = next((k for k in range(ln, -1, -1) if re.match(r"^\w[\w *]*?\b\w+\(.*\) \{$", lines[k])), 0)
    above, below = "\n".join(lines[:head]), "\n".join(lines[head:])
    retyped, cast = [], []
    for n in names:
        # a parameter of the enclosing function, or one of its locals
        decl = re.compile(r"(^\w[\w *]*?\b\w+\((?:[^)]*,\s*)?|^\s+)char \*" + n + r"\b(?=[,);])", re.M)
        if decl.search(below):
            retyped.append(above + ("\n" if above else "") + decl.sub(lambda m: m.group(1) + "s32 " + n, below, 1))
        occ = [m.start() for m in re.finditer(name_at.format(n), line)]
        for i in occ:
            cast.append(line[:i] + f"(s32) {n}" + line[i + len(n):])
        if len(occ) > 1:
            cast.append(re.sub(name_at.format(n), f"(s32) {n}", line))
    return retyped + ["\n".join(lines[:ln] + [x] + lines[ln + 1:]) for x in cast[:12]]


def call_casts(line: str, msg: str, frm: str, to: str) -> list[str]:
    """Lines with one argument of the call the compiler points at cast to `to`. mwcc
    prints the end of the source line (cut on the left when long, indentation not
    as written) and a caret under the `)` that closes the call (or a `,` after
    the argument)."""
    m = re.search(r"^(#\s+\d+: )(.*)\n(#\s+Error:\s*)\^", msg, re.M)
    if not m:
        return []
    shown, col = m.group(2), len(m.group(3)) - len(m.group(1))
    col -= len(shown) - len(shown.lstrip())
    shown = shown.lstrip()
    start = line.rfind(shown)
    if start < 0 or not 0 < col <= len(shown):
        return []
    end = start + col
    if end >= len(line) or line[end] not in ",)":
        return []
    # back to the `(` that opens the argument list
    depth, i = 0, end - 1
    while i >= 0:
        c = line[i]
        if c in ")]":
            depth += 1
        elif c in "([":
            if depth == 0:
                break
            depth -= 1
        i -= 1
    if i < 0 or line[i] != "(" or not re.search(r"\w\s*$", line[:i]):
        return []
    close = end
    if line[end] == ",":  # caret after one argument: its call's `)`
        close = matching(line, i) - 1
        if close < 0:
            return []
    args, k, depth = [], i + 1, 0
    for j in range(i + 1, close + 1):
        c = line[j]
        depth += {"(": 1, "[": 1, ")": -1, "]": -1}.get(c, 0) if j < close else 0
        if j == close or (c == "," and depth == 0):
            args.append((k, j))
            k = j + 1
    num = re.compile(r"-?(?:0x[0-9A-Fa-f]+|\d+)U?")
    ptrish = lambda a: a.startswith(("&", '"')) or "*)" in a  # noqa: E731

    def key(span):
        a = line[span[0]:span[1]].strip()
        return (not ptrish(a)) if frm.endswith("*") else ptrish(a)
    out = []
    for a0, a1 in sorted(args, key=key):
        a = line[a0:a1]
        if not a.strip() or num.fullmatch(a.strip()) or a.strip().startswith(f"({to})"):
            continue
        lead = a[:len(a) - len(a.lstrip())]
        out.append(f"{line[:a0]}{lead}({to}) ({a.strip()}){line[a1:]}")
    return out


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

def candidates(f: dict, cfg: Config, callees: Callees):
    """Yield (declarations, body, lang) to try, best guesses first."""
    for decls, body in tail_sources(f, callees):
        yield decls, body, "c"
    # with the known prototypes as context, then without (m2c fails on some contexts)
    every = {**cfg.guessed, **cfg.protos}
    seen = set()
    for text in dict.fromkeys([m2c_draft(f, every), m2c_draft(f, cfg.protos), m2c_draft(f)]):
        seen.add(text)
        yield from draft_sources(f, cfg, text, every)
    # then the same with arguments 5-8 ($t0-$t3), drafted only when the above failed
    if any(op == "jal" for op, _ in f["ins"]) or any(r in ops for _, ops in f["ins"]
                                                       for r in ("$t0", "$t1", "$t2", "$t3")):
        for args in ((f, every), (f, cfg.protos), (f,)):
            text = m2c_draft(*args, eabi=True)
            if text not in seen:
                seen.add(text)
                yield from draft_sources(f, cfg, text, every)


def guess_prototypes(cfg: Config, callees: Callees, funcs: list[dict]) -> dict[str, str]:
    """`s32 f(s32, ...)` for the functions still in assembly, with as many arguments as
    they read (a lower bound; variadic functions are left out). Given to m2c, which
    otherwise guesses from the registers the caller sets."""
    out = {}
    for f in funcs:
        if f["name"].startswith("func_") and f["name"] not in cfg.protos:
            n = callees.reads(f["name"])
            if n is not None:
                out[f["name"]] = f"s32 {f['name']}({', '.join(['s32'] * n) or 'void'})"
    return out


def n_params(proto: str) -> int:
    p = proto[proto.index("(") + 1:proto.rindex(")")].strip()
    return 0 if p in ("", "void") else p.count(",") + 1


def draft_sources(f: dict, cfg: Config, text: str, ctx: dict[str, str]):
    plain, arr = convert(f["name"], text, False), convert(f["name"], text, True)
    if plain is None:
        return
    # a draft must give known functions their known argument count
    for d in plain[0]:
        if (m := re.search(r"\b(\w+)\(", d)) and m.group(1) in cfg.protos and "()" not in d \
                and n_params(d) != n_params(cfg.protos[m.group(1)]):
            return
    # m2c leaves out the declarations it was given as context
    decls = plain[0] + [f"extern {ctx[n]};" for n in sorted(ctx)
                        if n != f["name"] and re.search(r"\b" + n + r"\(", text)
                        and not any(re.search(r"\b" + n + r"\(", d) for d in plain[0])]
    # m2c's merged block tails (`goto`) written out, right after the plain draft
    bodies = [plain[1], *inline_gotos(plain[1])]
    bodies += [arr[1]] if arr and arr[1] not in bodies else []
    # array accesses read `p[i]` (`addu i, p`), the pointer sum `p + i * k` (`addu p, i`)
    arr_c = convert(f["name"], text, "char")
    if arr_c and arr_c[1] not in bodies:
        bodies.append(arr_c[1])
    # byte arrays (stride 1, func_08863D58): both terms tried as the index
    for mode in ("byte", "byte_r"):
        conv = convert(f["name"], text, mode)
        if conv and conv[1] not in bodies:
            bodies.append(conv[1])
    bodies += [b.replace("(s16 *)", "(u16 *)").replace("(s8 *)", "(u8 *)") for b in bodies
               if "(s16 *)" in b or "(s8 *)" in b]
    # m2c reads `D_X[i]` of a symbol it typed as char as `*(&D_X + (i * 2))`: try the
    # element types of that size
    idx = re.compile(r"\*\(&(D_\w+) \+ \(([^()]*(?:\([^()]*\)[^()]*)*) \* ([24])\)\)")
    if idx.search(plain[1]):
        for k, types in (("2", ("s16", "u16")), ("4", ("s32",))):
            for t in types:
                b = idx.sub(lambda m: f"(({t} *)&{m.group(1)})[{m.group(2)}]" if m.group(3) == k
                            else m.group(0), plain[1])
                if b != plain[1]:
                    bodies.append(b)
    m = re.search(r"^.*\b" + f["name"] + r"\(([^)]*)\) \{$", bodies[0], re.M)
    if m and "s32 arg" in m.group(1):
        bodies.append(bodies[0].replace(m.group(0), re.sub(r"s32 (arg\d)", r"char *\1", m.group(0))))
    bodies += [b for b0 in list(bodies) for b in typed_derefs(f, decls, b0)]
    bodies += [b for b0 in list(bodies) for b in stack_arrays(f, b0) if b not in bodies]
    bodies += [b for b0 in list(bodies) for b in pointer_offsets(b0) if b not in bodies]
    bodies += [b for b0 in bodies[:4] for b in stride_arrays(b0) if b not in bodies]
    bodies += [b for b0 in list(bodies) for b in bool_tests(b0) if b not in bodies]
    bodies += [b for b0 in list(bodies) for b in invert_ifs(b0) if b not in bodies]
    bodies += [b for b0 in list(bodies) for b in narrow_params(f["name"], b0) if b not in bodies]
    # signedness, on the first bodies only (each adds a few per site)
    bodies += [b for b0 in bodies[:4] for b in widen_narrow(f["name"], b0) if b not in bodies]
    bodies += [b for b0 in bodies[:6] for b in sign_loads(b0) if b not in bodies]
    # allocation + inlined constructor: temporary result, word loads, pointer arguments
    for b0 in bodies[:3]:
        a = alloc_temps(b0) or b0
        for b in (a, word_derefs(a)):
            if b and b not in bodies:
                bodies.append(b)
    pairs = [(decls, b) for b in bodies]
    pairs += [p for b in bodies[:3] + bodies[-6:] if (p := pointer_args(f["name"], decls, b)) and p not in pairs]
    kr = KR_DECL.search("\n".join(decls + bodies))
    for lang in ("c", "cpp"):
        if lang == "cpp" and kr:  # C++ reads `f()` as taking no arguments
            break
        for d, b in pairs:
            yield d, b, lang


NEGATED = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}


def negate(cond: str) -> str:
    """`a < b` -> `a >= b` (mwccpsp does not compile `!(a < b)` the same way), `!x` ->
    `x`, `x` -> `x == 0`; else `!(cond)`."""
    depth, ops = 0, []
    i = 0
    while i < len(cond):
        c = cond[i]
        depth += {"(": 1, ")": -1, "[": 1, "]": -1}.get(c, 0)
        two = cond[i:i + 2]
        if depth == 0 and two in ("&&", "||"):
            return f"!({cond})"
        if depth == 0 and c == "?":
            return f"!({cond})"
        if depth == 0 and two in ("<<", ">>", "->"):
            i += 2
            continue
        if depth == 0 and two in ("==", "!=", "<=", ">="):
            ops.append((i, two))
            i += 2
            continue
        if depth == 0 and c in "<>":
            ops.append((i, c))
        i += 1
    if len(ops) == 1:
        k, op = ops[0]
        return cond[:k] + NEGATED[op] + cond[k + len(op):]
    if ops:
        return f"!({cond})"
    if cond.startswith("!") and matching(cond, 1) == len(cond) and cond[1] == "(":
        return cond[2:-1]
    if re.fullmatch(r"!\w+", cond):
        return cond[1:]
    if re.fullmatch(r"[\w.]+", cond) or (cond.startswith("(") and matching(cond, 0) == len(cond)):
        return f"{cond} == 0"
    return f"!({cond})"


def invert_ifs(body: str, limit: int = 4) -> list[str]:
    """mwccpsp lays blocks out in source order; m2c puts the long branch first:

        if (C) {              ->    if (!(C)) {
            ...; return X;              return Y;
        }                           }
        return Y;                   ...; return X;

    for an `if` without `else` whose block ends in `return` or `goto`. One body per
    such `if` (the first `limit`), and one with all of them inverted."""
    lines = body.split("\n")
    sites = []
    for i, l in enumerate(lines):
        m = re.match(r"^(\s*)if \((.*)\) \{$", l)
        if not m:
            continue
        ind = m.group(1)
        end = next((j for j in range(i + 1, len(lines)) if lines[j].startswith(ind + "}")
                    and not lines[j].startswith(ind + "} ") and len(lines[j]) == len(ind) + 1), None)
        if end is None or end + 1 >= len(lines) or end - i < 2:
            continue
        last, after = lines[end - 1], lines[end + 1]
        if not re.match(ind + r"    (return\b|goto )", last) or not re.match(ind + r"return\b.*;$", after):
            continue
        if any(not b.startswith(ind + "    ") and b.strip() for b in lines[i + 1:end]):
            continue
        sites.append((i, end, ind, m.group(2)))
    sites = [s for k, s in enumerate(sites) if all(s[0] > t[1] + 1 or s[1] < t[0] for t in sites[:k])]
    sites = sites[:limit]

    def apply(chosen):
        out, i = [], 0
        for s, e, ind, cond in sorted(chosen):
            out += lines[i:s]
            out += [f"{ind}if ({negate(cond)}) {{", ind + "    " + lines[e + 1][len(ind):], ind + "}"]
            out += [b[4:] if b.strip() else b for b in lines[s + 1:e]]
            i = e + 2
        return "\n".join(out + lines[i:])

    variants = [apply([s]) for s in sites]
    if len(sites) > 1:
        variants.append(apply(sites))
    return variants


def narrow_params(name: str, body: str) -> list[str]:
    """m2c reads an `unsigned char` / `unsigned short` parameter as `s32 argN` masked
    at every use (`argN & 0xFF`); declared narrow, it matches in func_0881C240,
    func_088493A4 and func_088DDFE8. For each such parameter: `u8 argN` / `u16
    argN` without the masks. One body per parameter, and one with all of them."""
    m = re.search(r"^.*\b" + name + r"\(([^)]*)\) \{$", body, re.M)
    if not m:
        return []
    sites = []
    for p in re.findall(r"\bs32 (arg\d+)\b", m.group(1)):
        uses = re.findall(r"\b" + p + r"\b(?: & (0xFFFF|0xFF)\b)?", body[m.end():])
        if uses and len(set(uses)) == 1 and uses[0]:
            sites.append((p, "u8" if uses[0] == "0xFF" else "u16", uses[0]))

    def apply(chosen):
        head, rest = m.group(0), body[m.end():]
        for p, t, mask in chosen:
            head = re.sub(r"\bs32 " + p + r"\b", f"{t} {p}", head)
            rest = re.sub(r"\(" + p + " & " + mask + r"\)", p, rest)
            rest = re.sub(r"\b" + p + " & " + mask + r"\b", p, rest)
            # `temp = argN;` as the only store to a local: use the parameter
            for t in re.findall(r"^[ \t]+(\w+) = " + p + r";$", rest, re.M):
                if len(re.findall(r"\b" + t + r" =[^=]", rest)) == 1:
                    decl = "|".join(sorted(TYPE_WORDS, key=len, reverse=True))
                    rest = re.sub(r"^[ \t]+(?:(?:" + decl + r") )+" + t + r";\n|^[ \t]+" + t + " = " + p + r";\n",
                                  "", rest,
                                  flags=re.M)
                    rest = re.sub(r"\b" + t + r"\b", p, rest)
        return body[:m.start()] + head + rest

    out = [apply([s]) for s in sites]
    if len(sites) > 1:
        out.append(apply(sites))
    return out


TYPE_WORDS = {"void", "char", "int", "short", "long", "signed", "unsigned", "const", "s8", "u8",
              "s16", "u16", "s32", "u32", "f32"}


def matching(text: str, i: int) -> int:
    """Index just past the parenthesis that closes the one at text[i], or -1."""
    depth = 0
    for j in range(i, len(text)):
        depth += {"(": 1, ")": -1}.get(text[j], 0)
        if not depth:
            return j + 1
    return -1


def untyped_derefs(decls: list[str], body: str) -> list[tuple[int, int]]:
    """(start, end) of the operands of the `*` that m2c applies to a non-pointer
    (`*temp_s1`, `*(0xF7A57C + (s32) p)`, `*func_X(...)` returning s32), which
    mwccpsp rejects ("pointer/array required"). Pointers are the names declared with
    `*` or as arrays, and the functions declared as returning a pointer."""
    decl_line = re.compile(r"^\s*(?:\w+\s+)+\**\s*\w+(?:\[[^\]]*\])?;$")
    text = "\n".join(decls + [l for l in body.split("\n")
                              if decl_line.match(l) or re.search(r"\b\w+\(.*\) \{$", l)])
    ptrs = set(re.findall(r"\*\s*(\w+)\s*(?=[;,)\[(])", text)) | set(re.findall(r"\b\w+\s+(\w+)\[", text))

    def is_ptr(expr: str) -> bool:
        expr = expr.strip()
        while expr.startswith("(") and matching(expr, 0) == len(expr):
            expr = expr[1:-1].strip()
        depth, terms, start = 0, [], 0
        for k, c in enumerate(expr):
            depth += {"(": 1, ")": -1}.get(c, 0)
            if depth == 0 and c in "+-" and k > 0 and expr[k - 1] == " ":
                terms.append(expr[start:k])
                start = k + 1
        terms.append(expr[start:])
        for t in (t.strip() for t in terms):
            if t.startswith("&") or re.match(r"\((?:\w+ )*\w+ \*+\)", t):
                return True
            if (m := re.match(r"\w+", t)) and m.group(0) in ptrs:
                return True
        return False

    out = []
    for m in re.finditer(r"\*", body):
        i = m.start()
        line_start = body.rfind("\n", 0, i) + 1
        line_end = body.find("\n", i)
        line = body[line_start:line_end if line_end >= 0 else len(body)]
        if decl_line.match(line) or re.search(r"\b\w+\(.*\) \{$", line):
            continue
        before = body[line_start:i].rstrip()
        prev = before[-1:]
        if prev and prev not in "(=,!&|<>+-*/%?:;{}[~" and not before.endswith("return"):
            if prev != ")":
                continue
            # `(type) *x` is a cast then a dereference; `a) * b` is a product
            words = before[before.rfind("(") + 1:-1].replace("*", " ").split()
            if not words or not all(w in TYPE_WORDS for w in words):
                continue
        j = i + 1
        if j >= len(body) or body[j] in " )":
            continue
        if body[j] == "(":
            end = matching(body, j)
            if end < 0:
                continue
            inner = body[j + 1:end - 1].strip()
            if re.fullmatch(r"(?:\w+ )*\w+ \*+", inner) or is_ptr(inner):  # `*(T *)...`, pointer
                continue
            out.append((j, end))
        elif (mm := re.match(r"[A-Za-z_]\w*", body[j:])):
            if mm.group(0) in ptrs:
                continue
            end = j + mm.end()
            if end < len(body) and body[end] == "(":
                end = matching(body, end)
                if end < 0:
                    continue
            out.append((j, end))
    return out


def typed_derefs(f: dict, decls: list[str], body: str) -> list[str]:
    """Bodies where each untyped dereference (untyped_derefs) gets a type of a width
    the function loads or stores: every combination up to 3 places, else one type
    for all."""
    sites = untyped_derefs(decls, body)
    if not sites:
        return []
    ops = {op for op, _ in f["ins"]}
    types = [t for t, o in (("s32", ("lw", "sw")), ("u8", ("lbu", "sb")), ("u16", ("lhu", "sh")),
                            ("s8", ("lb",)), ("s16", ("lh",))) if ops & set(o)] or ["s32"]
    combos = itertools.product(types, repeat=len(sites)) if len(sites) <= 3 \
        else ([t] * len(sites) for t in types)
    out = []
    for combo in itertools.islice(combos, 64):
        b = body
        for (a, e), t in sorted(zip(sites, combo), reverse=True):
            b = b[:a] + f"({t} *)({b[a:e]})" + b[e:]
        out.append(b)
    return out


def bool_tests(body: str, limit: int = 3) -> list[str]:
    """The original turns a flag test into a C++ `bool` (`andi`, `sltu $v0, $zero, $v0`)
    and compares that with 0 or 1 (an inlined `bool` getter): `!(A & K)`,
    `(A & K) == 0` and `(A & K) == 1` become `(bool) (A & K) == 0 / 1` (func_0881C884,
    func_08828884; C++ only). One body per site (the first `limit`), and one with all."""
    sites = []
    for m in re.finditer(r"!\(|\(", body):
        start = m.end() - 1
        if m.group(0) == "(" and m.start() and re.match(r"[\w\])]", body[m.start() - 1]):
            continue  # a call's argument list, an index, a cast's operand
        end = matching(body, start)
        if end < 0:
            continue
        inner = body[start + 1:end - 1]
        if len(split_top(inner, " & ")) != 2 or any(len(split_top(inner, op)) > 1
                                                    for op in (" && ", " || ", " == ", " != ")):
            continue
        if m.group(0) == "!(":
            sites.append((m.start(), end, f"((bool) ({inner}) == 0)"))
        elif (t := re.match(r" (==) ([01])\b", body[end:])):
            sites.append((start, end + t.end(), f"(bool) ({inner}) == {t.group(2)}"))
    kept = []
    for s in sites:
        if all(s[0] >= t[1] or s[1] <= t[0] for t in kept):
            kept.append(s)
    sites = kept

    def apply(chosen):
        b = body
        for a, e, new in sorted(chosen, reverse=True):
            b = b[:a] + new + b[e:]
        return b
    out = [apply([s]) for s in sites[:limit]]
    if len(sites) > 1:
        out.append(apply(sites))
    return out


def pointer_offsets(body: str) -> list[str]:
    """m2c writes a large field offset as an integer sum, `*(T *)((0x5623D0 + (s32) p))`;
    mwccpsp then builds the constant whole (`lui` + `ori`). On a `char *` it splits
    it between `lui` and the load or store offset, as the original does
    (func_08880864): `*(T *)((char *)p + 0x5623D0)`. One body with every site."""
    out, i = body, 0
    pat = re.compile(r"\((?:\w+ )*\w+ \*+\)\((\((0x[0-9A-Fa-f]+) \+ )")
    while m := pat.search(out, i):
        start = m.start(1)
        end = matching(out, start)
        if end < 0:
            break
        rest = out[start + len(m.group(1)):end - 1].strip()
        if len(split_top(rest, " + ")) == 1 and len(split_top(rest, " - ")) == 1:  # one term
            rest = re.sub(r"^\(s32\) ", "", rest)
        base = rest if re.fullmatch(r"\w+", rest) else f"({rest})"
        new = f"(char *){base} + {m.group(2)}"
        out = out[:start] + new + out[end:]
        i = start + len(new)
    return [out] if out != body else []


NARROW = {"s8": "u8", "u8": "s8", "s16": "u16", "u16": "s16"}


def sign_loads(body: str, limit: int = 4) -> list[str]:
    """m2c guesses the sign of a byte or halfword load from its uses; the original may
    load the other way (`lbu` for `lb`, func_08823C84, func_088A9FF8). Each typed load
    `*(u8 *)(...)` gets the other sign, and a symbol m2c left as `char`, `*(&D_X + i)`,
    is read through `(u8 *)` or `(s8 *)`. Stores are left alone (same instruction).
    One body per site (the first `limit`), and one with all of them."""
    sites = []
    for m in re.finditer(r"\*\((s8|u8|s16|u16) \*\)\(", body):
        end = matching(body, m.end() - 1)
        if end > 0 and not re.match(r" =[^=]", body[end:]):
            sites.append((m.start() + 2, m.start() + 2 + len(m.group(1)), NARROW[m.group(1)]))
    for m in re.finditer(r"\*\(&(D_\w+) \+ ", body):
        for t in ("u8", "s8"):
            sites.append((m.start() + 2, m.start() + 3 + len(m.group(1)), f"({t} *)&{m.group(1)}"))

    def apply(chosen):
        b = body
        for a, e, new in sorted(chosen, reverse=True):
            b = b[:a] + new + b[e:]
        return b
    out = [apply([s]) for s in sites[:limit]]
    if len(sites) > 1:
        # one site per position for the combined body
        out.append(apply(list({a: (a, e, n) for a, e, n in sites}.values())))
    return out


def widen_narrow(name: str, body: str, limit: int = 4) -> list[str]:
    """m2c types as `s8` / `s16` a counter or parameter that the original kept in an
    `int`, truncated only where it is stored or passed (extra `seb` / `seh`,
    func_08891B14, func_088D5C34); or the original narrowed at a call a parameter m2c
    declared narrow (func_08865F68). Each such local or parameter is made `s32`; a
    call argument `(s32) v` becomes `(T) v`. One body per variable, and one with all."""
    sig = re.search(r"^.*\b" + name + r"\(([^)]*)\) \{$", body, re.M)
    vars_ = [(m.group(1), m.group(2)) for m in re.finditer(r"^    (s8|u8|s16|u16) (\w+);$", body, re.M)]
    if sig:
        vars_ += re.findall(r"\b(s8|u8|s16|u16) (arg\d+)\b", sig.group(1))

    def apply(chosen):
        b = body
        for t, v in chosen:
            b = re.sub(r"^    " + t + " " + v + ";$", f"    s32 {v};", b, flags=re.M)
            if v.startswith("arg") and (s := re.search(r"^.*\b" + name + r"\(([^)]*)\) \{$", b, re.M)):
                b = b[:s.start()] + re.sub(r"\b" + t + " " + v + r"\b", f"s32 {v}", s.group(0)) + b[s.end():]
            b = re.sub(r"(?<=\w\()\(s32\) " + v + r"\b|(?<=, )\(s32\) " + v + r"\b", f"({t}) {v}", b)
        return b
    out = [apply([v]) for v in vars_[:limit]]
    if len(vars_) > 1:
        out.append(apply(vars_))
    return [b for b in out if b != body]


def closing_brace(text: str, i: int) -> int:
    """Index just past the brace that closes the one at text[i], or -1."""
    depth = 0
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if not depth:
            return j + 1
    return -1


def alloc_temps(body: str) -> str | None:
    """`v = f(...); if (v != 0) { ... } else { v = 0; }` (an allocation followed by an
    inlined constructor, func_088C354C): the original keeps the `v = 0` of the else
    block (dead code after a `b`), which m2c's single variable lets the compiler drop.
    The result goes to a temporary, copied to `v` at the end of the then block."""
    m = re.search(r"^( *)(\w+) = (\w+\(.*\));\n\1if \(\2 != 0\) \{\n", body, re.M)
    if not m:
        return None
    ind, v = m.group(1), m.group(2)
    end = closing_brace(body, m.end() - 2)
    decl = re.search(r"^    (\w+(?: \*+)?) " + v + ";$", body, re.M)
    if end < 0 or not decl or not re.match(r" else \{\n *" + v + r" = 0;\n *\}", body[end:]) \
            or re.search(r"\btmp\b", body):
        return None
    # `v` must hold the allocation only: no other assignment in the then block
    if re.search(r"\b" + v + r" (?:[-+*/&|^]|<<|>>)?=(?!=)", body[m.end() - 2:end]):
        return None
    block =re.sub(r"\b" + v + r"\b", "tmp", body[m.end() - 2:end - 1])
    out = (body[:m.start()] + f"{ind}tmp = {m.group(3)};\n{ind}if (tmp != 0) " + block
           + f"    {ind}{v} = tmp;\n{ind}}}" + body[end:])
    return out.replace(decl.group(0), decl.group(0) + f"\n    {decl.group(1)} tmp;", 1)


def word_derefs(body: str) -> str | None:
    """`x = *argN;` of a `char *` parameter read as a word (`lw`, func_088C354C)."""
    out = re.sub(r"= \*(arg\d+);", r"= *(s32 *)\1;", body)
    return out if out != body else None


def stride_arrays(body: str) -> list[str]:
    """`t = (I * K) + B;` then `*(T *)(t + off)` (m2c, func_08830728): the original
    reads element I of an array of K-byte structures, `*(T *) &((E<K> *) (B + off))[i]`,
    the index kept in a local (inlined, mwccpsp computes it at each access; as a sum,
    the `addu` operands come out swapped). The local is tried as `s32` and as the
    type of a leading cast of I. One body per local type, all such temporaries
    rewritten; None when a temporary has any other use."""
    lines = body.split("\n")
    sites = []
    for n, l in enumerate(lines):
        m = re.match(r"^( +)(\w+) = (.+);$", l)
        if not m:
            continue
        rhs = re.sub(r"^\((?:char|void) \*\) ", "", m.group(3))
        sides = split_top(strip_parens(rhs), "+")
        if len(sides) != 2:
            continue
        prod = split_top(strip_parens(sides[0]), "*")
        if len(prod) < 2 or not re.fullmatch(r"0x[0-9A-Fa-f]+|\d+", prod[-1]):
            continue
        k = int(prod[-1], 0)
        if k < 2:
            continue
        sites.append((n, m.group(1), m.group(2), " * ".join(prod[:-1]), k, sides[1]))
    if not sites:
        return []
    out = []
    for typed in (False, True):
        new, ok, declared = list(lines), True, set()
        for x, (n, ind, t, idx, k, base) in enumerate(sites):
            cast = re.match(r"^\((s8|u8|s16|u16)\) ", idx)
            ty = cast.group(1) if typed and cast else "s32"
            i = f"{t}_i"
            new[n] = f"{ind}{i} = {idx};"
            # up to the next assignment of the same temporary (same local index)
            stop = next((s[0] for s in sites[x + 1:] if s[2] == t), len(new))
            rest = "\n".join(new[n + 1:stop])
            rest = re.sub(r"\*\((\w+ \*+)\)\(" + t + r" \+ ([^()]+)\)",
                          lambda m: f"*({m.group(1)}) &((E{k} *) ({base} + {m.group(2)}))[{i}]", rest)
            rest = re.sub(r"\*\((\w+ \*+)\)(?:\(" + t + r"\)|" + t + r"\b)",
                          lambda m: f"*({m.group(1)}) &((E{k} *) ({base}))[{i}]", rest)
            if re.search(r"\b" + t + r"\b", rest):
                ok = False
                break
            new[n + 1:stop] = rest.split("\n")
            if t in declared:
                continue
            d = next((j for j, l in enumerate(new) if re.match(r"^    \S.* \**" + t + ";$", l)), None)
            if d is None:
                ok = False
                break
            new[d] = f"    {ty} {i};"
            declared.add(t)
        # any use left (before the first assignment, in an index or base): no body
        if ok and any(re.search(r"\b" + t + r"\b", "\n".join(new)) for t in declared):
            ok = False
        if ok and (b := "\n".join(new)) not in out:
            out.append(b)
    return out


def inline_gotos(body: str, limit: int = 8) -> list[str]:
    """m2c merges identical block tails: `goto block_N;` jumps to a label inside a
    later block. The original repeats the tail (func_088C3C54: each branch of an
    `if / else if` stores its own result). Each `goto` is replaced with a copy of the
    statements that follow its label up to the end of the label's block; the label
    goes when nothing jumps to it any more. A second body also turns
    `if (a) {...} if (b) {` into `if (a) {...} else if (b) {` where the first block
    held the `goto` (without it, control would fall into the second test)."""

    def once(text: str, chain: bool):
        lines = text.split("\n")
        g = next((n for n, l in enumerate(lines) if re.match(r"^ +goto (\w+);$", l)), None)
        if g is None:
            return None
        label = re.match(r"^ +goto (\w+);$", lines[g]).group(1)
        at = next((n for n, l in enumerate(lines) if l == label + ":"), None)
        if at is None or at < g:
            return None
        if at == g + 1:  # jump to the next line: no copy
            new = lines[:g] + lines[g + 1:]
            if not any(re.match(r"^ +goto " + label + ";$", l) for l in new):
                new = [l for l in new if l != label + ":"]
            return "\n".join(new)
        tail, depth = [], 0
        for l in lines[at + 1:]:
            depth += l.count("{") - l.count("}")
            if depth < 0 or re.match(r"^\w+:$", l):
                break
            tail.append(l)
        if not tail:
            return None
        ind = re.match(r"^ *", lines[g]).group(0)
        base = min(len(re.match(r"^ *", l).group(0)) for l in tail if l.strip())
        copy = [ind + l[base:] if l.strip() else l for l in tail]
        new = lines[:g] + copy + lines[g + 1:]
        if chain:
            # the block that held the goto ends right after the copy: chain the next if
            end = g + len(copy)
            if end + 1 < len(new) and new[end].strip() == "}" and \
                    re.match(r"^ *if \(", new[end + 1]) and \
                    len(re.match(r"^ *", new[end + 1]).group(0)) == len(new[end]) - 1:
                new[end] = new[end] + " else " + new[end + 1].lstrip()
                del new[end + 1]
        # the label goes last (removing it first would shift the indexes above)
        if not any(re.match(r"^ +goto " + label + ";$", l) for l in new):
            new = [l for l in new if l != label + ":"]
        return "\n".join(new)

    out = []
    for chain in (False, True):
        b = body
        for _ in range(limit):
            nb = once(b, chain)
            if nb is None:
                break
            b = nb
        if b != body and "goto " not in b and b not in out:
            out.append(b)
    return out


def extern_params(decl: str, callee: str):
    """`extern T f(A, B);` -> (head up to the '(', [A, B], tail from the ')'), or None."""
    m = re.match(r"^extern .*?\b" + callee + r"\(", decl)
    if not m:
        return None
    e = matching(decl, m.end() - 1)
    if e < 0:
        return None
    return decl[:m.end()], split_top(decl[m.end():e - 1], ","), decl[e - 1:]


def pointer_args(name: str, decls: list[str], body: str):
    """A call argument `(int) (argN + K)` or `argN + K` passed to an `s32` parameter:
    the cast makes mwccpsp compute the sum once and keep it in a saved register, the
    original recomputes it at each call (func_088C354C). The argument is passed
    uncast to a `void *` parameter of the callee's extern, and an `s32 argN` of the
    signature becomes `char *argN`. -> (declarations, body) or None."""
    externs = {c: k for k, d in enumerate(decls)
               for c in re.findall(r"\b(func_\w+)\(", d)[:1] if extern_params(d, c)}
    pointer = re.compile(r"^\(?(arg\d+) \+ ")
    sites, params, out, pos = set(), set(), body, 0
    # one call at a time, the text scanned again after each rewrite (nested calls)
    while (m := re.compile(r"\b(func_\w+)\(").search(out, pos)):
        pos = m.end()
        callee, a = m.group(1), m.end() - 1
        e = matching(out, a)
        if callee == name or callee not in externs or e < 0:
            continue
        args = split_top(out[a + 1:e - 1], ",")
        new = [re.sub(r"^\((?:int|s32)\) ", "", x) for x in args]
        hits = [i for i, y in enumerate(new) if pointer.match(y)]
        if not hits:
            continue
        sites |= {(callee, i) for i in hits}
        params |= {pointer.match(new[i]).group(1) for i in hits}
        out = out[:a + 1] + ", ".join(args[i] if i not in hits else new[i] for i in range(len(args))) + out[e - 1:]
    if not sites:
        return None
    sig = re.search(r"^.*\b" + name + r"\(([^)]*)\) \{$", out, re.M)
    if sig:
        line = sig.group(0)
        for p in params:
            line = re.sub(r"\bs32 " + p + r"\b", "char *" + p, line)
        out = out[:sig.start()] + line + out[sig.end():]
    new_decls = list(decls)
    for callee, i in sites:
        k = externs[callee]
        head, ps, tail = extern_params(new_decls[k], callee)
        if i < len(ps):
            ps[i] = "void *"
        new_decls[k] = head + ", ".join(ps) + tail
    return new_decls, out


LOAD_TYPES = {"lb": "s8", "lbu": "u8", "lh": "s16", "lhu": "u16", "lw": "s32",
              "sb": "s8", "sh": "s16", "sw": "s32"}


def stack_arrays(f: dict, body: str, limit: int = 6) -> list[str]:
    """m2c declares the first word of a stack structure passed by address (`u16 sp10;`,
    `&sp10`) and uses the other fields undeclared (`sp12`, `unksp2E`). Each
    undeclared `spYY` goes to the closest such local `spXX` below it, made an array
    of its type up to the top of the frame (`u16 sp10[8]`, sizes down to the last
    field, the first `limit`): `spXX[(YY - XX) / size]`, or `*(T *)((char *)spXX +
    d)` with T the width the function loads or stores at YY when not aligned."""
    ins = f["ins"]
    if not ins or ins[0][0] != "addiu" or ins[0][1][:2] != ["$sp", "$sp"]:
        return []
    frame = -int(ins[0][1][2], 0)
    decl = {m.group(2): (m.group(1), m.group(0)) for m in
            re.finditer(r"^    (s8|u8|s16|u16|s32|u32) (sp([0-9A-F]+));$", body, re.M)
            if re.search("&" + m.group(2) + r"\b", body)}
    used = set(re.findall(r"\b((?:unk)?sp[0-9A-F]+)\b", body))
    undef = sorted(n for n in used if n not in decl and not re.search(
        r"^\s+(?:\w+\s+)+\**" + n + r"(?:\[\w*\])?;$", body, re.M))
    if not undef or not decl:
        return []
    width = {}
    for op, ops in ins:
        if op in LOAD_TYPES and len(ops) == 2 and (m := re.fullmatch(r"(-?0x[0-9A-F]+|\d+)\(\$sp\)", ops[1])):
            width.setdefault(int(m.group(1), 0), LOAD_TYPES[op])
    off = lambda n: int(re.sub(r"^(?:unk)?sp", "", n), 16)  # noqa: E731
    plan = {}  # base -> [(name, offset from base, width)]
    for n in undef:
        bases = [b for b in decl if off(b) < off(n)]
        if not bases:
            return []
        b = max(bases, key=off)
        plan.setdefault(b, []).append((n, off(n) - off(b), width.get(off(n))))
    # the array of a base ends at the next local passed by address, or the frame top;
    # locals declared inside it become fields too
    others = {m.group(2): m.group(0) for m in
              re.finditer(r"^    (s8|u8|s16|u16|s32|u32) (sp([0-9A-F]+));\n", body, re.M) if m.group(2) not in decl}
    ends = {b: min([off(c) for c in decl if off(c) > off(b)] + [frame]) for b in plan}
    for b in plan:
        for n in others:
            if off(b) < off(n) < ends[b]:
                plan[b].append((n, off(n) - off(b), width.get(off(n))))
                body = body.replace(others[n], "", 1)
    out_sets = []
    for b, fields in plan.items():
        t, line = decl[b]
        size = SIZES[t]
        last = max(d + SIZES.get(w or t, size) for _, d, w in fields)
        top = ends[b] - off(b)
        counts = [n for n in range(top // size, -(-last // size) - 1, -1)][:limit]
        if not counts:  # a field past the next local or the frame top
            return []
        out_sets.append((b, t, line, size, fields, counts))
    out = []
    for k in range(max(len(s[5]) for s in out_sets)):
        nb = body
        for b, t, line, size, fields, counts in out_sets:
            n = counts[min(k, len(counts) - 1)]
            nb = nb.replace(line, "\0D", 1)
            nb = re.sub(r"&" + b + r"\b", "\0P", nb)  # `&spXX` -> the array itself
            nb = re.sub(r"\b" + b + r"\b", f"{b}[0]", nb)  # `spXX` -> its first element
            nb = nb.replace("\0P", b).replace("\0D", f"    {t} {b}[{n}];")
            for name, d, w in fields:
                acc = f"{b}[{d // size}]" if d % size == 0 and (w is None or SIZES[w] == size) \
                    else f"*({w or t} *)((char *){b} + {d:#x})"
                nb = re.sub(r"\b" + name + r"\b", acc, nb)
        out.append(nb)
    return out


def grow_buffer(cfg: Config, f: dict, body: str):
    """m2c types a stack buffer by its first use (`s32 sp1C;`, passed as `&sp1C`). When
    the original frame is larger (`addiu $sp, $sp, -X`), make the only such local a
    char array that fills the gap. -> new bodies, largest buffer first (the saved
    registers at the top of the frame take an unknown part of it)."""
    addr = int(f["name"][5:], 16)
    w = cfg.word(addr)
    if w >> 16 != 0x27BD or not w & 0x8000:
        return []
    frame = 0x10000 - (w & 0xFFFF)
    locs = [m for m in re.finditer(r"^    (s8|u8|s16|u16|s32|u32|char) (sp[0-9A-F]+);$", body, re.M)
            if "&" + m.group(2) in body]
    if len(locs) != 1:
        return []
    m = locs[0]
    top = frame - int(m.group(2)[2:], 16)
    return [body.replace(m.group(0), f"    char {m.group(2)}[{size:#x}];", 1).replace(
        f"&{m.group(2)}", m.group(2)) for size in range(top, top - 0x30, -4)
        if size > SIZES.get(m.group(1), 4)]


def state_rank(state: str) -> int:
    return next((i for i, k in enumerate(("differs", "length")) if state.startswith(k)), 2)


def solve(f: dict, cfg: Config, callees: Callees, verbose: bool = False):
    """-> (state, source, lang) of the first matching source, else of the closest try
    (the first that differs, else the first of the wrong length, else the first)."""
    first = None
    for decls, body, lang in candidates(f, cfg, callees):
        state, src, err = try_source(cfg, f["name"], f["size"], decls, body, lang)
        if state.startswith("differs at 0,"):
            for grown in grow_buffer(cfg, f, body):
                state2, src2, err2 = try_source(cfg, f["name"], f["size"], decls, grown, lang)
                if state2 == "OK":
                    state, src, err = state2, src2, err2
                    break
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
        if first is None or state_rank(state) < state_rank(first[0]):
            first = (state, src, lang)
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

_worker = None  # (cfg, callees) of a worker process, see _init_worker


def _init_worker(cfg: Config, callees: Callees) -> None:
    global _worker
    _worker = cfg, callees


def _solve_worker(f: dict):
    return (f, *solve(f, *_worker))


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
    parser.add_argument("-j", "--jobs", type=int,
                        help="parallel workers (default: [batch] jobs of decomp.toml, else all CPUs)")
    parser.add_argument("--write", action="store_true", help="write src/, the splat yaml and table rows")
    parser.add_argument("--show", metavar="FUNC", help="print the sources tried for one function")
    args = parser.parse_args()

    cfg = Config(args.version, args.module)
    jobs = args.jobs or cfg.jobs or os.cpu_count() or 4
    if args.start is not None:
        cfg.ranges = [(args.start, args.end or 1 << 32)]
    if not cfg.ranges:
        sys.exit(f"decomp.toml: no [batch.ranges] for {args.version} (or give --start/--end)")
    funcs = sorted(read_functions(sorted(project.asm_dir(args.version, args.module).glob("text*.s"))),
                   key=lambda f: f["addr"])
    callees = Callees(cfg, funcs)
    cfg.guessed = guess_prototypes(cfg, callees, funcs)
    if args.show:
        f = next((f for f in funcs if f["name"] == args.show), None)
        if f is None:
            sys.exit(f"{args.show}: not in the assembly pieces")
        print(solve(f, cfg, callees, verbose=True)[0])
        return
    todo = [f for f in funcs if eligible(f, cfg, args)]
    print(f"{len(todo)} functions to try")
    print(f"{jobs} workers")
    # processes, not threads: the drafts and comparisons are Python work held by the GIL
    with ProcessPoolExecutor(jobs, initializer=_init_worker, initargs=(cfg, callees)) as pool:
        results = list(pool.map(_solve_worker, todo, chunksize=1))
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
