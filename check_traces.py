#!/usr/bin/env python3
"""Refuse local traces in a public repository: absolute paths of the author's
machine, attribution trailers, private words, and local files that must stay out
of the repository.

Checks, from the root of the git work tree:
  python tools/psp/check_traces.py                  # files of the index (next commit)
  python tools/psp/check_traces.py --commit-msg F   # one commit message (commit-msg hook)
  python tools/psp/check_traces.py --log A..B       # messages of a commit range (CI)
  python tools/psp/check_traces.py --install-hooks  # pre-commit + commit-msg hooks

Private settings never live in the repository:
  - every path listed in .git/info/exclude must not be tracked;
  - .git/info/traces.txt (local) and the TRACE_PATTERNS environment variable (CI,
    one pattern per line) add forbidden regular expressions;
  - a line `allow: <text>` in .git/info/traces.txt, or the `[traces] allow` list of
    decomp.toml, allows the lines that contain <text>.

Exit status 1 when anything is found; every hit is printed as path:line: reason.
"""

import argparse
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

PATTERNS = [
    # Absolute paths: Windows drives, MSYS drives, user homes
    (r"\b[A-Za-z]:[\\/](?:Users|Projets|Projects|Dev|Documents|Github|home)\b", "absolute path"),
    (r"(?<![\w.])/[a-z]/(?:Users|Projets|Projects)\b", "absolute path"),
    (r"(?<![\w.])/(?:home|Users)/[A-Za-z0-9_.-]+/", "home directory"),
    (r"\bAppData[\\/]", "absolute path"),
    # Commit attribution trailers
    (r"(?i)co-?authored-?by", "attribution trailer"),
]

PRE_COMMIT = """#!/bin/sh
# Installed by check_traces.py --install-hooks
exec python "{script}"
"""
COMMIT_MSG = """#!/bin/sh
# Installed by check_traces.py --install-hooks
exec python "{script}" --commit-msg "$1"
"""


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True,
                          encoding="utf-8", errors="replace").stdout


def git_path(root: Path, name: str) -> Path:
    path = Path(git("rev-parse", "--git-path", name).strip())
    return path if path.is_absolute() else root / path


def load_settings(root: Path) -> tuple[list, list[str], list[str]]:
    """(patterns, allowed substrings, excluded paths)"""
    patterns = [(re.compile(p), why) for p, why in PATTERNS]
    allow: list[str] = []
    conf = root / "decomp.toml"
    if conf.is_file():
        allow += tomllib.loads(conf.read_text(encoding="utf-8")).get("traces", {}).get("allow", [])
    private = git_path(root, "info/traces.txt")
    lines = private.read_text(encoding="utf-8").splitlines() if private.is_file() else []
    lines += os.environ.get("TRACE_PATTERNS", "").splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("allow:"):
            allow.append(line[6:].strip())
        else:
            patterns.append((re.compile(line), "private pattern"))
    exclude = git_path(root, "info/exclude")
    excluded = [l.strip().lstrip("/") for l in exclude.read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#")] if exclude.is_file() else []
    return patterns, allow, excluded


def scan_text(label: str, text: str, patterns, allow: list[str]) -> list[str]:
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if any(a in line for a in allow):
            continue
        for pat, why in patterns:
            if pat.search(line):
                hits.append(f"{label}:{n}: {why}")
                break
    return hits


def index_blobs() -> list[tuple[str, str]]:
    """(path, blob id) of every regular file in the index: what the next commit holds."""
    out = []
    for entry in git("ls-files", "-s", "-z").split("\0"):
        if not entry:
            continue
        meta, name = entry.split("\t", 1)
        mode, blob, _stage = meta.split()
        if mode in ("100644", "100755"):  # not symlinks or submodules
            out.append((name, blob))
    return out


def read_blobs(blobs: list[str]) -> list[bytes]:
    """Contents of the blobs, through one `git cat-file --batch`."""
    proc = subprocess.run(["git", "cat-file", "--batch"], input="\n".join(blobs).encode() + b"\n",
                          capture_output=True, check=True)
    data, pos, out = proc.stdout, 0, []
    for _ in blobs:
        header_end = data.index(b"\n", pos)
        size = int(data[pos:header_end].split()[2])
        out.append(data[header_end + 1:header_end + 1 + size])
        pos = header_end + 1 + size + 1
    return out


def scan_files(patterns, allow, excluded) -> list[str]:
    entries = index_blobs()
    hits = []
    for name, _ in entries:
        if any(name == e.rstrip("/") or name.startswith(e.rstrip("/") + "/") for e in excluded):
            hits.append(f"{name}: listed in .git/info/exclude, must stay out of the repository")
    for (name, _), data in zip(entries, read_blobs([b for _, b in entries])):
        if b"\0" in data[:8192]:
            continue  # binary
        hits += scan_text(name, data.decode("utf-8", errors="replace"), patterns, allow)
    return hits


def install_hooks(root: Path) -> None:
    hooks = git_path(root, "hooks")
    hooks.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).resolve().relative_to(root.resolve()).as_posix()
    for name, body in (("pre-commit", PRE_COMMIT), ("commit-msg", COMMIT_MSG)):
        path = hooks / name
        path.write_text(body.format(script=script), newline="\n")
        path.chmod(0o755)
    print(f"hooks installed: pre-commit, commit-msg -> {script}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--commit-msg", type=Path, help="check one commit message file")
    parser.add_argument("--log", help="check the messages of a commit range")
    parser.add_argument("--install-hooks", action="store_true")
    args = parser.parse_args()

    root = Path(git("rev-parse", "--show-toplevel").strip())
    if args.install_hooks:
        install_hooks(root)
        return
    patterns, allow, excluded = load_settings(root)
    if args.commit_msg:
        # git comment lines are not part of the message
        text = "\n".join(l for l in args.commit_msg.read_text(encoding="utf-8").splitlines()
                         if not l.startswith("#"))
        hits = scan_text("commit message", text, patterns, [])
    elif args.log:
        hits = []
        for commit in git("rev-list", args.log).split():
            hits += scan_text(f"commit {commit[:10]}", git("log", "-1", "--format=%an%n%ae%n%B", commit),
                              patterns, [])
    else:
        hits = scan_files(patterns, allow, excluded)
    for hit in hits:
        print(hit, file=sys.stderr)
    if hits:
        sys.exit(f"{len(hits)} local trace(s) found")
    print("no local traces")


if __name__ == "__main__":
    main()
