#!/usr/bin/env python3
"""Check the files listed in a sha1sum-format file (`<sha1>  <path>` lines)."""

import argparse
import hashlib
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checksum_file", type=Path)
    args = parser.parse_args()

    failed = False
    for line in args.checksum_file.read_text().splitlines():
        if not line.strip():
            continue
        target, name = line.split(maxsplit=1)
        name = name.lstrip("*")
        path = Path(name)
        if not path.exists():
            print(f"{name}: MISSING", file=sys.stderr)
            failed = True
            continue
        digest = hashlib.sha1(path.read_bytes()).hexdigest()
        if digest != target:
            print(f"{name}: FAILED\nExpected: {target}\nGot:      {digest}", file=sys.stderr)
            failed = True
        else:
            print(f"{name}: OK")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
