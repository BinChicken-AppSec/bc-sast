#!/usr/bin/env python3
"""Line and function coverage from lcov files, as percentages.

Every coverage gate in CI writes lcov and nothing else, so a failing gate
names no number: you learn that 99.37% was not met, not what was actually
measured. Re-running the gate to find out costs another full coverage
pass, and on a toolchain bump there are twelve of them to re-tune.

The lcov files are already on disk by then. This reads them.

Usage: lcov_summary.py lcov-*.info
"""

from __future__ import annotations

import sys
from pathlib import Path


def summarize(path: Path) -> tuple[int, int, int, int]:
    """(lines_found, lines_hit, functions_found, functions_hit)."""
    lf = lh = fnf = fnh = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, _, value = line.partition(":")
        if not value.isdigit():
            continue
        n = int(value)
        if key == "LF":
            lf += n
        elif key == "LH":
            lh += n
        elif key == "FNF":
            fnf += n
        elif key == "FNH":
            fnh += n
    return lf, lh, fnf, fnh


def pct(hit: int, found: int) -> str:
    # A file with nothing to measure is reported as such rather than as
    # 0% or 100%, either of which would read as a verdict.
    return "n/a" if found == 0 else f"{hit / found * 100:.3f}%"


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv[1:]]
    if not paths:
        print("usage: lcov_summary.py lcov-*.info", file=sys.stderr)
        return 2
    missing = [p for p in paths if not p.is_file()]
    for p in missing:
        print(f"  {p.name}: not written (its gate may not have run)")
    print(f"  {'file':<34}{'lines':>12}{'functions':>12}   (hit/found)")
    for p in sorted(paths):
        if not p.is_file():
            continue
        lf, lh, fnf, fnh = summarize(p)
        print(
            f"  {p.name:<34}{pct(lh, lf):>12}{pct(fnh, fnf):>12}"
            f"   {lh}/{lf} lines, {fnh}/{fnf} fns"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
