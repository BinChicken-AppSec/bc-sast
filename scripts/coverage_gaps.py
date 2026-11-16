#!/usr/bin/env python3
"""List what a coverage gate missed, from `cargo llvm-cov report --json`.

CI's coverage gates write lcov and fail with nothing but an exit code,
and the summary table names a file, not the function in it that never
ran. This prints every file below 100% of functions or lines, then the
start line of each function none of whose instantiations ran.

Usage: coverage_gaps.py <llvm-cov-export.json>
"""

import json
import sys


def main(path: str) -> None:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)["data"][0]

    short = set()
    for entry in data["files"]:
        functions = entry["summary"]["functions"]
        lines = entry["summary"]["lines"]
        if functions["covered"] < functions["count"] or lines["covered"] < lines["count"]:
            short.add(entry["filename"])
            print(
                f"{entry['filename']}: functions {functions['covered']}/{functions['count']}, "
                f"lines {lines['covered']}/{lines['count']}"
            )

    # A generic function has one record per instantiation; it counts as
    # covered when any of them ran.
    ran = {}
    for function in data["functions"]:
        where = (function["filenames"][0], function["regions"][0][0])
        ran[where] = ran.get(where, False) or function["count"] > 0
    for (filename, line), hit in sorted(ran.items()):
        if not hit and filename in short:
            print(f"never ran: the function starting at {filename}:{line}")


if __name__ == "__main__":
    main(sys.argv[1])
