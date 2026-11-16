#!/usr/bin/env python3
"""Check tracked text for house style before it is published.

This project writes US English and avoids typographic characters that
signal machine-generated prose. The rules are small, but they are easy to
regress a few words at a time, and the repository is a public work
sample, so the check is mechanical rather than a matter of review
attention.

Two categories are reported:

  british   a British spelling in prose. The word list is deliberately
            explicit rather than a clever -ise/-ize rule, because an
            algorithmic rule rewrites identifiers, quoted output and
            proper nouns that must not change.

  typography  em-dash, en-dash, a prose arrow, or an ellipsis.

A quoted line from an external tool may legitimately contain any of
these. The baseline is therefore a number to hold steady rather than
drive to zero: compare against it, and account for any increase.

Usage: python3 scripts/style_check.py [root] [glob ...]
Defaults to the current directory and '*.md'. Operates on git-tracked
files only, so build output and local virtualenvs are never scanned.
"""
import os
import re
import subprocess
import sys

BRITISH = r"""behaviour|behaviours|behavioural|colour|coloured|colours|licence|licences|
prioritise|prioritised|prioritises|prioritising|recognise|recognised|recognises|recognising|
analyse|analysed|analyses|analysing|organise|organised|organises|organising|
authorisation|authorise|authorised|authorises|deserialisation|deserialise|deserialised|
deserialises|serialisation|serialise|serialised|sanitisation|sanitise|sanitised|sanitises|
neutralise|neutralised|neutralises|summarise|summarised|summarises|minimisation|minimise|
minimised|normalise|normalised|normalises|normalising|initialise|initialised|initialises|
optimise|optimised|optimises|categorise|categorised|utilise|utilised|customise|customised|
artefact|artefacts|labelled|labelling|modelled|modelling|cancelled|cancelling"""
BRITISH_RX = re.compile(r"\b(" + BRITISH.replace("\n", "") + r")\b", re.IGNORECASE)

TYPOGRAPHY = {
    "—": "em-dash",
    "–": "en-dash",
    "→": "arrow",
    "…": "ellipsis",
}


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    pats = sys.argv[2:] or ["*.md"]
    listing = subprocess.run(
        ["git", "-C", root, "ls-files"] + pats,
        capture_output=True, text=True)
    if listing.returncode != 0:
        print(f"error: {root} is not a git repository, so there is nothing "
              f"tracked to check", file=sys.stderr)
        return 2
    files = listing.stdout.split()

    issues = 0
    for rel in files:
        path = os.path.join(root, rel)
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            match = BRITISH_RX.search(line)
            if match:
                print(f"{rel}:{lineno}: british '{match.group(1)}': {line.strip()[:100]}")
                issues += 1
            for char, name in TYPOGRAPHY.items():
                if char in line:
                    print(f"{rel}:{lineno}: {name}: {line.strip()[:100]}")
                    issues += 1
                    break

    print(f"\nchecked {len(files)} files; {issues} issue(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
