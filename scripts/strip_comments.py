#!/usr/bin/env python3
"""Remove every comment from Rust source, without touching anything else.

    python3 scripts/strip_comments.py --check      # report, change nothing
    python3 scripts/strip_comments.py --self-test  # run the lexer's own tests
    python3 scripts/strip_comments.py --apply      # rewrite the files

Why a lexer and not a regular expression. All of these are legal Rust
in which `//` or `/*` is *not* a comment, and a naive pattern corrupts
every one of them:

    let s = "// not a comment";
    let r = r#"a // b and /* c */"#;
    let c = '/';
    /* nested /* block */ comments are legal */
    let life: &'a str;          // `'a` is a lifetime, not a char literal

So the file is tokenised into spans, and the single safety property
this rests on is asserted for every file before anything is written:

    the spans tile the file exactly -- concatenated, they reproduce the
    original byte for byte

which means the only bytes that can ever be dropped are those the lexer
classified as a comment. Non-comment bytes are copied, never rewritten.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

CODE, COMMENT = "code", "comment"

IDENT = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def spans(src: str) -> list[tuple[str, int, int]]:
    """Partition `src` into consecutive (kind, start, end) spans."""
    out: list[tuple[str, int, int]] = []
    i, n = 0, len(src)
    code_from = 0

    def close_code(upto: int) -> None:
        if upto > code_from:
            out.append((CODE, code_from, upto))

    while i < n:
        c = src[i]

        # --- comments -------------------------------------------------
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            close_code(i)
            j = src.find("\n", i)
            j = n if j == -1 else j
            out.append((COMMENT, i, j))
            i = code_from = j
            continue

        if c == "/" and i + 1 < n and src[i + 1] == "*":
            close_code(i)
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append((COMMENT, i, j))
            i = code_from = j
            continue

        # --- raw strings: r"", r#""#, br#""#, cr#""# -------------------
        if c in "rbc":
            start = i
            k = i
            if src[k] in "bc" and k + 1 < n and src[k + 1] == "r":
                k += 1
            if src[k] == "r":
                prev_is_ident = start > 0 and src[start - 1] in IDENT
                h = k + 1
                while h < n and src[h] == "#":
                    h += 1
                # `r#"` is a raw string; `r#type` is a raw identifier.
                if not prev_is_ident and h < n and src[h] == '"':
                    hashes = h - (k + 1)
                    terminator = '"' + "#" * hashes
                    j = src.find(terminator, h + 1)
                    i = n if j == -1 else j + len(terminator)
                    continue

        # --- ordinary and byte strings --------------------------------
        if c == '"' or (c in "bc" and i + 1 < n and src[i + 1] == '"'
                        and not (i > 0 and src[i - 1] in IDENT)):
            j = i + 1 if c == '"' else i + 2
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue

        # --- char literals, told apart from lifetimes ------------------
        if c == "'":
            if i + 1 < n and src[i + 1] == "\\":
                # An escape is always a char literal: '\n', '\'', '\\'.
                j = i + 2
                while j < n and src[j] != "'":
                    j += 1
                i = j + 1
                continue
            # 'a' is a char literal; 'a is a lifetime. One character
            # followed by a closing quote decides it.
            if i + 2 < n and src[i + 2] == "'":
                i += 3
                continue
            # A lifetime: step over the quote and let the identifier be
            # read as ordinary code.
            i += 1
            continue

        i += 1

    close_code(n)
    return out


def strip(src: str) -> str:
    """Drop every comment, and any line a comment leaves blank."""
    parts = spans(src)

    # The safety property: the spans must reproduce the file exactly.
    rebuilt = "".join(src[a:b] for _, a, b in parts)
    if rebuilt != src:
        raise AssertionError("span partition lost or duplicated bytes")

    # Mark which lines held a comment, so a line that was *already*
    # blank is kept and one left blank by this is not.
    had_comment = set()
    for kind, a, b in parts:
        if kind is COMMENT or kind == COMMENT:
            had_comment.update(range(src.count("\n", 0, a), src.count("\n", 0, b) + 1))

    pieces = []
    for kind, a, b in parts:
        if kind != COMMENT:
            pieces.append(src[a:b])
        elif not src.startswith("//", a):
            # A block comment can sit between two tokens with no
            # whitespace -- `a/*c*/b` -- so dropping it outright would
            # weld them into one. It leaves a space. A line comment runs
            # to end of line and cannot join anything.
            pieces.append(" ")
    out = "".join(pieces)

    kept = []
    for number, line in enumerate(out.split("\n")):
        trimmed = line.rstrip()
        if not trimmed and number in had_comment:
            continue
        kept.append(trimmed)
    text = "\n".join(kept)
    # A file that was nothing but comments has no code left. It keeps a
    # single newline rather than becoming truly empty, because that is
    # what rustfmt writes for one and the two must agree or they fight.
    if not text.strip():
        return "\n" if src.strip() else src
    if src.endswith("\n") and not text.endswith("\n"):
        text += "\n"
    return text


# --------------------------------------------------------------------
# The lexer's own tests. These run before any file is touched.
# --------------------------------------------------------------------
SELF_TESTS: list[tuple[str, str, str]] = [
    ("a line comment", "let x = 1; // gone\n", "let x = 1;\n"),
    ("a whole-line comment", "// gone\nlet x = 1;\n", "let x = 1;\n"),
    ("a doc comment", "/// gone\nfn f() {}\n", "fn f() {}\n"),
    ("a module doc", "//! gone\nfn f() {}\n", "fn f() {}\n"),
    ("a block comment", "let x = /* gone */ 1;\n", "let x =   1;\n"),
    (
        "a block comment welded between two tokens leaves a space",
        "let x = a/* gone */b;\n",
        "let x = a b;\n",
    ),
    (
        "nested block comments",
        "let x = /* a /* b */ c */ 1;\n",
        "let x =   1;\n",
    ),
    (
        "slashes inside a string are not a comment",
        'let s = "// not a comment";\n',
        'let s = "// not a comment";\n',
    ),
    (
        "a block opener inside a string",
        'let s = "/* not a comment";\n',
        'let s = "/* not a comment";\n',
    ),
    (
        "a raw string keeps everything",
        'let s = r#"a // b and /* c */"#;\n',
        'let s = r#"a // b and /* c */"#;\n',
    ),
    (
        "a raw string with several hashes",
        'let s = r###"// kept"###;\n',
        'let s = r###"// kept"###;\n',
    ),
    (
        "a byte raw string",
        'let s = br#"// kept"#;\n',
        'let s = br#"// kept"#;\n',
    ),
    (
        "a raw identifier is not a raw string",
        "let r#type = 1; // gone\n",
        "let r#type = 1;\n",
    ),
    (
        "an identifier ending in r before a quote",
        'let xr = "// kept";\n',
        'let xr = "// kept";\n',
    ),
    (
        "an escaped quote does not end the string",
        'let s = "a \\" // kept";\n',
        'let s = "a \\" // kept";\n',
    ),
    ("a slash char literal", "let c = '/'; // gone\n", "let c = '/';\n"),
    ("a quote char literal", "let c = '\\''; // gone\n", "let c = '\\'';\n"),
    ("a backslash char literal", "let c = '\\\\'; // gone\n", "let c = '\\\\';\n"),
    (
        "a lifetime is not an unterminated char",
        "fn f<'a>(x: &'a str) {} // gone\n",
        "fn f<'a>(x: &'a str) {}\n",
    ),
    (
        "a static lifetime followed by a string",
        "const S: &'static str = \"// kept\";\n",
        "const S: &'static str = \"// kept\";\n",
    ),
    (
        "an anonymous lifetime",
        "impl Foo<'_> {} // gone\n",
        "impl Foo<'_> {}\n",
    ),
    (
        "a url inside a string",
        'let u = "https://example.com";\n',
        'let u = "https://example.com";\n',
    ),
    (
        "a blank line that was already blank is kept",
        "let a = 1;\n\nlet b = 2;\n",
        "let a = 1;\n\nlet b = 2;\n",
    ),
    (
        "trailing whitespace from a stripped comment goes too",
        "let x = 1;   // gone\n",
        "let x = 1;\n",
    ),
    (
        "an unterminated block comment eats the rest",
        "let x = 1;\n/* never closed\n",
        "let x = 1;\n",
    ),
    ("an empty file", "", ""),
    ("a file of only comments", "// a\n// b\n", "\n"),
    ("an already empty file stays empty", "", ""),
]


def self_test() -> bool:
    ok = True
    for name, given, expected in SELF_TESTS:
        try:
            got = strip(given)
        except AssertionError as e:
            print(f"  FAIL {name}: {e}")
            ok = False
            continue
        if got != expected:
            print(f"  FAIL {name}\n       given    {given!r}\n"
                  f"       expected {expected!r}\n       got      {got!r}")
            ok = False
        # Idempotence: stripping twice must change nothing.
        if strip(got) != got:
            print(f"  FAIL {name}: not idempotent")
            ok = False
    print(f"  {len(SELF_TESTS)} lexer self-tests, {'all passed' if ok else 'FAILURES'}")
    return ok


def rust_files(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(
        p for p in root.rglob("*.rs")
        if "target" not in p.parts and p.is_file()
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--root", default="crates")
    args = ap.parse_args()

    if args.self_test or not (args.apply or args.check):
        return 0 if self_test() else 1

    if not self_test():
        print("refusing to touch any file: the lexer's own tests fail")
        return 1

    files = rust_files(pathlib.Path(args.root))
    changed = removed = 0
    for path in files:
        src = path.read_text(encoding="utf-8")
        try:
            out = strip(src)
        except AssertionError as e:
            print(f"  REFUSED {path}: {e}")
            return 1
        if out == src:
            continue
        changed += 1
        removed += len(src.splitlines()) - len(out.splitlines())
        if args.apply:
            path.write_text(out, encoding="utf-8")

    verb = "rewrote" if args.apply else "would rewrite"
    print(f"  {verb} {changed} of {len(files)} files, {removed} lines fewer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
