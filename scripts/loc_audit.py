#!/usr/bin/env python3
"""Report how large each tracked source file actually is.

Raw `wc -l` badly overstates size in this repository, for two reasons
that have nothing to do with a file being monolithic:

  * **Inline tests.** House style puts `#[cfg(test)] mod tests` in the
    same file as the code it covers, and the test block is routinely
    larger than the code. `crates/appsec-cli/src/lib.rs` is 12k lines;
    most of that is tests.
  * **Dense documentation.** Doc comments here carry the reasoning
    behind a decision, often many lines per item. That is the house
    style working as intended, not something to break up.

So this reports four numbers per file and thresholds on the one that
matters:

  code     non-blank, non-comment lines outside any test block
  test     lines inside a top-level `#[cfg(test)]` item
  comment  line and block comments, and doc comments
  blank    whitespace-only

`code` is what a refactor actually has to move, so `--threshold`
applies to it. `total` is still shown, because that is the number
anybody eyeballing the file sees.

Rust gets exact treatment: a single-pass lexer strips comments and
string literals (including raw strings, which in this codebase contain
braces), and the stripped text is brace-matched to find the real extent
of every `#[cfg(test)]` item -- several files have more than one, and
some interleave test blocks with real code, so "from the first one to
end of file" would be wrong. Other languages get total/blank/comment
by prefix.

Memory: files are streamed one at a time and never held together, so
the whole run stays in a few hundred kilobytes regardless of repository
size. There is no parallelism, deliberately -- this is I/O bound, and
the machine it is written for has better uses for its RAM.

`--check` is the CI gate. It compares against `scripts/loc_baseline.json`
and fails on exactly two things:

  * a baselined file whose code count GREW -- a module already past the
    limit must not get worse;
  * a file not in the baseline that CROSSED the limit -- a new monolith.

It deliberately does not fail when a file shrinks, or when a baselined
file drops under the limit. Those are the outcome the gate exists to
encourage, and failing a build on an improvement during exactly the
refactor it is meant to support would get the gate switched off. They
are reported, with the command to lock the progress in.

Only `rust` files are gated. A generated price table is not a module and
splitting it would mean nothing; the audit still reports it.

Usage:
  scripts/loc_audit.py                      # files over the default threshold
  scripts/loc_audit.py --threshold 500
  scripts/loc_audit.py --all                # every file, no threshold
  scripts/loc_audit.py --format csv
  scripts/loc_audit.py --outline <file>     # top-level items and their spans
  scripts/loc_audit.py --check              # CI gate against the baseline
  scripts/loc_audit.py --update-baseline    # record today's counts
"""
import argparse
import json
import os
import re
import subprocess
import sys

DEFAULT_THRESHOLD = 2000

# Deliberately far below the file threshold. A file gate cannot see a
# large function inside a reasonable file: `appsec-stage-s4/src/hints.rs`
# is 1311 code lines and holds a single 833-line function, and the file
# audit reported it as unremarkable. Anything past a few hundred lines is
# worth a look even in a small file.
DEFAULT_FN_THRESHOLD = 250

# Languages whose line comments we recognize by prefix. Rust is handled
# by the lexer below instead.
LINE_COMMENT = {
    ".py": ("#",),
    ".sh": ("#",),
    ".yml": ("#",),
    ".yaml": ("#",),
    ".toml": ("#",),
    ".tf": ("#", "//"),
}

TEXT_SUFFIXES = {
    ".rs", ".py", ".sh", ".yml", ".yaml", ".toml", ".md", ".json", ".tf", ".sql",
}

KIND_BY_SUFFIX = {
    ".rs": "rust", ".py": "script", ".sh": "script", ".md": "docs",
    ".json": "data", ".sql": "data", ".toml": "config", ".yml": "config",
    ".yaml": "config", ".tf": "config",
}


def classify(rel):
    """What kind of file this is, so a 8k-line price table is not read as
    a monolithic module.

    A Rust file is `rust-test` when its path says so rather than its
    contents: an integration test under `tests/`, or a `tests.rs` /
    `tests/` module pulled in with `#[cfg(test)] mod tests;`. Those have
    no inline `#[cfg(test)]` block to attribute, so without this their
    test bodies would count as `code` and they would top the list of
    things to break up -- which is true, but a different and much lower
    priority job than splitting a module that mixes concerns.
    """
    suffix = os.path.splitext(rel)[1]
    kind = KIND_BY_SUFFIX.get(suffix, "text")
    if kind != "rust":
        return kind
    parts = rel.split("/")
    name = parts[-1]
    if "tests" in parts[:-1] or name in ("tests.rs",) or name.endswith("_tests.rs"):
        return "rust-test"
    return "rust"


class Stats:
    __slots__ = ("path", "total", "blank", "comment", "test", "code", "lang", "suspect")

    def __init__(self, path, lang):
        self.path = path
        self.lang = lang
        self.suspect = False
        self.total = self.blank = self.comment = self.test = self.code = 0

    def row(self):
        return {
            "path": self.path,
            "kind": self.lang,
            "suspect": self.suspect,
            "total": self.total,
            "code": self.code,
            "test": self.test,
            "comment": self.comment,
            "blank": self.blank,
        }


def tracked_files(root):
    """Git-tracked text files, so build output and local virtualenvs are
    never scanned -- the same choice `scripts/style_check.py` makes."""
    out = subprocess.run(
        ["git", "-C", root, "ls-files", "-z"],
        capture_output=True, text=True, check=True,
    ).stdout
    for rel in out.split("\0"):
        if not rel:
            continue
        if os.path.splitext(rel)[1] in TEXT_SUFFIXES:
            yield rel


def strip_rust(line, state):
    """Return (code_only_text, was_comment_line, new_state).

    `state` is `(block_depth, raw_hashes_or_None, in_plain_string)`
    carried across lines, since block comments and raw strings both
    span them. The returned text has comment bodies and literal
    contents removed, so the caller can brace-match it without a `{`
    inside a string or a doc comment throwing the depth off.
    """
    depth, raw_hashes, in_str = state
    kept = []
    saw_comment = False
    saw_code = False
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        nxt = line[i + 1] if i + 1 < n else ""
        if depth:
            if c == "*" and nxt == "/":
                depth -= 1
                i += 2
                continue
            if c == "/" and nxt == "*":
                depth += 1
                i += 2
                continue
            saw_comment = True
            i += 1
            continue
        if raw_hashes is not None:
            # Inside r#"..."#; ends at a quote followed by that many #.
            if c == '"' and line[i + 1:i + 1 + raw_hashes] == "#" * raw_hashes:
                i += 1 + raw_hashes
                raw_hashes = None
                continue
            i += 1
            continue
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        # Normal code.
        if c == "/" and nxt == "/":
            saw_comment = True
            break  # line comment runs to end of line
        if c == "/" and nxt == "*":
            depth = 1
            i += 2
            continue
        if c == "r" and nxt in ('"', "#"):
            j = i + 1
            hashes = 0
            while j < n and line[j] == "#":
                hashes += 1
                j += 1
            if j < n and line[j] == '"':
                raw_hashes = hashes
                saw_code = True
                i = j + 1
                continue
        if c == '"':
            in_str = True
            saw_code = True
            i += 1
            continue
        if c == "'":
            # A char literal or a lifetime, and telling them apart
            # matters: `'{'` and `'\''` both occur in this codebase, and
            # skipping only the opening quote leaves the next character
            # to be read as code -- which corrupts the brace depth for
            # `'{'`, and opens a string that never closes for `'\"'`.
            # That last one silently swallowed 1800 lines of a file.
            #
            # A char literal always has a closing quote within a few
            # characters (the longest is `'\u{10FFFF}'`); a lifetime
            # never does.
            j, close = i + 1, None
            while j < n and j <= i + 12:
                if line[j] == "\\":
                    j += 2
                    continue
                if line[j] == "'":
                    close = j
                    break
                j += 1
            saw_code = True
            i = close + 1 if close is not None else i + 1
            continue
        if not c.isspace():
            saw_code = True
        kept.append(c)
        i += 1
    return "".join(kept), (saw_comment and not saw_code), (depth, raw_hashes, in_str)


def rust_test_spans(code_lines):
    """1-based inclusive line spans of every top-level `#[cfg(test)]`
    item, found by brace-matching the comment-and-literal-stripped text.

    Handles the cases that defeat a simpler rule: a file with several
    test blocks, a test block followed by more real code, and a
    one-line `#[cfg(test)] use ...;`.
    """
    spans = []
    i, n = 0, len(code_lines)
    while i < n:
        if code_lines[i].lstrip().startswith("#[cfg(test)]"):
            start = i
            depth = 0
            opened = False
            j = i
            while j < n:
                depth += code_lines[j].count("{") - code_lines[j].count("}")
                if "{" in code_lines[j]:
                    opened = True
                if opened and depth <= 0:
                    break
                # A one-liner attribute target (`#[cfg(test)] use x;`)
                # never opens a brace.
                if not opened and j > start and code_lines[j].rstrip().endswith(";"):
                    break
                j += 1
            spans.append((start + 1, min(j, n - 1) + 1))
            i = j + 1
            continue
        i += 1
    return spans


def measure_rust(path, rel, kind="rust"):
    st = Stats(rel, kind)
    state = (0, None, False)
    code_lines, comment_flags, blank_flags = [], [], []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            st.total += 1
            stripped, is_comment, state = strip_rust(raw.rstrip("\n"), state)
            code_lines.append(stripped)
            comment_flags.append(is_comment)
            blank_flags.append(not raw.strip())
    # Self-check. A well-formed file always ends outside every comment,
    # string and raw string; ending inside one means the lexer lost
    # track, and every count for this file is then unreliable. This is
    # not hypothetical -- a mishandled `'\"'` char literal once
    # swallowed 1800 lines as string contents and hid a whole test
    # module, and the numbers looked plausible throughout.
    st.suspect = state != (0, None, False)
    if kind == "rust-test":
        # The path already says the whole file is tests.
        st.test = st.total - sum(blank_flags) - sum(comment_flags)
        st.comment = sum(comment_flags)
        st.blank = sum(blank_flags)
        return st
    in_test = [False] * st.total
    for lo, hi in rust_test_spans(code_lines):
        for k in range(lo - 1, min(hi, st.total)):
            in_test[k] = True
    for k in range(st.total):
        if blank_flags[k]:
            st.blank += 1
        elif in_test[k]:
            st.test += 1
        elif comment_flags[k]:
            st.comment += 1
        else:
            st.code += 1
    return st


def measure_generic(path, rel, kind):
    suffix = os.path.splitext(rel)[1]
    prefixes = LINE_COMMENT.get(suffix, ())
    st = Stats(rel, kind)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            st.total += 1
            line = raw.strip()
            if not line:
                st.blank += 1
            elif prefixes and line.startswith(prefixes):
                st.comment += 1
            else:
                st.code += 1
    return st


# One regex rather than a list of literal keyword prefixes, because the
# list was wrong twice and both times silently. It missed
# `pub(super) fn`, so a module freshly split out of a larger one
# reported one item instead of eighteen; and it missed `async fn`, so
# the largest function in an async pipeline crate did not appear at all.
# Both were found by running `--outline` on a file somebody already knew
# the contents of, which is not a detection mechanism. Hence
# `--selftest`.
#
# The modifier group deliberately may match nothing: `const` is both a
# function modifier and an item keyword, so for `const FOO: usize = 8;`
# the regex backtracks, consumes no modifier, and matches `const` as the
# keyword itself.
ITEM_RX = re.compile(
    r"^(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:default\s+)?"
    r"(?:(?:const|async|unsafe)\s+)*"
    r"(?:extern\s+\"[^\"]*\"\s+)?"
    # `macro_rules!` sits outside the `\b` group: `!` is already a
    # non-word character, so a trailing word boundary there can never
    # match. The selftest caught this in the very change that added it.
    r"(?:(?:fn|struct|enum|union|trait|impl|mod|const|static|type)\b"
    r"|macro_rules!)"
)

ITEM_SHAPES = [
    ("fn plain() {", True),
    ("pub fn public() {", True),
    ("pub(crate) fn crate_visible() {", True),
    ("pub(super) fn super_visible() {", True),
    ("pub(in crate::a) fn scoped() {", True),
    ("async fn bare_async() {", True),
    ("pub async fn public_async() {", True),
    ("pub(crate) async fn crate_async() {", True),
    ("const fn a_const_fn() -> usize {", True),
    ("pub const fn pub_const_fn() -> usize {", True),
    ("unsafe fn an_unsafe_fn() {", True),
    ("const FOO: usize = 8;", True),
    ("pub const BAR: &str = \"x\";", True),
    ("static LAZY: LazyLock<u8> = LazyLock::new(|| 0);", True),
    ("pub struct S {", True),
    ("pub enum E {", True),
    ("impl S {", True),
    ("impl Trait for S {", True),
    ("pub trait T {", True),
    ("mod m;", True),
    ("pub type Alias = u8;", True),
    ("macro_rules! m {", True),
    # Not items. The last three matter: a bare prefix match on "fn",
    # "const" or "struct" would take them.
    ("use std::path::Path;", False),
    ("let x = 1;", False),
    ("#[derive(Debug)]", False),
    ("}", False),
    ("", False),
    ("functional(x);", False),
    ("constant_name();", False),
    ("structure();", False),
]


def selftest():
    """Check the item matcher against the shapes this codebase uses.

    Exists because the matcher has been wrong twice, both times
    invisibly to anyone who did not already know what the file held.
    """
    bad = [(text, want) for text, want in ITEM_SHAPES
           if bool(ITEM_RX.match(text)) != want]
    for text, want in bad:
        print(f"  WRONG: {text!r} should {'match' if want else 'not match'}")
    print(f"selftest: {len(ITEM_SHAPES) - len(bad)}/{len(ITEM_SHAPES)} "
          f"item shapes correct")
    return 1 if bad else 0


def outline(path):
    """Top-level Rust items and their line spans, for finding the seams
    a file would split along. Brace-matched on stripped text, same as
    the test-span scan."""
    state = (0, None, False)
    raw_lines, code_lines = [], []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            raw_lines.append(raw.rstrip("\n"))
            stripped, _, state = strip_rust(raw_lines[-1], state)
            code_lines.append(stripped)
    items = []
    i, n = 0, len(code_lines)
    while i < n:
        text = code_lines[i]
        bare = text.lstrip()
        indented = len(text) - len(bare)
        if indented == 0 and ITEM_RX.match(bare):
            depth, opened, j = 0, False, i
            while j < n:
                depth += code_lines[j].count("{") - code_lines[j].count("}")
                if "{" in code_lines[j]:
                    opened = True
                if opened and depth <= 0:
                    break
                if not opened and code_lines[j].rstrip().endswith(";"):
                    break
                j += 1
            end = min(j, n - 1)
            items.append((i + 1, end + 1, end - i + 1, raw_lines[i].strip()[:96]))
            i = end + 1
            continue
        i += 1
    return items


BASELINE = os.path.join("scripts", "loc_baseline.json")


def load_baseline(root):
    path = os.path.join(root, BASELINE)
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"threshold": DEFAULT_THRESHOLD, "files": {}}


def function_baseline(root, threshold):
    """`"path::name" -> line span` for every function over the limit."""
    out = {}
    for rel in tracked_files(root):
        if not rel.endswith(".rs") or classify(rel) != "rust":
            continue
        try:
            for size, _s, _e, _t, name in functions_in(os.path.join(root, rel), threshold):
                out[f"{rel}::{name}"] = size
        except OSError:
            continue
    return dict(sorted(out.items()))


def write_baseline(root, threshold, rows):
    """Record every gated file currently over the limit.

    Only the offenders are recorded, deliberately. Tracking every file
    near the limit would mean re-baselining on most pull requests, and a
    gate that demands a chore on every change is a gate people route
    around. A file under the limit may grow freely until it crosses,
    which is the point at which somebody should be thinking about it
    anyway.
    """
    over = {s.path: s.code for s in sorted(rows, key=lambda s: s.path)
            if s.lang == "rust" and s.code > threshold}
    doc = {
        "_comment": (
            "Files over the code-line limit, as measured by "
            "scripts/loc_audit.py --check. Code lines only: test blocks, "
            "comments and blanks are excluded, because none of them is what "
            "a refactor has to move. Regenerate with --update-baseline."
        ),
        "threshold": threshold,
        "files": over,
        "fn_threshold": DEFAULT_FN_THRESHOLD,
        "functions": function_baseline(root, DEFAULT_FN_THRESHOLD),
    }
    path = os.path.join(root, BASELINE)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    return over


def check(root, rows, threshold):
    """Compare against the baseline. Returns the process exit code."""
    baseline = load_baseline(root)
    recorded = baseline.get("files", {})
    limit = baseline.get("threshold", threshold)
    gated = {s.path: s for s in rows if s.lang == "rust"}

    grew, arrived, shrank, cleared, vanished = [], [], [], [], []
    for path, was in sorted(recorded.items()):
        now = gated.get(path)
        if now is None:
            vanished.append(path)
        elif now.code > was:
            grew.append((path, was, now.code))
        elif now.code <= limit:
            cleared.append((path, was, now.code))
        elif now.code < was:
            shrank.append((path, was, now.code))
    for path, st in sorted(gated.items()):
        if path not in recorded and st.code > limit:
            arrived.append((path, st.code))

    for path, was, now in shrank:
        print(f"  smaller: {path}  {was} -> {now} code lines")
    for path, was, now in cleared:
        print(f"  under the limit now: {path}  {was} -> {now}")
    for path in vanished:
        print(f"  gone: {path}")
    if shrank or cleared or vanished:
        print("  lock that in: python3 scripts/loc_audit.py --update-baseline\n")

    for path, was, now in grew:
        print(f"GREW: {path}  {was} -> {now} code lines (+{now - was})")
    for path, now in arrived:
        print(f"NEW over {limit}: {path}  {now} code lines")

    # The same ratchet over functions. A file gate cannot see a large
    # function inside a reasonable file, which is how an 833-line
    # function sat in a 1311-line file unreported.
    fn_limit = baseline.get("fn_threshold", DEFAULT_FN_THRESHOLD)
    fn_recorded = baseline.get("functions", {})
    fn_now = function_baseline(root, fn_limit)
    fn_grew, fn_arrived, fn_better = [], [], []
    for key, was in sorted(fn_recorded.items()):
        now = fn_now.get(key)
        if now is None:
            fn_better.append((key, was, 0))
        elif now > was:
            fn_grew.append((key, was, now))
        elif now < was:
            fn_better.append((key, was, now))
    for key, now in sorted(fn_now.items()):
        if key not in fn_recorded:
            fn_arrived.append((key, now))
    for key, was, now in fn_better:
        print(f"  smaller: {key}  {was} -> {now or 'under the limit'} lines")
    if fn_better:
        print("  lock that in: python3 scripts/loc_audit.py --update-baseline\n")
    for key, was, now in fn_grew:
        print(f"GREW: {key}  {was} -> {now} lines (+{now - was})")
    for key, now in fn_arrived:
        print(f"NEW over {fn_limit}: {key}  {now} lines")

    if not grew and not arrived and not fn_grew and not fn_arrived:
        print(f"ok: {len(recorded)} file(s) over {limit} code lines and "
              f"{len(fn_recorded)} function(s) over {fn_limit} lines, "
              f"none grew, none joined them")
        return 0
    print(
        f"\n{len(grew) + len(arrived) + len(fn_grew) + len(fn_arrived)} "
        f"item(s) failed the size gate.\n"
        f"Split one up, or see where it would divide:\n"
        f"  python3 scripts/loc_audit.py --outline <file>\n"
        f"If the growth is genuinely the right call, record it:\n"
        f"  python3 scripts/loc_audit.py --update-baseline"
    )
    return 1


FN_RX = re.compile(
    r"^(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:(?:const|async|unsafe)\s+)*"
    r"(?:extern\s+\"[^\"]*\"\s+)?fn\b"
)


def functions_in(path, threshold):
    """Every function over `threshold` lines, including methods.

    Reports functions only, and reports them wherever they live. Both
    halves matter:

    * An `impl` block or a derive struct is a *container*. A 520-line
      `impl Validator` is thirty small methods and a 1170-line
      `pub struct Cli` is clap's surface with a doc comment per flag;
      neither is a thing to decompose, and listing them buries the
      functions that are.
    * A long method inside an `impl` is not a top-level item, so a
      top-level-only scan cannot see it at all. That is the gap this
      half closes.

    Test modules are skipped: a large `#[cfg(test)] mod tests` is the
    house style working, and the file audit counts test lines separately.
    """
    state = (0, None, False)
    raw, code = [], []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            raw.append(line.rstrip("\n"))
            stripped, _, state = strip_rust(raw[-1], state)
            code.append(stripped)

    # Lines inside a top-level `#[cfg(test)]` item are out of scope.
    in_test = [False] * len(code)
    for lo, hi in rust_test_spans(code):
        for k in range(lo - 1, min(hi, len(code))):
            in_test[k] = True

    out = []
    i, n = 0, len(code)
    while i < n:
        bare = code[i].lstrip()
        indent = len(code[i]) - len(bare)
        # Top level, or one level inside an impl/trait block.
        if in_test[i] or indent not in (0, 4) or not FN_RX.match(bare):
            i += 1
            continue
        depth, opened, j = 0, False, i
        while j < n:
            depth += code[j].count("{") - code[j].count("}")
            if "{" in code[j]:
                opened = True
            if opened and depth <= 0:
                break
            if not opened and code[j].rstrip().endswith(";"):
                break
            j += 1
        end = min(j, n - 1)
        size = end - i + 1
        if size > threshold:
            name = re.search(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", bare)
            out.append((size, i + 1, end + 1, " ".join(raw[i].split())[:72],
                        name.group(1) if name else "?"))
        i = end + 1
    return out


def big_functions(root, threshold):
    rows = []
    for rel in tracked_files(root):
        if not rel.endswith(".rs") or classify(rel) != "rust":
            continue
        try:
            for size, start, end, text, name in functions_in(
                os.path.join(root, rel), threshold
            ):
                rows.append((size, rel, start, end, text, name))
        except OSError:
            continue
    rows.sort(reverse=True)
    print(f"{'lines':>6}  {'span':>13}  item / file")
    for size, rel, start, end, bare, _name in rows:
        print(f"{size:>6}  {start:>6}-{end:<6}  {bare}")
        print(f"{'':>6}  {'':>13}  {rel}")
    print(f"\n{len(rows)} item(s) over {threshold} lines")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                    help=f"report files whose CODE lines exceed this (default {DEFAULT_THRESHOLD})")
    ap.add_argument("--all", action="store_true", help="report every file")
    ap.add_argument("--format", choices=("table", "csv", "json"), default="table")
    ap.add_argument("--sort", choices=("code", "total", "test", "path"), default="code")
    ap.add_argument("--kind", action="append", metavar="KIND",
                    help="only these kinds (rust, rust-test, docs, data, config, script); "
                         "repeatable. Default: every kind.")
    ap.add_argument("--outline", metavar="FILE",
                    help="list a Rust file's top-level items and their line spans")
    ap.add_argument("--functions", action="store_true",
                    help="report top-level items larger than --fn-threshold, across "
                         "every tracked Rust file")
    ap.add_argument("--fn-threshold", type=int, default=DEFAULT_FN_THRESHOLD,
                    help=f"line span above which an item is reported "
                         f"(default {DEFAULT_FN_THRESHOLD})")
    ap.add_argument("--selftest", action="store_true",
                    help="check the item matcher against known Rust item shapes")
    ap.add_argument("--check", action="store_true",
                    help="fail if a baselined file grew or a new file crossed the limit")
    ap.add_argument("--update-baseline", action="store_true",
                    help="rewrite scripts/loc_baseline.json from today's counts")
    args = ap.parse_args()

    if args.functions:
        return big_functions(args.root, args.fn_threshold)
    if args.selftest:
        return selftest()
    if args.outline:
        items = outline(args.outline)
        print(f"{'lines':>7}  {'span':>13}  item")
        for start, end, size, text in sorted(items, key=lambda t: -t[2]):
            print(f"{size:>7}  {start:>6}-{end:<6}  {text}")
        print(f"\n{len(items)} top-level items, "
              f"{sum(t[2] for t in items)} lines accounted for")
        return 0

    rows = []
    for rel in tracked_files(args.root):
        path = os.path.join(args.root, rel)
        kind = classify(rel)
        try:
            st = (
                measure_rust(path, rel, kind)
                if rel.endswith(".rs")
                else measure_generic(path, rel, kind)
            )
        except OSError:
            continue
        rows.append(st)

    if args.kind:
        rows = [s for s in rows if s.lang in args.kind]
    if args.update_baseline:
        over = write_baseline(args.root, args.threshold, rows)
        print(f"recorded {len(over)} file(s) over {args.threshold} code lines "
              f"in {BASELINE}")
        for path, code in sorted(over.items(), key=lambda kv: -kv[1]):
            print(f"  {code:>6}  {path}")
        return 0
    if args.check:
        return check(args.root, rows, args.threshold)

    selected = rows if args.all else [s for s in rows if s.code > args.threshold]
    key = {"code": lambda s: -s.code, "total": lambda s: -s.total,
           "test": lambda s: -s.test, "path": lambda s: s.path}[args.sort]
    selected.sort(key=key)

    if args.format == "json":
        json.dump([s.row() for s in selected], sys.stdout, indent=2)
        print()
    elif args.format == "csv":
        print("path,total,code,test,comment,blank")
        for s in selected:
            print(f"{s.path},{s.total},{s.code},{s.test},{s.comment},{s.blank}")
    else:
        print(f"{'code':>6} {'test':>6} {'comm':>6} {'blank':>6} {'total':>6}  "
              f"{'kind':<9} path")
        for s in selected:
            flag = "  !! LEXER LOST TRACK" if s.suspect else ""
            print(f"{s.code:>6} {s.test:>6} {s.comment:>6} {s.blank:>6} "
                  f"{s.total:>6}  {s.lang:<9} {s.path}{flag}")
        shown = "all files" if args.all else f"code > {args.threshold}"
        print(f"\n{len(selected)} of {len(rows)} tracked text files ({shown})")
        if selected:
            print(f"{sum(s.code for s in selected)} code lines in them, "
                  f"{sum(s.total for s in rows)} total lines tracked")
        suspect = [s.path for s in rows if s.suspect]
        if suspect:
            print(f"\nWARNING: {len(suspect)} file(s) left the lexer mid-literal, so "
                  f"their counts are unreliable:")
            for path in suspect:
                print(f"  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
