#!/usr/bin/env python3
"""Regenerate the inflate test vectors from Python's own zlib.

Run from the repository root:

    python3 crates/appsec-doctext/tests/generate_fixtures.py

A test-authoring tool, not a dependency: it writes binary fixtures plus a
Rust table of `include_bytes!`, and nothing at build or run time needs
Python. The point is that `inflate.rs` is checked against an
implementation nobody in this repository wrote -- a decoder tested only
against its own author's idea of the format proves very little.

The matrix spans all three DEFLATE block types. Level 0 forces stored
blocks, small inputs choose the fixed Huffman tables, larger and more
varied inputs force dynamic tables, and the long runs exercise
overlapping matches, where the distance is shorter than the length.
Levels are restricted on the large cases so the committed fixtures stay
small: a stored block is a stored block at any size.
"""

import pathlib
import random
import shutil
import zlib

HERE = pathlib.Path(__file__).resolve().parent
SUPPORT = HERE / "support"
FIXTURES = SUPPORT / "fixtures"

ALL_LEVELS = (0, 1, 6, 9)
NO_STORED = (1, 6, 9)
ONE = (6,)


def raw_deflate(data: bytes, level: int) -> bytes:
    # wbits=-15 is a raw stream: no zlib header and no trailing
    # checksum, which is exactly what a ZIP entry holds.
    c = zlib.compressobj(level, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def lorem(size: int) -> bytes:
    words = (
        b"the gateway terminates tls and forwards to the payments service "
        b"which reaches the cards database over a private subnet "
        b"authentication is enforced at the edge by the api gateway "
    )
    out = bytearray()
    while len(out) < size:
        out += words
    return bytes(out[:size])


def cases():
    rng = random.Random(20261116)
    # (name, plaintext, levels)
    yield "empty", b"", ALL_LEVELS
    yield "one_byte", b"a", ALL_LEVELS
    yield "short_text", b"hello world", ALL_LEVELS
    yield "no_repeats", b"abcdefghijklmnopqrstuvwxyz", ALL_LEVELS
    # A long run encodes as a short match repeated, so the decoder must
    # handle a distance smaller than the length it is copying.
    yield "long_run_of_one_byte", b"a" * 1000, ALL_LEVELS
    yield "two_byte_cycle", b"ab" * 500, ALL_LEVELS
    yield "three_byte_cycle", b"xyz" * 400, ALL_LEVELS
    yield "every_byte_value", bytes(range(256)), ALL_LEVELS
    # Incompressible, so the compressor falls back to stored blocks even
    # at a high level.
    yield "random_2k", bytes(rng.randrange(256) for _ in range(2048)), ALL_LEVELS
    # Realistic for this crate's actual job.
    yield "ooxml_like", (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        b"<w:body><w:p><w:r><w:t>Architecture overview</w:t></w:r></w:p>"
        b"<w:p><w:r><w:t>The service is internet facing.</w:t></w:r></w:p>"
        b"</w:body></w:document>"
    ), ALL_LEVELS
    yield "every_byte_value_repeated", bytes(range(256)) * 8, NO_STORED
    yield "lorem_4k", lorem(4096), NO_STORED
    # Big enough to need several blocks and a full Huffman alphabet.
    yield "lorem_32k", lorem(32768), ONE
    # Matches that reach back across the 32 KiB window.
    yield "window_crossing", lorem(20000) + b"UNIQUE-MARKER" + lorem(20000), ONE
    # The compressible-to-nothing case: the shape of a zip bomb, used to
    # prove the output cap refuses it and that a generous cap does not.
    yield "zeros_64k", b"\x00" * 65536, ONE


def main() -> None:
    if FIXTURES.exists():
        shutil.rmtree(FIXTURES)
    FIXTURES.mkdir(parents=True)
    # Under `tests/support/` rather than `tests/` directly: cargo treats
    # every `.rs` file immediately inside `tests/` as its own test
    # binary, and a table of fixtures is not a test.

    rows = []
    plain_bytes = 0
    comp_bytes = 0
    for name, plain, levels in cases():
        plain_path = FIXTURES / f"{name}.plain"
        plain_path.write_bytes(plain)
        plain_bytes += len(plain)
        for level in levels:
            compressed = raw_deflate(plain, level)
            comp_path = FIXTURES / f"{name}.level{level}.deflate"
            comp_path.write_bytes(compressed)
            comp_bytes += len(compressed)
            rows.append((name, level))

    # No comments in the emitted Rust: this repository does not carry
    # them in `.rs` files, and a generator that re-added a header on
    # every run would undo that silently. The provenance lives in this
    # script's own docstring instead.
    out = [
        "pub struct Vector {",
        "    pub name: &'static str,",
        "    pub level: i32,",
        "    pub compressed: &'static [u8],",
        "    pub plain: &'static [u8],",
        "}",
        "",
        "#[rustfmt::skip]",
        "pub const VECTORS: &[Vector] = &[",
    ]
    for name, level in rows:
        out.append("    Vector {")
        out.append(f'        name: "{name}_level{level}",')
        out.append(f"        level: {level},")
        out.append(
            f'        compressed: include_bytes!("fixtures/{name}.level{level}.deflate"),'
        )
        out.append(f'        plain: include_bytes!("fixtures/{name}.plain"),')
        out.append("    },")
    out.append("];")
    out.append("")

    target = SUPPORT / "inflate_vectors.rs"
    target.write_text("\n".join(out), encoding="utf-8")
    print(f"wrote {target} with {len(rows)} vectors")
    print(f"  plaintext fixtures  {plain_bytes:,} bytes")
    print(f"  compressed fixtures {comp_bytes:,} bytes")


if __name__ == "__main__":
    main()
