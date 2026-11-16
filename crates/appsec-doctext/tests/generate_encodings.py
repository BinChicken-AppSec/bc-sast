#!/usr/bin/env python3
"""Regenerate `src/pdf/tables.rs`: the PDF character encoding tables.

Run from the repository root:

    python3 crates/appsec-doctext/tests/generate_encodings.py

A code generator, not a dependency: it writes a Rust source file of
constants which is committed, and nothing at build or run time needs
Python.

Why generated. `WinAnsiEncoding` is `cp1252` and `MacRomanEncoding` is
`mac_roman`, each with the few deliberate differences the PDF
specification lists. Typing two hundred characters by hand is how one
of them ends up quietly wrong in a table nobody re-reads, and a wrong
character in a text extractor is confident mojibake rather than a
visible failure. The accented glyph names are composed from their base
letter and combining mark and normalised, for the same reason.
"""

import pathlib
import unicodedata

HERE = pathlib.Path(__file__).resolve().parent
TARGET = HERE.parent / "src" / "pdf" / "tables.rs"


def rust_char(c: str) -> str:
    return "'\\u{%04x}'" % ord(c)


def rust_str(s: str) -> str:
    return '"' + "".join("\\u{%04x}" % ord(c) for c in s) + '"'


def high_table(codec: str, fixups: dict) -> str:
    out = []
    for b in range(0x80, 0x100):
        if b in fixups:
            out.append(fixups[b])
            continue
        try:
            out.append(bytes([b]).decode(codec))
        except Exception:
            out.append("�")
    return "".join(out)


def glyph_names() -> dict:
    pairs = {
        "space": " ", "exclam": "!", "quotedbl": '"', "numbersign": "#",
        "dollar": "$", "percent": "%", "ampersand": "&", "quotesingle": "'",
        "quoteright": "’", "quoteleft": "‘", "parenleft": "(",
        "parenright": ")", "asterisk": "*", "plus": "+", "comma": ",",
        "hyphen": "-", "period": ".", "slash": "/", "zero": "0", "one": "1",
        "two": "2", "three": "3", "four": "4", "five": "5", "six": "6",
        "seven": "7", "eight": "8", "nine": "9", "colon": ":",
        "semicolon": ";", "less": "<", "equal": "=", "greater": ">",
        "question": "?", "at": "@", "bracketleft": "[", "backslash": "\\",
        "bracketright": "]", "asciicircum": "^", "underscore": "_",
        "grave": "`", "braceleft": "{", "bar": "|", "braceright": "}",
        "asciitilde": "~", "quotedblleft": "“",
        "quotedblright": "”", "quotedblbase": "„",
        "quotesinglbase": "‚", "guilsinglleft": "‹",
        "guilsinglright": "›", "guillemotleft": "«",
        "guillemotright": "»", "endash": "–", "emdash": "—",
        "bullet": "•", "ellipsis": "…", "dagger": "†",
        "daggerdbl": "‡", "perthousand": "‰", "section": "§",
        "paragraph": "¶", "periodcentered": "·",
        "currency": "¤", "yen": "¥", "sterling": "£",
        "cent": "¢", "euro": "€", "Euro": "€",
        "copyright": "©", "registered": "®",
        "trademark": "™", "degree": "°", "plusminus": "±",
        "multiply": "×", "divide": "÷", "minus": "−",
        "fraction": "⁄", "onehalf": "½", "onequarter": "¼",
        "threequarters": "¾", "exclamdown": "¡",
        "questiondown": "¿", "logicalnot": "¬",
        "brokenbar": "¦", "dieresis": "¨", "macron": "¯",
        "acute": "´", "cedilla": "¸", "ordfeminine": "ª",
        "ordmasculine": "º", "germandbls": "ß", "ae": "æ",
        "AE": "Æ", "oe": "œ", "OE": "Œ", "oslash": "ø",
        "Oslash": "Ø", "eth": "ð", "Eth": "Ð",
        "thorn": "þ", "Thorn": "Þ", "dotlessi": "ı",
        "fi": "ﬁ", "fl": "ﬂ", "nbspace": " ", "softhyphen": "-",
    }
    accents = {
        "acute": "́", "grave": "̀", "circumflex": "̂",
        "dieresis": "̈", "tilde": "̃", "ring": "̊",
        "cedilla": "̧", "caron": "̌", "breve": "̆",
        "macron": "̄", "ogonek": "̨", "dotaccent": "̇",
        "hungarumlaut": "̋",
    }
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for letter in letters:
        for name, mark in accents.items():
            composed = unicodedata.normalize("NFC", letter + mark)
            if len(composed) == 1:
                pairs.setdefault(letter + name, composed)
        pairs.setdefault(letter, letter)
    return pairs


def main() -> None:
    # PDF's WinAnsiEncoding differs from cp1252 at two codes, and both
    # differences are what a text extractor wants anyway: a plain space
    # rather than a non-breaking one, and a plain hyphen rather than a
    # soft one.
    win = high_table("cp1252", {0xA0: " ", 0xAD: "-"})
    # PDF's MacRomanEncoding has currency at 0xDB where Apple's later
    # revision, which Python implements, has the euro sign.
    mac = high_table("mac_roman", {0xDB: "¤"})
    names = sorted(glyph_names().items())

    # No comments in the emitted Rust: this repository does not carry
    # them in `.rs` files, and a generator that re-added them on every
    # run would undo that silently. What each table is, and why it is
    # generated rather than typed, is in this script's own docstring.
    lines = [
        f"pub const WIN_ANSI_HIGH: &str = {rust_str(win)};",
        "",
        f"pub const MAC_ROMAN_HIGH: &str = {rust_str(mac)};",
        "",
        "#[rustfmt::skip]",
        "pub const GLYPH_NAMES: &[(&str, char)] = &[",
    ]
    row = "   "
    for name, ch in names:
        item = f' ("{name}", {rust_char(ch)}),'
        if len(row) + len(item) > 94:
            lines.append(row)
            row = "   "
        row += item
    if row.strip():
        lines.append(row)
    lines.append("];")
    lines.append("")

    TARGET.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {TARGET}")
    print(f"  WinAnsi {len(win)} chars, MacRoman {len(mac)} chars, {len(names)} glyph names")


if __name__ == "__main__":
    main()
