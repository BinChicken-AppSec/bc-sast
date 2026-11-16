#!/usr/bin/env python3
"""Build the document fixtures: ordinary OOXML files and hostile ones.

Run from the repository root:

    python3 crates/appsec-doctext/tests/generate_documents.py

A test-authoring tool, not a dependency. Python's `zipfile` writes the
well-formed archives; the ones it will not write -- an encrypted entry,
an unsupported compression method, a ZIP64 sentinel -- are assembled
byte by byte below, because a reader that has never been shown a hostile
archive has not been tested against one.
"""

import pathlib
import shutil
import struct
import zipfile
import zlib

HERE = pathlib.Path(__file__).resolve().parent
DOCS = HERE / "support" / "docs"

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
S_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"

CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
)

DOCUMENT_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:document xmlns:w="{W_NS}"><w:body>'
    "<w:p><w:r><w:t>Architecture overview</w:t></w:r></w:p>"
    '<w:p><w:r><w:t xml:space="preserve">The service is </w:t>'
    "<w:t>internet facing</w:t></w:r></w:p>"
    "<w:p><w:r><w:t>Tabs:</w:t><w:tab/><w:t>after tab</w:t></w:r></w:p>"
    "<w:p><w:r><w:t>Line one</w:t><w:br/><w:t>Line two</w:t></w:r></w:p>"
    "<w:p><w:r><w:t>Entities: &lt;tag&gt; &amp; &#65;&#x42;</w:t></w:r></w:p>"
    "<w:p><w:r><w:t>Unicode: café — 日本語</w:t></w:r></w:p>"
    "<!-- a comment, which is not text -->"
    "<w:p><w:r><w:t><![CDATA[raw <angle> brackets]]></w:t></w:r></w:p>"
    "</w:body></w:document>"
)

FOOTNOTES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<w:footnotes xmlns:w="{W_NS}">'
    "<w:footnote><w:p><w:r><w:t>A footnote about PCI scope.</w:t></w:r></w:p></w:footnote>"
    "</w:footnotes>"
)

SHARED_STRINGS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<sst xmlns="{S_NS}">'
    "<si><t>Service</t></si><si><t>Exposure</t></si>"
    "<si><t>payments-api</t></si><si><t>internet</t></si>"
    "</sst>"
)

SHEET_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f'<worksheet xmlns="{S_NS}"><sheetData>'
    '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>'
    '<row r="2"><c r="A2" t="inlineStr"><is><t>inline cell</t></is></c></row>'
    "</sheetData></worksheet>"
)


def slide(text: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<p:sld xmlns:p="{P_NS}" xmlns:a="{A_NS}"><p:cSld><p:spTree>'
        f"<p:sp><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp>"
        "</p:spTree></p:cSld></p:sld>"
    )


# A fixed timestamp for every entry.
#
# `writestr` with a bare name stamps each entry with the current time,
# which would make the committed fixtures different bytes on every run.
# Nothing here depends on the date, and a fixture that churns cannot be
# regenerated and diffed to check the generator still produces it.
FIXED_DATE = (2026, 11, 16, 0, 0, 0)


def write_zip(path: pathlib.Path, members, compression=zipfile.ZIP_DEFLATED, comment=b""):
    with zipfile.ZipFile(path, "w", compression) as z:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            info.compress_type = compression
            z.writestr(info, data)
        if comment:
            z.comment = comment


def hand_built_zip(name: bytes, payload: bytes, *, flags=0, method=0, zip64_sentinel=False):
    """One entry, assembled by hand so flags and method can be anything.

    `zipfile` will not write an encrypted entry or a bogus method, and
    those are exactly the archives a reader has to refuse.
    """
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    size = 0xFFFFFFFF if zip64_sentinel else len(payload)
    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, flags, method, 0, 0, crc, size, size, len(name), 0
    ) + name
    data = local + payload
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50, 20, 20, flags, method, 0, 0, crc, size, size,
        len(name), 0, 0, 0, 0, 0, 0,
    ) + name
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(data), 0
    )
    return data + central + eocd


def main() -> None:
    if DOCS.exists():
        shutil.rmtree(DOCS)
    DOCS.mkdir(parents=True)

    # --- ordinary documents -------------------------------------------
    write_zip(DOCS / "ordinary.docx", [
        ("[Content_Types].xml", CONTENT_TYPES),
        ("word/document.xml", DOCUMENT_XML),
        ("word/footnotes.xml", FOOTNOTES_XML),
        ("word/styles.xml", "<styles/>"),
    ])
    # The same document stored rather than deflated, so the stored path
    # is exercised end to end.
    write_zip(DOCS / "stored.docx", [
        ("[Content_Types].xml", CONTENT_TYPES),
        ("word/document.xml", DOCUMENT_XML),
    ], compression=zipfile.ZIP_STORED)
    # A trailing comment, so the backward search for the
    # end-of-central-directory record has to work past something.
    write_zip(DOCS / "commented.docx", [
        ("[Content_Types].xml", CONTENT_TYPES),
        ("word/document.xml", DOCUMENT_XML),
    ], comment=b"x" * 3000)

    write_zip(DOCS / "ordinary.xlsx", [
        ("[Content_Types].xml", CONTENT_TYPES),
        ("xl/sharedStrings.xml", SHARED_STRINGS),
        ("xl/worksheets/sheet1.xml", SHEET_XML),
    ])

    # Numbered out of lexicographic order on purpose: slide10 must come
    # last, not second.
    write_zip(DOCS / "ordinary.pptx", [
        ("[Content_Types].xml", CONTENT_TYPES),
        ("ppt/slides/slide1.xml", slide("First slide")),
        ("ppt/slides/slide2.xml", slide("Second slide")),
        ("ppt/slides/slide10.xml", slide("Tenth slide")),
    ])

    # A part that is present and well-formed but holds no text, so the
    # "this part contributed nothing" path is exercised.
    write_zip(DOCS / "empty_part.docx", [
        ("word/document.xml", DOCUMENT_XML),
        ("word/footnotes.xml",
         f'<w:footnotes xmlns:w="{W_NS}"><w:footnote><w:p/></w:footnote></w:footnotes>'),
    ])

    # --- hostile and malformed ----------------------------------------
    # A document type definition, which must be refused outright.
    write_zip(DOCS / "doctype.docx", [
        ("word/document.xml",
         '<?xml version="1.0"?><!DOCTYPE w:document>'
         f'<w:document xmlns:w="{W_NS}"><w:body>'
         "<w:p><w:r><w:t>text</w:t></w:r></w:p></w:body></w:document>"),
    ])
    # The classic entity-expansion bomb. Refused at the DOCTYPE, before
    # any entity is even read.
    write_zip(DOCS / "billion_laughs.docx", [
        ("word/document.xml",
         '<?xml version="1.0"?>'
         '<!DOCTYPE lolz [<!ENTITY lol "lol">'
         '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
         '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
         ']>'
         f'<w:document xmlns:w="{W_NS}"><w:body><w:p><w:r><w:t>&lol3;</w:t>'
         "</w:r></w:p></w:body></w:document>"),
    ])
    # A part that decompresses to far more than any caller would allow.
    write_zip(DOCS / "bomb.docx", [
        ("word/document.xml",
         f'<w:document xmlns:w="{W_NS}"><w:body><w:p><w:r><w:t>'
         + "A" * (8 * 1024 * 1024)
         + "</w:t></w:r></w:p></w:body></w:document>"),
    ])
    # Deeply nested elements, to meet the depth bound.
    depth = 2000
    write_zip(DOCS / "deep.docx", [
        ("word/document.xml",
         f'<w:document xmlns:w="{W_NS}">'
         + ("<w:x>" * depth)
         + "<w:t>buried</w:t>"
         + ("</w:x>" * depth)
         + "</w:document>"),
    ])
    # A valid archive with none of the parts the format needs.
    write_zip(DOCS / "no_parts.docx", [
        ("[Content_Types].xml", CONTENT_TYPES),
        ("word/styles.xml", "<styles/>"),
    ])
    # A compression method that is neither stored nor deflate.
    write_zip(DOCS / "bzip2.docx", [
        ("word/document.xml", DOCUMENT_XML),
    ], compression=zipfile.ZIP_BZIP2)

    # Not an archive at all.
    (DOCS / "not_a_zip.docx").write_bytes(b"%PDF-1.7\nthis is not a zip\n" * 10)
    # Truncated halfway, so the central directory is gone.
    whole = (DOCS / "ordinary.docx").read_bytes()
    (DOCS / "truncated.docx").write_bytes(whole[: len(whole) // 2])

    # Hand-built: the encryption flag set (bit 0).
    (DOCS / "encrypted.docx").write_bytes(
        hand_built_zip(b"word/document.xml", b"ciphertext", flags=1)
    )
    # Hand-built: a ZIP64 sentinel where a size should be.
    (DOCS / "zip64.docx").write_bytes(
        hand_built_zip(b"word/document.xml", b"x", zip64_sentinel=True)
    )
    # Hand-built: a stored entry whose CRC does not match its bytes.
    bad = hand_built_zip(b"word/document.xml", b"<w:document/>")
    bad = bytearray(bad)
    bad[14] ^= 0xFF  # the local header's CRC field
    central_crc = bad.find(struct.pack("<I", 0x02014B50)) + 16
    bad[central_crc] ^= 0xFF
    (DOCS / "bad_crc.docx").write_bytes(bytes(bad))

    # One small, well-formed document for `appsec-mcp`, which needs a
    # real `.docx` to test that its fetch path reaches the extractor at
    # all. It does not re-test extraction; that is this crate's job.
    mcp_support = HERE.parents[1] / "appsec-mcp" / "tests" / "support"
    mcp_support.mkdir(parents=True, exist_ok=True)
    write_zip(mcp_support / "minimal.docx", [
        ("[Content_Types].xml", CONTENT_TYPES),
        ("word/document.xml",
         '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
         f'<w:document xmlns:w="{W_NS}"><w:body>'
         "<w:p><w:r><w:t>The payments API is internet facing.</w:t></w:r></w:p>"
         "<w:p><w:r><w:t>It reaches the cards database.</w:t></w:r></w:p>"
         "</w:body></w:document>"),
    ])
    print(f"wrote {mcp_support / 'minimal.docx'}")

    total = sum(p.stat().st_size for p in DOCS.iterdir())
    print(f"wrote {len(list(DOCS.iterdir()))} document fixtures to {DOCS}")
    print(f"  {total:,} bytes")


if __name__ == "__main__":
    main()
