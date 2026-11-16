#!/usr/bin/env python3
"""Build the synthetic PDF fixtures.

Run from the repository root:

    python3 crates/appsec-doctext/tests/generate_pdfs.py

A test-authoring tool, not a dependency.

**These do not replace the real ones.** `quartz_text.pdf` and
`quartz_unicode.pdf` beside them were produced by macOS Quartz through
`cupsfilter` and committed as captured artifacts -- they are not
regenerated here, because a real producer's output is the only thing
that proves the reader works on something nobody here wrote. What this
script adds is the structures that producer never emits: a `/ToUnicode`
CMap, an object stream, an encrypted trailer, a page with no text at
all, and a handful of deliberately broken files.
"""

import pathlib
import shutil
import zlib

HERE = pathlib.Path(__file__).resolve().parent
PDFS = HERE / "support" / "pdfs"
# Produced once by a real producer; this script must not touch them.
CAPTURED = {"quartz_text.pdf", "quartz_unicode.pdf"}


def build(objects: dict, root: int, extra_trailer: str = "") -> bytes:
    """A classic-xref PDF holding `objects`, numbered from 1."""
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n".encode() + objects[num] + b"\nendobj\n"
    xref_at = len(out)
    size = max(objects) + 1
    out += f"xref\n0 {size}\n".encode() + b"0000000000 65535 f \n"
    for n in range(1, size):
        out += (
            f"{offsets[n]:010d} 00000 n \n".encode()
            if n in offsets
            else b"0000000000 65535 f \n"
        )
    out += (
        f"trailer\n<< /Size {size} /Root {root} 0 R {extra_trailer}>>\n"
        f"startxref\n{xref_at}\n%%EOF\n"
    ).encode()
    return bytes(out)


def stream(dict_body: str, data: bytes, compress: bool = True) -> bytes:
    if compress:
        data = zlib.compress(data)
        dict_body += " /Filter /FlateDecode"
    return (
        f"<< {dict_body} /Length {len(data)} >>\nstream\n".encode()
        + data
        + b"\nendstream"
    )


def simple_page(contents_num: int, resources: str, parent: int = 2) -> bytes:
    return (
        f"<< /Type /Page /Parent {parent} 0 R /MediaBox [0 0 612 792] "
        f"/Resources {resources} /Contents {contents_num} 0 R >>"
    ).encode()


def main() -> None:
    PDFS.mkdir(parents=True, exist_ok=True)
    for existing in PDFS.iterdir():
        if existing.name not in CAPTURED:
            existing.unlink()

    # --- a Type0 font with a /ToUnicode CMap ---------------------------
    # The path a word processor takes, and the one the captured PDFs do
    # not exercise: two-byte codes that mean nothing without the CMap.
    cmap = (
        b"/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n"
        b"1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n"
        b"3 beginbfchar\n<0001> <0047>\n<0002> <0061>\n<0003> <0074>\nendbfchar\n"
        b"1 beginbfrange\n<0010> <0012> <0065>\nendbfrange\n"
        b"endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n"
    )
    # <0001 0002 0003 0010 0011> spells "Gate" then "f": G a t e f
    content = b"BT /F1 12 Tf 72 700 Td <00010002000300100011> Tj ET\n"
    build_to = {
        1: simple_page(4, "<< /Font << /F1 5 0 R >> >>"),
        2: b"<< /Type /Pages /Count 1 /Kids [1 0 R] >>",
        3: b"<< /Type /Catalog /Pages 2 0 R >>",
        4: stream("", content),
        5: (
            b"<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding /Identity-H "
            b"/DescendantFonts [7 0 R] /ToUnicode 6 0 R >>"
        ),
        6: stream("", cmap),
        7: b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Test >>",
    }
    (PDFS / "tounicode.pdf").write_bytes(build(build_to, 3))

    # --- objects inside a compressed object stream ---------------------
    # Since PDF 1.5 most objects live here. A reader that skips object
    # streams reads a modern file as very nearly empty.
    inner = {
        1: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
           b"/Resources << /Font << /F1 6 0 R >> >> /Contents 5 0 R >>",
        2: b"<< /Type /Pages /Count 1 /Kids [1 0 R] >>",
        3: b"<< /Type /Catalog /Pages 2 0 R >>",
        6: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    bodies, head, offset = b"", "", 0
    for num in sorted(inner):
        head += f"{num} {offset} "
        bodies += inner[num] + b" "
        offset = len(bodies)
    payload = head.encode() + bodies
    objstm_objects = {
        4: stream(f"/Type /ObjStm /N {len(inner)} /First {len(head)}", payload),
        5: stream("", b"BT /F1 12 Tf 72 700 Td (Inside an object stream) Tj ET\n"),
    }
    (PDFS / "objstm.pdf").write_bytes(build(objstm_objects, 3))

    # --- /Differences remapping codes to glyph names -------------------
    diff_content = b"BT /F1 12 Tf 72 700 Td (AB caf\\351) Tj ET\n"
    diff_objects = {
        1: simple_page(4, "<< /Font << /F1 5 0 R >> >>"),
        2: b"<< /Type /Pages /Count 1 /Kids [1 0 R] >>",
        3: b"<< /Type /Catalog /Pages 2 0 R >>",
        4: stream("", diff_content),
        5: (
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding "
            b"<< /Type /Encoding /BaseEncoding /WinAnsiEncoding "
            b"/Differences [65 /emdash /bullet] >> >>"
        ),
    }
    (PDFS / "differences.pdf").write_bytes(build(diff_objects, 3))

    # --- a TJ array whose gaps stand in for spaces ---------------------
    kern_content = (
        b"BT /F1 12 Tf 72 700 Td "
        b"[(Gateway) -400 (terminates) -400 (TLS) -30 (.)] TJ ET\n"
    )
    kern_objects = {
        1: simple_page(4, "<< /Font << /F1 5 0 R >> >>"),
        2: b"<< /Type /Pages /Count 1 /Kids [1 0 R] >>",
        3: b"<< /Type /Catalog /Pages 2 0 R >>",
        4: stream("", kern_content),
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    (PDFS / "kerning.pdf").write_bytes(build(kern_objects, 3))

    # --- three pages, with /Kids ordered against object numbers --------
    def page_content(text: str) -> bytes:
        return stream("", f"BT /F1 12 Tf 72 700 Td ({text}) Tj ET\n".encode())

    multi = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Count 3 /Kids [5 0 R 4 0 R 3 0 R] "
           b"/Resources << /Font << /F1 9 0 R >> >> >>",
        3: b"<< /Type /Page /Parent 2 0 R /Contents 8 0 R >>",
        4: b"<< /Type /Page /Parent 2 0 R /Contents 7 0 R >>",
        5: b"<< /Type /Page /Parent 2 0 R /Contents 6 0 R >>",
        6: page_content("First page"),
        7: page_content("Second page"),
        8: page_content("Third page"),
        9: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    (PDFS / "multipage.pdf").write_bytes(build(multi, 1))

    # --- a page tree that loops ----------------------------------------
    cyclic = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Count 1 /Kids [3 0 R 2 0 R] >>",
        3: b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R "
           b"/Resources << /Font << /F1 5 0 R >> >> >>",
        4: stream("", b"BT /F1 12 Tf 72 700 Td (Reachable despite the loop) Tj ET\n"),
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    (PDFS / "cycle.pdf").write_bytes(build(cyclic, 1))

    # --- a scanned page: an image, and no text at all -------------------
    scanned = {
        1: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
           b"/Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>",
        2: b"<< /Type /Pages /Count 1 /Kids [1 0 R] >>",
        3: b"<< /Type /Catalog /Pages 2 0 R >>",
        4: stream(
            "/Type /XObject /Subtype /Image /Width 2 /Height 2 "
            "/ColorSpace /DeviceGray /BitsPerComponent 8",
            b"\x00\xff\xff\x00",
        ),
        5: stream("", b"q 612 0 0 792 0 0 cm /Im0 Do Q\n"),
    }
    (PDFS / "scanned.pdf").write_bytes(build(scanned, 3))

    # --- encrypted ------------------------------------------------------
    enc = {
        1: simple_page(4, "<< >>"),
        2: b"<< /Type /Pages /Count 1 /Kids [1 0 R] >>",
        3: b"<< /Type /Catalog /Pages 2 0 R >>",
        4: stream("", b"BT (secret) Tj ET\n", compress=False),
        5: b"<< /Filter /Standard /V 2 /R 3 /Length 128 >>",
    }
    (PDFS / "encrypted.pdf").write_bytes(build(enc, 3, extra_trailer="/Encrypt 5 0 R "))

    # --- a catalog with no pages ----------------------------------------
    (PDFS / "nopages.pdf").write_bytes(
        build({1: b"<< /Type /Catalog >>", 2: b"<< /Nothing true >>"}, 1)
    )

    # --- not a PDF, and a truncated one ---------------------------------
    (PDFS / "no_header.pdf").write_bytes(b"just some bytes, no header at all\n" * 20)
    whole = (PDFS / "quartz_text.pdf").read_bytes()
    (PDFS / "truncated.pdf").write_bytes(whole[: len(whole) // 3])

    # One small PDF for `appsec-mcp`, which needs a real one to test
    # that its fetch path reaches the extractor. It does not re-test
    # extraction; that is this crate's job.
    mcp_support = HERE.parents[1] / "appsec-mcp" / "tests" / "support"
    mcp_support.mkdir(parents=True, exist_ok=True)
    mcp = {
        1: simple_page(4, "<< /Font << /F1 5 0 R >> >>"),
        2: b"<< /Type /Pages /Count 1 /Kids [1 0 R] >>",
        3: b"<< /Type /Catalog /Pages 2 0 R >>",
        4: stream(
            "",
            b"BT /F1 12 Tf 72 700 Td (The payments API is internet facing.) Tj ET\n"
            b"BT /F1 12 Tf 72 680 Td (It reaches the cards database.) Tj ET\n",
        ),
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    (mcp_support / "minimal.pdf").write_bytes(build(mcp, 3))
    print(f"wrote {mcp_support / 'minimal.pdf'}")

    total = sum(p.stat().st_size for p in PDFS.iterdir())
    built = sorted(p.name for p in PDFS.iterdir() if p.name not in CAPTURED)
    print(f"captured (not regenerated): {sorted(CAPTURED)}")
    print(f"built {len(built)}: {built}")
    print(f"  {total:,} bytes total")


if __name__ == "__main__":
    main()
