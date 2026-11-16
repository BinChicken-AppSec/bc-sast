use appsec_doctext::{extract, zipentry, DocError, Format, Limits};

fn doc(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support/docs")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

#[test]
fn a_word_document_yields_its_paragraphs_in_order() {
    let got = extract("ordinary.docx", &doc("ordinary.docx"), &Limits::default())
        .expect("a readable document");
    assert_eq!(got.format, Format::Docx);
    assert!(!got.truncated, "nothing should have been cut: {got:?}");

    let text = &got.text;
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "Architecture overview", "{text:?}");
    assert_eq!(lines[1], "The service is internet facing", "{text:?}");
    assert_eq!(lines[2], "Tabs:\tafter tab", "{text:?}");
    assert_eq!(lines[3], "Line one", "{text:?}");
    assert_eq!(lines[4], "Line two", "{text:?}");
    assert_eq!(lines[5], "Entities: <tag> & AB", "{text:?}");
    assert_eq!(lines[6], "Unicode: café — 日本語", "{text:?}");
    assert_eq!(lines[7], "raw <angle> brackets", "{text:?}");

    assert!(!text.contains("a comment"), "{text:?}");
    assert!(text.contains("A footnote about PCI scope."), "{text:?}");
    assert_eq!(
        got.parts_read,
        ["word/document.xml", "word/footnotes.xml"],
        "styles.xml is not a text part"
    );
}

#[test]
fn an_uncompressed_document_reads_the_same_as_a_compressed_one() {
    let stored = extract("stored.docx", &doc("stored.docx"), &Limits::default())
        .expect("a readable document");
    let deflated = extract("ordinary.docx", &doc("ordinary.docx"), &Limits::default())
        .expect("a readable document");
    let body: String = deflated
        .text
        .lines()
        .take(stored.text.lines().count())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(stored.text.trim_end(), body.trim_end());
}

#[test]
fn a_document_with_a_trailing_archive_comment_is_still_read() {
    let got = extract("commented.docx", &doc("commented.docx"), &Limits::default())
        .expect("a readable document");
    assert!(got.text.contains("Architecture overview"), "{:?}", got.text);
}

#[test]
fn a_spreadsheet_yields_its_shared_and_inline_strings() {
    let got = extract("ordinary.xlsx", &doc("ordinary.xlsx"), &Limits::default())
        .expect("a readable document");
    assert_eq!(got.format, Format::Xlsx);
    for wanted in [
        "Service",
        "Exposure",
        "payments-api",
        "internet",
        "inline cell",
    ] {
        assert!(
            got.text.contains(wanted),
            "{wanted:?} missing: {:?}",
            got.text
        );
    }
    assert_eq!(
        got.parts_read,
        ["xl/sharedStrings.xml", "xl/worksheets/sheet1.xml"]
    );
}

#[test]
fn slides_are_read_in_numeric_order_not_lexicographic() {
    let got = extract("ordinary.pptx", &doc("ordinary.pptx"), &Limits::default())
        .expect("a readable document");
    assert_eq!(got.format, Format::Pptx);
    assert_eq!(
        got.parts_read,
        [
            "ppt/slides/slide1.xml",
            "ppt/slides/slide2.xml",
            "ppt/slides/slide10.xml"
        ]
    );
    let first = got.text.find("First slide").expect("slide 1");
    let second = got.text.find("Second slide").expect("slide 2");
    let tenth = got.text.find("Tenth slide").expect("slide 10");
    assert!(first < second && second < tenth, "{:?}", got.text);
}

#[test]
fn a_doctype_is_refused_rather_than_skipped() {
    let err = extract("doctype.docx", &doc("doctype.docx"), &Limits::default())
        .expect_err("a DOCTYPE must be refused");
    match err {
        DocError::Xml {
            ref part,
            ref cause,
        } => {
            assert_eq!(part, "word/document.xml");
            assert!(cause.to_string().contains("DOCTYPE"), "{cause}");
        }
        other => panic!("expected an XML refusal, got {other:?}"),
    }
}

#[test]
fn an_entity_expansion_bomb_is_refused_at_the_doctype() {
    let started = std::time::Instant::now();
    let err = extract(
        "billion_laughs.docx",
        &doc("billion_laughs.docx"),
        &Limits::default(),
    )
    .expect_err("an entity bomb must be refused");
    assert!(
        matches!(err, DocError::Xml { .. }),
        "expected an XML refusal, got {err:?}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "refusing a DOCTYPE took {:?}",
        started.elapsed()
    );
}

#[test]
fn a_compression_bomb_is_truncated_at_the_bound_not_allowed_through() {
    let limits = Limits {
        max_chars: 4096,
        max_part_bytes: 32 * 1024 * 1024,
        ..Limits::default()
    };
    let got = extract("bomb.docx", &doc("bomb.docx"), &limits).expect("a bounded read");
    assert!(got.truncated, "the bound was not reported");
    assert!(
        got.text.chars().count() <= 4096,
        "produced {} characters against a 4096 bound",
        got.text.chars().count()
    );
}

#[test]
fn a_compression_bomb_is_refused_by_the_part_byte_bound() {
    let limits = Limits {
        max_part_bytes: 64 * 1024,
        ..Limits::default()
    };
    let err = extract("bomb.docx", &doc("bomb.docx"), &limits)
        .expect_err("the part bound must refuse it");
    assert!(
        err.to_string().contains("limit") || err.to_string().contains("decompress"),
        "{err}"
    );
}

#[test]
fn nesting_past_the_depth_bound_is_reported_rather_than_followed() {
    let err = extract("deep.docx", &doc("deep.docx"), &Limits::default())
        .expect_err("2000 levels is past the default bound");
    assert!(err.to_string().contains("nesting"), "{err}");
}

#[test]
fn an_archive_with_none_of_the_formats_parts_says_so() {
    let err = extract("no_parts.docx", &doc("no_parts.docx"), &Limits::default())
        .expect_err("there is no document part");
    assert!(matches!(err, DocError::NoReadableParts { .. }), "{err:?}");
    assert!(err.to_string().contains("no docx part"), "{err}");
}

#[test]
fn an_unsupported_compression_method_is_named() {
    let err = extract("bzip2.docx", &doc("bzip2.docx"), &Limits::default())
        .expect_err("bzip2 is not supported");
    assert!(err.to_string().contains("compression method"), "{err}");
    assert!(err.to_string().contains("word/document.xml"), "{err}");
}

#[test]
fn an_encrypted_entry_is_refused_by_name() {
    let err = extract("encrypted.docx", &doc("encrypted.docx"), &Limits::default())
        .expect_err("an encrypted entry must be refused");
    assert!(err.to_string().contains("encrypted"), "{err}");
}

#[test]
fn a_zip64_archive_is_refused_rather_than_misread() {
    let err = extract("zip64.docx", &doc("zip64.docx"), &Limits::default())
        .expect_err("ZIP64 is not supported");
    assert!(err.to_string().contains("ZIP64"), "{err}");
}

#[test]
fn a_mismatched_checksum_is_reported() {
    let err = extract("bad_crc.docx", &doc("bad_crc.docx"), &Limits::default())
        .expect_err("a bad CRC must not pass");
    assert!(err.to_string().contains("CRC-32"), "{err}");
}

#[test]
fn something_that_is_not_an_archive_is_refused() {
    let err = extract("not_a_zip.docx", &doc("not_a_zip.docx"), &Limits::default())
        .expect_err("not a zip");
    assert!(err.to_string().contains("not a ZIP archive"), "{err}");
}

#[test]
fn a_truncated_archive_is_refused() {
    let err = extract("truncated.docx", &doc("truncated.docx"), &Limits::default())
        .expect_err("the central directory is gone");
    assert!(matches!(err, DocError::Archive(_)), "{err:?}");
}

#[test]
fn a_format_is_identified_by_extension_including_the_macro_variants() {
    for (name, expected) in [
        ("design.docx", Format::Docx),
        ("DESIGN.DOCX", Format::Docx),
        ("macros.docm", Format::Docx),
        ("data.xlsx", Format::Xlsx),
        ("data.xlsm", Format::Xlsx),
        ("deck.pptx", Format::Pptx),
        ("deck.pptm", Format::Pptx),
        ("a.b.c.docx", Format::Docx),
        ("report.pdf", Format::Pdf),
        ("REPORT.PDF", Format::Pdf),
    ] {
        assert_eq!(Format::of_name(name), Some(expected), "{name}");
    }
    for name in ["legacy.doc", "sheet.xls", "deck.ppt", "README", "noext."] {
        assert_eq!(Format::of_name(name), None, "{name}");
    }
}

#[test]
fn an_unsupported_format_names_the_extension_and_the_alternatives() {
    let err = extract("legacy.doc", b"\xd0\xcf\x11\xe0", &Limits::default())
        .expect_err("the legacy binary format is not supported");
    assert_eq!(
        err,
        DocError::UnsupportedFormat {
            extension: Some("doc".into())
        }
    );
    let rendered = err.to_string();
    assert!(rendered.contains(".doc"), "{rendered}");
    assert!(rendered.contains("docx"), "{rendered}");
    assert!(rendered.contains("pdf"), "{rendered}");

    let no_ext = extract("README", b"x", &Limits::default()).expect_err("no extension");
    assert_eq!(no_ext, DocError::UnsupportedFormat { extension: None });
    assert!(no_ext.to_string().contains("no extension"), "{no_ext}");
}

#[test]
fn an_archive_past_the_size_bound_is_refused_before_it_is_parsed() {
    let limits = Limits {
        max_archive_bytes: 100,
        ..Limits::default()
    };
    let err = extract("ordinary.docx", &doc("ordinary.docx"), &limits).expect_err("past the bound");
    assert!(
        matches!(err, DocError::TooLarge { limit: 100, .. }),
        "{err:?}"
    );
}

#[test]
fn the_entry_names_of_a_real_document_are_listed() {
    let names = zipentry::entry_names(&doc("ordinary.docx"), &zipentry::Limits::default())
        .expect("a readable archive");
    assert!(
        names.contains(&"word/document.xml".to_string()),
        "{names:?}"
    );
    assert!(names.contains(&"word/styles.xml".to_string()), "{names:?}");
}

#[test]
fn an_entry_cap_of_one_refuses_a_real_document() {
    let limits = zipentry::Limits {
        max_entries: 1,
        ..zipentry::Limits::default()
    };
    let err = zipentry::entry_names(&doc("ordinary.docx"), &limits).expect_err("past the cap");
    assert!(err.to_string().contains("more than 1 entries"), "{err}");
}

#[test]
fn asking_for_an_entry_that_is_not_there_says_so() {
    let err = zipentry::read_entry(
        &doc("ordinary.docx"),
        "word/nonexistent.xml",
        &zipentry::Limits::default(),
    )
    .expect_err("no such entry");
    assert!(err.to_string().contains("no entry named"), "{err}");
}

#[test]
fn an_entry_name_is_matched_exactly_and_never_resolved_as_a_path() {
    for probe in [
        "word/../word/document.xml",
        "./word/document.xml",
        "/word/document.xml",
        "WORD/DOCUMENT.XML",
        "word/document.xml ",
    ] {
        let got = zipentry::read_entry(&doc("ordinary.docx"), probe, &zipentry::Limits::default());
        assert!(
            got.is_err(),
            "{probe:?} resolved to a real entry; names must match exactly"
        );
    }
    assert!(zipentry::read_entry(
        &doc("ordinary.docx"),
        "word/document.xml",
        &zipentry::Limits::default()
    )
    .is_ok());
}

#[test]
fn a_part_with_no_text_contributes_nothing_and_adds_no_blank_line() {
    let got = extract(
        "empty_part.docx",
        &doc("empty_part.docx"),
        &Limits::default(),
    )
    .expect("a readable document");
    assert!(got.text.contains("Architecture overview"), "{:?}", got.text);
    assert!(
        !got.text.ends_with("\n\n"),
        "a blank line was added: {:?}",
        got.text
    );
    assert_eq!(got.parts_read, ["word/document.xml", "word/footnotes.xml"]);
}
