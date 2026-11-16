use appsec_doctext::{extract, pdf, DocError, Format, Limits};

fn load(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support/pdfs")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn text_of(name: &str) -> String {
    extract(name, &load(name), &Limits::default())
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .text
}

#[test]
fn a_real_pdf_yields_its_lines_in_order() {
    let got = extract(
        "quartz_text.pdf",
        &load("quartz_text.pdf"),
        &Limits::default(),
    )
    .expect("a readable PDF");
    assert_eq!(got.format, Format::Pdf);
    assert_eq!(
        got.text.lines().collect::<Vec<_>>(),
        [
            "Architecture overview",
            "The payments service is internet facing.",
            "It reaches the cards database.",
        ]
    );
    assert_eq!(got.parts_read, ["page 1"]);
    assert!(!got.truncated);
}

#[test]
fn a_real_pdf_decodes_its_encoding_rather_than_guessing_latin1() {
    let text = text_of("quartz_unicode.pdf");
    assert!(text.contains("Café — unicode test"), "{text:?}");
    assert!(!text.contains("CafŽ"), "decoded as cp1252: {text:?}");
    assert!(!text.contains('\u{FFFD}'), "undecoded bytes: {text:?}");
}

#[test]
fn trailing_padding_is_not_carried_into_the_text() {
    let text = text_of("quartz_text.pdf");
    for line in text.lines() {
        assert_eq!(line, line.trim_end(), "line kept its padding: {line:?}");
    }
}

#[test]
fn a_tounicode_cmap_decodes_two_byte_codes() {
    let text = text_of("tounicode.pdf");
    assert_eq!(text, "Gatef", "{text:?}");
}

#[test]
fn objects_inside_an_object_stream_are_found() {
    assert_eq!(text_of("objstm.pdf"), "Inside an object stream");
}

#[test]
fn a_differences_array_remaps_codes_by_glyph_name() {
    let text = text_of("differences.pdf");
    assert_eq!(text, "—• café", "{text:?}");
}

#[test]
fn a_word_gap_becomes_a_space_and_kerning_does_not() {
    let text = text_of("kerning.pdf");
    assert_eq!(text, "Gateway terminates TLS.", "{text:?}");
}

#[test]
fn pages_come_back_in_tree_order_not_object_order() {
    let got = extract("multipage.pdf", &load("multipage.pdf"), &Limits::default())
        .expect("a readable PDF");
    assert_eq!(got.pages_read(), 3);
    assert_eq!(
        got.text.lines().collect::<Vec<_>>(),
        ["First page", "Second page", "Third page"]
    );
    assert_eq!(got.parts_read, ["page 1", "page 2", "page 3"]);
}

#[test]
fn a_looping_page_tree_terminates_and_still_yields_its_page() {
    assert_eq!(text_of("cycle.pdf"), "Reachable despite the loop");
}

#[test]
fn a_scanned_page_is_reported_as_having_no_text_rather_than_being_empty() {
    let err = extract("scanned.pdf", &load("scanned.pdf"), &Limits::default())
        .expect_err("a scan holds no text");
    assert!(
        matches!(err, DocError::Pdf(pdf::PdfError::NoTextFound { pages: 1 })),
        "{err:?}"
    );
    let rendered = err.to_string();
    assert!(rendered.contains("scanned"), "{rendered}");
    assert!(rendered.contains("1 page"), "{rendered}");
}

#[test]
fn an_encrypted_pdf_is_refused_with_something_to_do_about_it() {
    let err = extract("encrypted.pdf", &load("encrypted.pdf"), &Limits::default())
        .expect_err("encrypted");
    assert!(
        matches!(err, DocError::Pdf(pdf::PdfError::Encrypted)),
        "{err:?}"
    );
    assert!(err.to_string().contains("export"), "{err}");
}

#[test]
fn a_catalog_with_no_pages_is_refused() {
    let err =
        extract("nopages.pdf", &load("nopages.pdf"), &Limits::default()).expect_err("no pages");
    assert!(
        matches!(err, DocError::Pdf(pdf::PdfError::NoPages)),
        "{err:?}"
    );
}

#[test]
fn something_that_is_not_a_pdf_is_refused() {
    let err = extract("no_header.pdf", &load("no_header.pdf"), &Limits::default())
        .expect_err("no header");
    assert!(
        matches!(err, DocError::Pdf(pdf::PdfError::NotAPdf)),
        "{err:?}"
    );
}

#[test]
fn a_truncated_pdf_still_yields_the_objects_that_survived() {
    let text = text_of("truncated.pdf");
    assert!(text.contains("Architecture overview"), "{text:?}");
}

#[test]
fn the_character_bound_truncates_rather_than_failing() {
    let limits = Limits {
        max_chars: 12,
        ..Limits::default()
    };
    let got = extract("multipage.pdf", &load("multipage.pdf"), &limits).expect("a bounded read");
    assert!(got.text.chars().count() <= 12, "{:?}", got.text);
    assert!(got.truncated);
}

#[test]
fn the_object_and_page_bounds_are_enforced() {
    let few_objects = Limits {
        max_pdf_objects: 2,
        ..Limits::default()
    };
    let err = extract("multipage.pdf", &load("multipage.pdf"), &few_objects)
        .expect_err("past the object bound");
    assert!(err.to_string().contains("objects"), "{err}");

    let few_pages = Limits {
        max_pdf_pages: 1,
        ..Limits::default()
    };
    let got = extract("multipage.pdf", &load("multipage.pdf"), &few_pages).expect("a bounded read");
    assert_eq!(got.text, "First page");
    assert!(got.truncated, "the page cap was not reported");
}

#[test]
fn a_pdf_is_identified_by_extension_and_takes_the_pdf_path() {
    assert_eq!(Format::of_name("report.pdf"), Some(Format::Pdf));
    assert_eq!(Format::of_name("REPORT.PDF"), Some(Format::Pdf));
    assert_eq!(Format::Pdf.as_str(), "pdf");
    let err = extract("x.pdf", b"not a pdf at all", &Limits::default()).expect_err("refused");
    assert!(matches!(err, DocError::Pdf(_)), "{err:?}");
}

#[test]
fn corrupt_pdfs_are_never_a_panic() {
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state = state.wrapping_mul(0x2545F4914F6CDD1D);
        state
    };
    for name in [
        "quartz_text.pdf",
        "tounicode.pdf",
        "objstm.pdf",
        "multipage.pdf",
    ] {
        let original = load(name);
        for _ in 0..120 {
            let mut bytes = original.clone();
            for _ in 0..1 + (next() % 8) {
                let at = (next() as usize) % bytes.len();
                bytes[at] = (next() % 256) as u8;
            }
            let _ = extract(name, &bytes, &Limits::default());
        }
        for cut in (0..original.len()).step_by(97) {
            let _ = extract(name, &original[..cut], &Limits::default());
        }
    }
}
