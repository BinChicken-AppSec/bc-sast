use crate::extract::SourceDocument;
use std::path::{Path, PathBuf};

pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DOCUMENTS: usize = 64;
pub const MAX_WALK_DEPTH: usize = 4;

const TEXT_EXTENSIONS: &[&str] = &[
    "md", "markdown", "txt", "text", "csv", "tsv", "json", "yaml", "yml", "adoc", "asciidoc",
    "rst", "log",
];

const BLOCKED_HOSTS: &[&str] = &[
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "fd00:ec2::254",
];

enum Reading {
    AsText,
    AsDocument,
}

fn extension_of(name: &str) -> Option<String> {
    Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
}

fn reading_for(name: &str) -> Result<Reading, String> {
    let Some(extension) = extension_of(name) else {
        return Err(format!(
            "{name}: no file extension, so the format is unknown"
        ));
    };
    if TEXT_EXTENSIONS.contains(&extension.as_str()) {
        return Ok(Reading::AsText);
    }
    match extension.as_str() {
        "docx" | "xlsx" | "pptx" | "pdf" => Ok(Reading::AsDocument),
        "doc" | "xls" | "ppt" => Err(format!(
            "{name}: the legacy binary Office format is not read; export it as docx/xlsx/pptx"
        )),
        other => Err(format!(
            "{name}: .{other} is not a readable document format"
        )),
    }
}

pub fn decode(name: &str, bytes: &[u8], url: &str) -> Result<SourceDocument, String> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(format!(
            "{name}: {} bytes exceeds the {MAX_DOCUMENT_BYTES}-byte document limit",
            bytes.len()
        ));
    }
    let (text, truncated) = match reading_for(name)? {
        Reading::AsText => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| format!("{name}: not valid UTF-8 text"))?
                .to_string();
            let limit = appsec_doctext::Limits::default().max_chars;
            if text.chars().count() > limit {
                (text.chars().take(limit).collect(), true)
            } else {
                (text, false)
            }
        }
        Reading::AsDocument => {
            let extracted =
                appsec_doctext::extract(name, bytes, &appsec_doctext::Limits::default())
                    .map_err(|e| format!("{name}: {e}"))?;
            (extracted.text, extracted.truncated)
        }
    };
    if text.trim().is_empty() {
        return Err(format!("{name}: no readable text"));
    }
    Ok(SourceDocument {
        title: name.to_string(),
        space: "supplied".to_string(),
        url: url.to_string(),
        modified: None,
        truncated,
        text,
    })
}

pub fn check_url(raw: &str) -> Result<(), String> {
    let trimmed = raw.trim();
    let Some(rest) = trimmed.strip_prefix("https://") else {
        return Err(format!(
            "{trimmed}: only https:// document URLs are fetched"
        ));
    };
    if rest.is_empty() {
        return Err(format!("{trimmed}: no host"));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err(format!(
            "{trimmed}: credentials in a URL are refused; the scanner does not authenticate to document hosts"
        ));
    }
    let host = authority
        .rsplit_once(':')
        .filter(|(h, _)| !h.contains(']') || h.ends_with(']'))
        .map(|(h, _)| h)
        .unwrap_or(authority)
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err(format!("{trimmed}: no host"));
    }
    if BLOCKED_HOSTS.contains(&host.as_str()) || host.starts_with("169.254.") {
        return Err(format!(
            "{trimmed}: the link-local metadata range is never a document source"
        ));
    }
    if host.starts_with("fe80:") {
        return Err(format!("{trimmed}: link-local addresses are refused"));
    }
    Ok(())
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .map(|n| n.to_string_lossy().starts_with('.'))
        .unwrap_or(false)
}

fn collect(path: &Path, depth: usize, out: &mut Vec<PathBuf>, problems: &mut Vec<String>) {
    if out.len() > MAX_DOCUMENTS {
        return;
    }
    if depth > 0 && is_hidden(path) {
        return;
    }
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            problems.push(format!("{}: {e}", path.display()));
            return;
        }
    };
    if meta.is_file() {
        out.push(path.to_path_buf());
        return;
    }
    if depth >= MAX_WALK_DEPTH {
        problems.push(format!(
            "{}: stopped at {MAX_WALK_DEPTH} directory levels",
            path.display()
        ));
        return;
    }
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(e) => {
            problems.push(format!("{}: {e}", path.display()));
            return;
        }
    };
    let mut children: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    children.sort();
    for child in children {
        collect(&child, depth + 1, out, problems);
    }
}

pub fn read_paths(paths: &[PathBuf]) -> (Vec<SourceDocument>, Vec<String>) {
    let mut files = Vec::new();
    let mut problems = Vec::new();
    for path in paths {
        collect(path, 0, &mut files, &mut problems);
    }
    let truncated = files.len() > MAX_DOCUMENTS;
    files.truncate(MAX_DOCUMENTS);
    if truncated {
        problems.push(format!(
            "more than {MAX_DOCUMENTS} supplied documents; the rest were not read"
        ));
    }
    let mut documents = Vec::new();
    for file in files {
        let name = file_name_of(&file);
        match std::fs::read(&file) {
            Ok(bytes) => match decode(&name, &bytes, &file.display().to_string()) {
                Ok(document) => documents.push(document),
                Err(e) => problems.push(e),
            },
            Err(e) => problems.push(format!("{}: {e}", file.display())),
        }
    }
    (documents, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_markdown_file_is_read_as_text() {
        let doc = decode("design.md", b"# Design\n\nInternet facing.", "design.md")
            .expect("markdown reads");
        assert_eq!(doc.title, "design.md");
        assert_eq!(doc.space, "supplied");
        assert!(doc.text.contains("Internet facing"));
        assert!(!doc.truncated);
    }

    #[test]
    fn a_file_with_no_extension_is_refused_by_name() {
        let e = decode("README", b"hello", "README").expect_err("refused");
        assert!(e.contains("no file extension"), "{e}");
    }

    #[test]
    fn a_legacy_office_file_says_what_to_do_instead() {
        let e = decode("spec.doc", b"\xd0\xcf\x11\xe0", "spec.doc").expect_err("refused");
        assert!(e.contains("export it as docx"), "{e}");
    }

    #[test]
    fn an_unknown_extension_is_refused() {
        let e = decode("thing.exe", b"MZ", "thing.exe").expect_err("refused");
        assert!(e.contains("not a readable document format"), "{e}");
    }

    #[test]
    fn a_text_file_that_is_not_utf8_is_refused_rather_than_mangled() {
        let e = decode("notes.txt", &[0xff, 0xfe, 0x00], "notes.txt").expect_err("refused");
        assert!(e.contains("not valid UTF-8"), "{e}");
    }

    #[test]
    fn an_oversized_file_is_refused_before_it_is_parsed() {
        let bytes = vec![b'a'; MAX_DOCUMENT_BYTES + 1];
        let e = decode("big.txt", &bytes, "big.txt").expect_err("refused");
        assert!(e.contains("exceeds"), "{e}");
    }

    #[test]
    fn an_empty_document_is_refused_rather_than_admitted_blank() {
        let e = decode("blank.md", b"   \n  ", "blank.md").expect_err("refused");
        assert!(e.contains("no readable text"), "{e}");
    }

    #[test]
    fn long_text_is_cut_and_says_so() {
        let limit = appsec_doctext::Limits::default().max_chars;
        let bytes = vec![b'x'; limit + 10];
        let doc = decode("long.txt", &bytes, "long.txt").expect("reads");
        assert!(doc.truncated);
        assert_eq!(doc.text.chars().count(), limit);
    }

    #[test]
    fn only_https_urls_are_fetched() {
        assert!(check_url("https://wiki.example.com/page").is_ok());
        let e = check_url("http://wiki.example.com/page").expect_err("refused");
        assert!(e.contains("only https"), "{e}");
        assert!(check_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn the_cloud_metadata_endpoint_is_never_a_document_source() {
        for url in [
            "https://169.254.169.254/latest/meta-data/",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://169.254.1.1/doc.md",
        ] {
            let e = check_url(url).expect_err("refused");
            assert!(e.contains("link-local"), "{url}: {e}");
        }
    }

    #[test]
    fn credentials_in_a_url_are_refused() {
        let e = check_url("https://user:pass@wiki.example.com/p").expect_err("refused");
        assert!(e.contains("credentials in a URL"), "{e}");
    }

    #[test]
    fn a_host_with_a_port_still_resolves_to_the_host() {
        assert!(check_url("https://wiki.example.com:8443/page").is_ok());
        let e = check_url("https://169.254.169.254:80/x").expect_err("refused");
        assert!(e.contains("link-local"), "{e}");
    }

    #[test]
    fn an_internal_host_is_allowed_because_that_is_the_normal_case() {
        assert!(
            check_url("https://wiki.internal.corp/page").is_ok(),
            "an internal documentation host is the point of the feature"
        );
        assert!(check_url("https://10.1.2.3/page").is_ok());
    }

    #[test]
    fn a_url_with_no_host_is_refused() {
        assert!(check_url("https://").is_err());
        assert!(check_url("https:///path").is_err());
    }

    #[test]
    fn a_directory_of_documents_is_read_in_a_stable_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("b.md"), "second doc").unwrap();
        std::fs::write(dir.path().join("a.md"), "first doc").unwrap();
        let (docs, problems) = read_paths(&[dir.path().to_path_buf()]);
        assert!(problems.is_empty(), "{problems:?}");
        let titles: Vec<&str> = docs.iter().map(|d| d.title.as_str()).collect();
        assert_eq!(titles, vec!["a.md", "b.md"]);
    }

    #[test]
    fn an_unreadable_file_is_reported_and_the_rest_still_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("good.md"), "readable").unwrap();
        std::fs::write(dir.path().join("bad.exe"), "MZ").unwrap();
        let (docs, problems) = read_paths(&[dir.path().to_path_buf()]);
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].title, "good.md");
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("bad.exe"), "{:?}", problems);
    }

    #[test]
    fn hidden_files_and_directories_are_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/config"), "secret").unwrap();
        std::fs::write(dir.path().join(".env"), "TOKEN=x").unwrap();
        std::fs::write(dir.path().join("ok.md"), "readable").unwrap();
        let (docs, _) = read_paths(&[dir.path().to_path_buf()]);
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].title, "ok.md");
    }

    fn minimal_pdf(body: &str) -> Vec<u8> {
        let stream = format!("BT /F1 12 Tf 72 720 Td ({body}) Tj ET");
        format!(
            "%PDF-1.7\n\
             1 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n\
             2 0 obj\n<< /Type /Pages /Count 1 /Kids [1 0 R] >>\nendobj\n\
             3 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
             4 0 obj\n<< /Length {} >>\nstream\n{stream}\nendstream\nendobj\n\
             5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n\
             trailer\n<< /Size 6 /Root 3 0 R >>\n%%EOF\n",
            stream.len()
        )
        .into_bytes()
    }

    #[test]
    fn a_pdf_is_read_through_the_document_reader() {
        let doc = decode("design.pdf", &minimal_pdf("Internet facing"), "design.pdf")
            .expect("the pdf reads");
        assert!(
            doc.text.contains("Internet facing"),
            "the document path extracted no text: {:?}",
            doc.text
        );
        assert_eq!(doc.title, "design.pdf");
    }

    #[test]
    fn a_document_that_will_not_parse_is_reported_by_name() {
        let e = decode("design.pdf", b"not a pdf at all", "design.pdf").expect_err("refused");
        assert!(e.starts_with("design.pdf: "), "{e}");
    }

    #[test]
    fn an_ipv6_link_local_url_is_refused() {
        let e = check_url("https://[fe80::1]/doc.md").expect_err("refused");
        assert!(e.contains("link-local"), "{e}");
    }

    #[test]
    fn a_path_with_no_final_component_still_gets_a_name() {
        assert_eq!(file_name_of(Path::new("/")), "/");
        assert_eq!(file_name_of(Path::new("a/b.md")), "b.md");
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_neither_a_file_nor_a_directory_is_reported() {
        // A FIFO, not a chmod. Permissions prove nothing when the test runs as
        // root -- root reads a 0o000 file happily -- and tests run as root in
        // every container. A FIFO is refused the same way for every user: it is
        // not a file, so the walk tries to read it as a directory and fails.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("ok.md"), "readable").unwrap();
        let fifo = dir.path().join("pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "mkfifo failed");

        let (docs, problems) = read_paths(&[dir.path().to_path_buf()]);
        assert_eq!(docs.len(), 1, "the readable document still loaded");
        assert_eq!(docs[0].title, "ok.md");
        assert!(problems.iter().any(|p| p.contains("pipe")), "{problems:?}");
    }

    #[test]
    fn a_missing_path_is_reported_not_fatal() {
        let (docs, problems) = read_paths(&[PathBuf::from("/nonexistent/doc.md")]);
        assert!(docs.is_empty());
        assert_eq!(problems.len(), 1);
    }

    #[test]
    fn the_walk_stops_at_the_depth_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut deep = dir.path().to_path_buf();
        for i in 0..(MAX_WALK_DEPTH + 2) {
            deep = deep.join(format!("d{i}"));
            std::fs::create_dir(&deep).unwrap();
        }
        std::fs::write(deep.join("buried.md"), "too deep").unwrap();
        let (docs, problems) = read_paths(&[dir.path().to_path_buf()]);
        assert!(docs.is_empty(), "the buried document was not read");
        assert!(
            problems.iter().any(|p| p.contains("directory levels")),
            "{problems:?}"
        );
    }

    #[test]
    fn the_document_count_is_capped_and_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        for i in 0..(MAX_DOCUMENTS + 3) {
            std::fs::write(dir.path().join(format!("d{i:03}.md")), "body").unwrap();
        }
        let (docs, problems) = read_paths(&[dir.path().to_path_buf()]);
        assert_eq!(docs.len(), MAX_DOCUMENTS);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("the rest were not read")),
            "a silent cap reads as complete: {problems:?}"
        );
    }
}
