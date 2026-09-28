//! The `PatternScan` fact tool: a deterministic regex sweep of the
//! in-scope tree, ported from `validation/tools/pattern_scanner.py`
//! (vvaharness v1.4.0) with its constants from
//! `validation/constants/pattern_sets.py`.
//!
//! **What changed in v1.4, and why it matters here.** The v1.2 scanner
//! this port started from read every in-scope file whole, with no limit,
//! and returned each match's text. Both were problems for a tool whose
//! output goes straight back into a model's context and from there into
//! transcripts and reports:
//! - **No candidate text.** A match record now carries only the file, the
//!   line, the pattern set and a description. For `secret_exposure` the
//!   matched text IS the credential, and a redacted snippet (this port's
//!   earlier compromise) still told the model the credential's shape and
//!   length. The persona needs to know where to look, not what it found.
//! - **Bounded work and output.** At most [`MAX_FILE_BYTES`] per file,
//!   [`MAX_TOTAL_BYTES`] and [`MAX_FILES`] per scan, [`MAX_MATCHES_PER_FILE`]
//!   per file and [`MAX_MATCHES`] overall. A scanned repository is
//!   untrusted input, and one planted multi-gigabyte file used to be read
//!   into memory whole.
//! - **An honest summary.** The last record (`"kind": "summary"`) reports
//!   what was scanned, what was skipped and why, and whether any limit
//!   truncated the result, so a persona never mistakes "stopped looking"
//!   for "found nothing".

use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;
use serde_json::{json, Value};

use crate::scope::iter_in_scope_files;

/// Largest file scanned (`_MAX_FILE_BYTES`); a larger one is skipped and
/// counted in `files_too_large`.
pub const MAX_FILE_BYTES: u64 = 512 * 1024;
/// Most bytes read across one scan (`_MAX_TOTAL_BYTES`).
pub const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
/// Most files considered in one scan (`_MAX_FILES`).
pub const MAX_FILES: usize = 10_000;
/// Most match records kept from one file (`_MAX_MATCHES_PER_FILE`).
pub const MAX_MATCHES_PER_FILE: usize = 50;
/// Most match records returned in total (`_MAX_MATCHES`).
pub const MAX_MATCHES: usize = 200;

/// `diff.patch` is the host's own artifact in Python's staged workspace,
/// never target source (`SKIP_IN_SCAN`). This port passes the diff in as
/// text, but a target that carries a file by that name is still not
/// production surface.
const DIFF_PATCH_FILENAME: &str = "diff.patch";

/// Rule tag emitted for matches from the builtin pattern sets
/// (`validation/constants/pattern_sets.py`).
const BUILTIN_RULE: &str = "__builtin__";

/// `s1_preprocess.py`'s `_SECRET_RX`, which
/// `validation/constants/pattern_sets.py` reuses verbatim as the
/// `secret_exposure` set. The negative lookaheads skip templated /
/// encrypted refs (`{{var}}`, `${VAR}`, `CRYPT:…`, `ENC(…)`, `<%= … %>`,
/// `vault:…`) and nested-key false positives (`auth-token:\n  timeout:`,
/// a "value" that is really another key), which is why this needs
/// `fancy-regex` rather than the `regex` crate.
///
/// Deliberately restated here rather than imported from
/// `bc_repo_analysis`, where the same two patterns already live as
/// private statics behind `dedup.rs`'s `suspicious_set`: exporting them
/// would widen that crate's public API for one consumer. The pairing is
/// covered by `regexes_match_the_s1_preprocess_originals` below.
pub(crate) static SECRET_RX: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(
        r#"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|credential)s?[ \t]*[:=][ \t]*['"]?(?!CRYPT:|ENC\(|\{\{|\$\{|<%=|<%|vault:|secret:|file:|/)(?![\w.-]+[ \t]*:)[^\s'",}{]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[0-9A-Za-z-]{10,}\b|\bgh[pousr]_[0-9A-Za-z]{36,}\b|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"#,
    )
    .expect("SECRET_RX is a compile-time-constant valid regex")
});

/// `s1_preprocess.py`'s `_INSECURE_RX`, reused as the `insecure_value`
/// set: insecure *values* (not secrets) such as disabled TLS verification,
/// `debug: true` and anonymous auth.
pub(crate) static INSECURE_RX: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(
        r#"(?i)\b(?:verify|verif(?:y|ication)[_-]?ssl|ssl[_-]?verify|validate[_-]?cert\w*|tls[_-]?verify|check[_-]?hostname|reject[_-]?unauthori[sz]ed)\b\s*[:=]\s*['"]?(?:false|0|no|none|off)\b|\binsecure\w*\s*[:=]\s*['"]?(?:true|1|yes)\b|\bInsecureSkipVerify\s*[:=]\s*true\b|\b(?:auth|authentication|authn|security)\s*[:=]\s*['"]?(?:none|disabled|off|false)\b|\bdebug\s*[:=]\s*['"]?(?:true|1|yes)\b|\ballow[_-]?anonymous\s*[:=]\s*['"]?(?:true|1|yes)\b"#,
    )
    .expect("INSECURE_RX is a compile-time-constant valid regex")
});

/// `DEFAULT_PATTERN_SETS`: set name to (human description, pattern).
pub(crate) fn pattern_set(name: &str) -> Option<(&'static str, &'static FancyRegex)> {
    match name {
        "secret_exposure" => Some(("hardcoded secret or credential", &SECRET_RX)),
        "insecure_value" => Some(("insecure configuration value", &INSECURE_RX)),
        _ => None,
    }
}

/// Sorted for the error message, matching Python's
/// `sorted(DEFAULT_PATTERN_SETS)`.
const PATTERN_SET_NAMES: [&str; 2] = ["insecure_value", "secret_exposure"];

/// What one bounded read produced (`_ReadResult`).
#[derive(Debug, Default, PartialEq)]
struct ReadResult {
    data: Vec<u8>,
    unreadable: bool,
    too_large: bool,
    binary: bool,
    has_more: bool,
}

/// Reads at most `max_bytes` of `path`, noting whether the file is larger
/// than [`MAX_FILE_BYTES`] or than what was read (`_read_bounded`). The
/// size comes from the open handle's own metadata, so a file swapped
/// between the stat and the read cannot slip a larger payload past it;
/// whichever of "reported" and "actually read" is bigger wins.
fn read_bounded(path: &Path, max_bytes: u64) -> ReadResult {
    let Ok(file) = std::fs::File::open(path) else {
        return ReadResult {
            unreadable: true,
            ..ReadResult::default()
        };
    };
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut data = Vec::new();
    if file.take(max_bytes).read_to_end(&mut data).is_err() {
        return ReadResult {
            unreadable: true,
            ..ReadResult::default()
        };
    }
    let observed = size.max(data.len() as u64);
    ReadResult {
        too_large: observed > MAX_FILE_BYTES,
        binary: data.contains(&0u8),
        has_more: observed > max_bytes,
        data,
        ..ReadResult::default()
    }
}

/// The scan's running tally (`_ScanState`).
#[derive(Debug, Default)]
struct ScanState {
    matches: Vec<(String, usize, Value)>,
    matches_seen: usize,
    files_considered: usize,
    files_scanned: usize,
    files_too_large: usize,
    files_unreadable: usize,
    binary_files: usize,
    bytes_scanned: u64,
    file_count_truncated: bool,
    byte_limit_truncated: bool,
    per_file_truncated: bool,
    overall_truncated: bool,
}

/// Records every match of `regex` in `text` against the per-file and
/// overall caps (`_scan_text`). Every match is COUNTED in `matches_seen`,
/// kept or not, so the summary can say how much was left out.
fn scan_text(
    state: &mut ScanState,
    text: &str,
    rel: &str,
    set: &str,
    description: &str,
    regex: &FancyRegex,
) {
    let mut file_matches = 0usize;
    // `map_while(Result::ok)` is `fancy-regex`'s backtrack-limit escape
    // hatch: a pathological file stops contributing matches rather than
    // failing the whole scan (Python's `re` has no such limit).
    for found in regex.find_iter(text).map_while(Result::ok) {
        state.matches_seen += 1;
        file_matches += 1;
        if file_matches > MAX_MATCHES_PER_FILE {
            state.per_file_truncated = true;
            continue;
        }
        if state.matches.len() >= MAX_MATCHES {
            state.overall_truncated = true;
            continue;
        }
        let line = text[..found.start()].matches('\n').count() + 1;
        state.matches.push((
            rel.to_string(),
            line,
            json!({
                "kind": "match",
                "file": rel,
                "line": line,
                "pattern_set": set,
                "rule": BUILTIN_RULE,
                "description": description,
            }),
        ));
    }
}

/// Reads and scans one file, updating every counter (`_consume_file`).
fn consume_file(
    state: &mut ScanState,
    rel: &str,
    path: &Path,
    set: &str,
    description: &str,
    regex: &FancyRegex,
) {
    state.files_considered += 1;
    let remaining = MAX_TOTAL_BYTES - state.bytes_scanned;
    let read_limit = MAX_FILE_BYTES.min(remaining);
    let result = read_bounded(path, read_limit);
    state.bytes_scanned += result.data.len() as u64;
    state.files_unreadable += usize::from(result.unreadable);
    state.files_too_large += usize::from(result.too_large);
    state.binary_files += usize::from(result.binary);
    let budget_exhausted = read_limit == remaining && result.has_more;
    state.byte_limit_truncated |= budget_exhausted;
    if !(result.unreadable || result.too_large || result.binary || budget_exhausted) {
        state.files_scanned += 1;
        scan_text(
            state,
            &String::from_utf8_lossy(&result.data),
            rel,
            set,
            description,
            regex,
        );
    }
}

/// The ordered match records followed by the summary record (`_result`).
fn finish(mut state: ScanState, set: &str) -> Value {
    state.matches.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    let reasons: Vec<&str> = [
        (state.files_too_large > 0, "file_size_limit"),
        (state.files_unreadable > 0, "unreadable_files"),
        (state.binary_files > 0, "binary_files"),
        (state.file_count_truncated, "overall_file_limit"),
        (state.byte_limit_truncated, "overall_byte_limit"),
        (state.per_file_truncated, "per_file_match_limit"),
        (state.overall_truncated, "overall_match_limit"),
    ]
    .into_iter()
    .filter_map(|(limited, reason)| limited.then_some(reason))
    .collect();
    let returned = state.matches.len();
    let mut records: Vec<Value> = state.matches.into_iter().map(|m| m.2).collect();
    records.push(json!({
        "kind": "summary",
        "pattern_set": set,
        "matches_seen": state.matches_seen,
        "matches_returned": returned,
        "files_considered": state.files_considered,
        "files_scanned": state.files_scanned,
        "files_too_large": state.files_too_large,
        "files_unreadable": state.files_unreadable,
        "binary_files": state.binary_files,
        "bytes_scanned": state.bytes_scanned,
        "truncated": !reasons.is_empty(),
        "truncation_reasons": reasons,
        "limits": {
            "max_file_bytes": MAX_FILE_BYTES,
            "max_total_bytes": MAX_TOTAL_BYTES,
            "max_files": MAX_FILES,
            "max_matches_per_file": MAX_MATCHES_PER_FILE,
            "max_matches": MAX_MATCHES,
        },
    }));
    Value::Array(records)
}

/// Bounded, secret-free match metadata for `set_name` over the in-scope
/// tree under `root`, followed by one summary record. An unknown set is an
/// `Err` so the caller gets a signal rather than a clean-looking empty
/// list, as Python raises `ValueError`.
pub fn pattern_scan(root: &Path, set_name: &str) -> Result<Value, String> {
    let Some((description, regex)) = pattern_set(set_name) else {
        return Err(format!(
            "unknown pattern_set '{set_name}'; available: {}",
            PATTERN_SET_NAMES.join(", ")
        ));
    };
    let mut state = ScanState::default();
    for (rel, path) in iter_in_scope_files(root, false) {
        if rel.rsplit('/').next() == Some(DIFF_PATCH_FILENAME) {
            continue;
        }
        if state.files_considered >= MAX_FILES {
            state.file_count_truncated = true;
            break;
        }
        consume_file(&mut state, &rel, &path, set_name, description, regex);
        if state.byte_limit_truncated {
            break;
        }
    }
    Ok(finish(state, set_name))
}

#[cfg(test)]
mod tests;
