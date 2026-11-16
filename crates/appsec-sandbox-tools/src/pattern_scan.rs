use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;
use serde_json::{json, Value};

use crate::scope::iter_in_scope_files;

pub const MAX_FILE_BYTES: u64 = 512 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_FILES: usize = 10_000;
pub const MAX_MATCHES_PER_FILE: usize = 50;
pub const MAX_MATCHES: usize = 200;

const DIFF_PATCH_FILENAME: &str = "diff.patch";

const BUILTIN_RULE: &str = "__builtin__";

pub(crate) static SECRET_RX: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(
        r#"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|credential)s?[ \t]*[:=][ \t]*['"]?(?!CRYPT:|ENC\(|\{\{|\$\{|<%=|<%|vault:|secret:|file:|/)(?![\w.-]+[ \t]*:)[^\s'",}{]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[0-9A-Za-z-]{10,}\b|\bgh[pousr]_[0-9A-Za-z]{36,}\b|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"#,
    )
    .expect("SECRET_RX is a compile-time-constant valid regex")
});

pub(crate) static INSECURE_RX: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(
        r#"(?i)\b(?:verify|verif(?:y|ication)[_-]?ssl|ssl[_-]?verify|validate[_-]?cert\w*|tls[_-]?verify|check[_-]?hostname|reject[_-]?unauthori[sz]ed)\b\s*[:=]\s*['"]?(?:false|0|no|none|off)\b|\binsecure\w*\s*[:=]\s*['"]?(?:true|1|yes)\b|\bInsecureSkipVerify\s*[:=]\s*true\b|\b(?:auth|authentication|authn|security)\s*[:=]\s*['"]?(?:none|disabled|off|false)\b|\bdebug\s*[:=]\s*['"]?(?:true|1|yes)\b|\ballow[_-]?anonymous\s*[:=]\s*['"]?(?:true|1|yes)\b"#,
    )
    .expect("INSECURE_RX is a compile-time-constant valid regex")
});

pub(crate) fn pattern_set(name: &str) -> Option<(&'static str, &'static FancyRegex)> {
    match name {
        "secret_exposure" => Some(("hardcoded secret or credential", &SECRET_RX)),
        "insecure_value" => Some(("insecure configuration value", &INSECURE_RX)),
        _ => None,
    }
}

const PATTERN_SET_NAMES: [&str; 2] = ["insecure_value", "secret_exposure"];

#[derive(Debug, Default, PartialEq)]
struct ReadResult {
    data: Vec<u8>,
    unreadable: bool,
    too_large: bool,
    binary: bool,
    has_more: bool,
}

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

fn scan_text(
    state: &mut ScanState,
    text: &str,
    rel: &str,
    set: &str,
    description: &str,
    regex: &FancyRegex,
) {
    let mut file_matches = 0usize;
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
