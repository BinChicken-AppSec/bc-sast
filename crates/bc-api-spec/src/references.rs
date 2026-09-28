//! Finding and rewriting textual references to a relocated specification.
//!
//! Every mention of the file's name in a scanned text file is a reference
//! candidate. A candidate is rewritable only when it is exactly one of the
//! path spellings this module can translate (the repository-relative
//! path, or the path relative to the referring file's directory,
//! including `../` climbs, each with or without a leading `./`) and the
//! file may be edited. Anything else, such
//! as a URL path, a `classpath:` or `${...}` prefix, another directory's
//! file with the same name, or any mention in a file the step may not
//! edit, blocks the relocation. A stale reference is worse than a
//! specification in a less conventional place.

use serde::{Deserialize, Serialize};

/// One rewritable mention of the relocated file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    pub file: String,
    pub line: usize,
    pub from: String,
    pub to: String,
}

/// What one file's scan found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileScan {
    pub rewritable: Vec<Reference>,
    /// Line number and reason for each mention that blocks relocation.
    pub blocking: Vec<(usize, String)>,
    /// The file's text with every rewritable mention replaced, when there
    /// was at least one and nothing blocked.
    pub rewritten: Option<String>,
}

/// Scan `text`, the contents of repository file `file`, for references to
/// a specification moving from `old` to `new`.
pub fn scan(file: &str, text: &str, old: &str, new: &str, editable: bool) -> FileScan {
    let basename = old.rsplit('/').next().unwrap_or(old);
    let forms = forms(file, old, new);
    let mut result = FileScan::default();
    let mut replacements = Vec::new();
    for (start, _) in text.match_indices(basename) {
        let end = start + basename.len();
        if name_character_before(text, start) || !boundary_after(text, end) {
            continue;
        }
        let line = text[..start].matches('\n').count() + 1;
        let form = forms.iter().find(|(from, _)| {
            text[..end].ends_with(from.as_str()) && path_boundary_before(text, end - from.len())
        });
        match form {
            Some((from, to)) if editable => {
                replacements.push((end - from.len(), end, to.clone()));
                result.rewritable.push(Reference {
                    file: file.into(),
                    line,
                    from: from.clone(),
                    to: to.clone(),
                });
            }
            Some(_) => result
                .blocking
                .push((line, "a reference in a file this step may not edit".into())),
            None => result.blocking.push((
                line,
                format!("mentions {basename} in a form that cannot be rewritten unambiguously"),
            )),
        }
    }
    if result.blocking.is_empty() && !replacements.is_empty() {
        let mut rewritten = text.to_string();
        for (start, end, to) in replacements.iter().rev() {
            rewritten.replace_range(*start..*end, to);
        }
        result.rewritten = Some(rewritten);
    }
    result
}

/// Spellings of `old` that `file` may use, each paired with its
/// replacement, longest first so the most specific spelling wins.
fn forms(file: &str, old: &str, new: &str) -> Vec<(String, String)> {
    let mut forms = vec![
        (old.to_string(), new.to_string()),
        (format!("./{old}"), format!("./{new}")),
    ];
    // Relative to the referring file's directory, climbing with `../` when
    // the specification lies elsewhere, as a Markdown link would.
    if let Some((directory, _)) = file.rsplit_once('/') {
        let from = relative_path(directory, old);
        let to = relative_path(directory, new);
        if !from.starts_with("../") {
            let dotted = if to.starts_with("../") {
                to.clone()
            } else {
                format!("./{to}")
            };
            forms.push((format!("./{from}"), dotted));
        }
        forms.push((from, to));
    }
    forms.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
    forms.dedup_by(|a, b| a.0 == b.0);
    forms
}

/// `to` (repository relative) as seen from directory `from`.
pub fn relative_path(from: &str, to: &str) -> String {
    let from: Vec<&str> = from.split('/').filter(|part| !part.is_empty()).collect();
    let to: Vec<&str> = to.split('/').collect();
    // Never consume the file name itself as a shared directory.
    let common = from
        .iter()
        .zip(&to)
        .take_while(|(a, b)| a == b)
        .count()
        .min(to.len() - 1);
    let mut parts = vec![".."; from.len() - common];
    parts.extend(&to[common..]);
    parts.join("/")
}

fn is_name_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
}

/// The match is the tail of a longer file name, such as `petstore.openapi.yaml`.
fn name_character_before(text: &str, start: usize) -> bool {
    text[..start]
        .chars()
        .next_back()
        .is_some_and(is_name_character)
}

/// The match is followed by something that ends a file name. A `.` ends it
/// only when it is not the start of another extension, so a sentence may
/// end with the file name.
fn boundary_after(text: &str, end: usize) -> bool {
    let mut rest = text[end..].chars();
    match rest.next() {
        None => true,
        Some('.') => !rest.next().is_some_and(|c| c.is_ascii_alphanumeric()),
        Some(c) => !(c.is_ascii_alphanumeric() || c == '_' || c == '-'),
    }
}

/// A spelling starting at `start` is a whole path, not the tail of a
/// longer one (`src/docs/...`), a relative climb (`../docs/...`), a
/// variable expansion (`${root}/...`) or a URI scheme (`classpath:...`).
fn path_boundary_before(text: &str, start: usize) -> bool {
    let mut before = text[..start].chars().rev();
    match before.next() {
        None => true,
        Some(':') => !before.next().is_some_and(|c| c.is_ascii_alphanumeric()),
        Some(c) => !(is_name_character(c) || matches!(c, '/' | '\\' | '~' | '$' | '}' | '@' | '%')),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "docs/openapi.yaml";
    const NEW: &str = "src/main/resources/static/openapi.yaml";

    #[test]
    fn repository_and_directory_relative_spellings_are_rewritten() {
        let text = "See [the spec](docs/openapi.yaml) or ./docs/openapi.yaml.\nurl: \"docs/openapi.yaml\"\n";
        let result = scan("README.md", text, OLD, NEW, true);
        assert!(result.blocking.is_empty());
        assert_eq!(result.rewritable.len(), 3);
        assert_eq!(result.rewritable[2].line, 2);
        assert_eq!(
            result.rewritten.unwrap(),
            format!("See [the spec]({NEW}) or ./{NEW}.\nurl: \"{NEW}\"\n")
        );
        let nested = scan(
            "docs/guide.md",
            "Open openapi.yaml or ./openapi.yaml",
            OLD,
            NEW,
            true,
        );
        assert_eq!(
            nested.rewritten.unwrap(),
            "Open ../src/main/resources/static/openapi.yaml or ../src/main/resources/static/openapi.yaml"
        );
        let below = scan(
            "src/main/README.md",
            "resources/x/openapi.yaml",
            "src/main/resources/x/openapi.yaml",
            "src/main/resources/static/openapi.yaml",
            true,
        );
        assert_eq!(below.rewritten.unwrap(), "resources/static/openapi.yaml");
        let dotted = scan(
            "src/main/README.md",
            "./resources/x/openapi.yaml",
            "src/main/resources/x/openapi.yaml",
            "src/main/resources/static/openapi.yaml",
            true,
        );
        assert_eq!(dotted.rewritten.unwrap(), "./resources/static/openapi.yaml");
        let climbing = scan(
            "guides/setup.md",
            "[spec](../docs/openapi.yaml)",
            OLD,
            NEW,
            true,
        );
        assert_eq!(
            climbing.rewritten.unwrap(),
            "[spec](../src/main/resources/static/openapi.yaml)"
        );
    }

    #[test]
    fn other_files_and_unrelated_names_are_ignored() {
        for text in [
            "petstore.openapi.yaml",
            "myopenapi.yaml",
            "openapi.yaml.bak",
            "openapi.yamlx",
            "no mention at all",
        ] {
            assert_eq!(
                scan("README.md", text, OLD, NEW, true),
                FileScan::default(),
                "{text}"
            );
        }
    }

    #[test]
    fn ambiguous_spellings_block_relocation() {
        for text in [
            "springdoc.swagger-ui.url=/openapi.yaml",
            "classpath:docs/openapi.yaml",
            "${root}/docs/openapi.yaml",
            "../other/openapi.yaml",
            "other/docs/openapi.yaml",
            "C:\\repo\\docs\\openapi.yaml",
        ] {
            let result = scan("app.properties", text, OLD, NEW, true);
            assert_eq!(result.blocking.len(), 1, "{text}");
            assert!(result.rewritten.is_none());
        }
        // A key-value separator is not a URI scheme.
        let spaced = scan("a.properties", "spec= :docs/openapi.yaml", OLD, NEW, true);
        assert!(spaced.blocking.is_empty());
    }

    #[test]
    fn mentions_in_files_the_step_may_not_edit_block_relocation() {
        let result = scan(
            "src/App.java",
            "load(\"docs/openapi.yaml\");",
            OLD,
            NEW,
            false,
        );
        assert_eq!(
            result.blocking,
            [(1, "a reference in a file this step may not edit".into())]
        );
        assert!(result.rewritable.is_empty() && result.rewritten.is_none());
        // One blocking mention stops every rewrite in the file.
        let mixed = scan(
            "README.md",
            "docs/openapi.yaml and /openapi.yaml",
            OLD,
            NEW,
            true,
        );
        assert_eq!(mixed.rewritable.len(), 1);
        assert!(mixed.rewritten.is_none());
    }

    #[test]
    fn relative_paths_climb_only_as_far_as_needed() {
        assert_eq!(relative_path("docs", "src/a.yaml"), "../src/a.yaml");
        assert_eq!(relative_path("src/main", "src/main/r/a.yaml"), "r/a.yaml");
        assert_eq!(relative_path("", "a.yaml"), "a.yaml");
        assert_eq!(relative_path("a", "a"), "../a");
    }
}
