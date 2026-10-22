//! Where a document belongs: a standard's convention for one service, and
//! the path arithmetic every standard shares. Each standard's table of
//! conventions lives in its own module.

use crate::format::Syntax;

/// A framework's or library's convention for one standard's documents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Convention {
    /// Where a new document goes, relative to the service root.
    pub path: &'static str,
    pub syntax: Syntax,
    /// Tooling reads the file from here, so a document elsewhere is not
    /// found by default. Only a confident convention ever justifies moving
    /// a file somebody already placed.
    pub confident: bool,
    /// Directories, relative to the service root, where an existing
    /// document counts as correctly placed for this convention.
    pub accepted_directories: &'static [&'static str],
    pub basis: &'static str,
    /// The framework builds this document from code, so a static copy is
    /// a reviewed snapshot that must be regenerated when the code changes.
    pub code_first: bool,
}

/// `relative` joined under `root` (`.` is the repository root).
pub fn join(root: &str, relative: &str) -> String {
    if root.is_empty() || root == "." {
        relative.to_string()
    } else {
        format!("{}/{relative}", root.trim_end_matches('/'))
    }
}

/// `path` relative to `root`, if it lies under it.
pub fn relative_to<'a>(root: &str, path: &'a str) -> Option<&'a str> {
    if root.is_empty() || root == "." {
        return Some(path);
    }
    path.strip_prefix(root.trim_end_matches('/'))?
        .strip_prefix('/')
}

/// Whether a document at `path` is correctly placed for a service at
/// `root` with this convention. Non-confident conventions accept any
/// location, since they are not evidence of where tooling looks.
pub fn is_accepted(convention: &Convention, root: &str, path: &str) -> bool {
    if !convention.confident {
        return true;
    }
    let Some(relative) = relative_to(root, path) else {
        return false;
    };
    relative == convention.path
        || convention
            .accepted_directories
            .iter()
            .any(|directory| relative.starts_with(&format!("{directory}/")))
}

/// The conventional path for a service at `root`, keeping `syntax` when an
/// existing JSON or YAML document is being relocated: moving never
/// converts YAML to JSON or back.
pub fn conventional_path(convention: &Convention, root: &str, syntax: Syntax) -> String {
    let path = join(root, convention.path);
    if syntax == convention.syntax {
        return path;
    }
    // Every JSON or YAML convention path ends in `.yaml` or `.json`.
    let stem = path
        .rsplit_once('.')
        .map_or(path.as_str(), |(stem, _)| stem);
    match syntax {
        Syntax::Json => format!("{stem}.json"),
        Syntax::Yaml => format!("{stem}.yaml"),
        // Text standards have one syntax each, so the convention's own
        // extension is kept.
        _ => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_join_and_relativise_against_a_service_root() {
        assert_eq!(join(".", "a.yaml"), "a.yaml");
        assert_eq!(join("", "a.yaml"), "a.yaml");
        assert_eq!(join("svc/", "a.yaml"), "svc/a.yaml");
        assert_eq!(relative_to(".", "a/b"), Some("a/b"));
        assert_eq!(relative_to("svc", "svc/a"), Some("a"));
        assert_eq!(relative_to("svc", "svcx/a"), None);
        assert_eq!(relative_to("svc", "other/a"), None);
    }

    #[test]
    fn a_text_standard_keeps_its_conventional_extension() {
        let convention = Convention {
            path: "schema.graphqls",
            syntax: Syntax::Yaml,
            confident: false,
            accepted_directories: &[],
            basis: "",
            code_first: false,
        };
        assert_eq!(
            conventional_path(&convention, "svc", Syntax::Graphql),
            "svc/schema.graphqls"
        );
    }
}
