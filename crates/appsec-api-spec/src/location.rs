use crate::format::Syntax;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Convention {
    pub path: &'static str,
    pub syntax: Syntax,
    pub confident: bool,
    pub accepted_directories: &'static [&'static str],
    pub basis: &'static str,
    pub code_first: bool,
}

pub fn join(root: &str, relative: &str) -> String {
    if root.is_empty() || root == "." {
        relative.to_string()
    } else {
        format!("{}/{relative}", root.trim_end_matches('/'))
    }
}

pub fn relative_to<'a>(root: &str, path: &'a str) -> Option<&'a str> {
    if root.is_empty() || root == "." {
        return Some(path);
    }
    path.strip_prefix(root.trim_end_matches('/'))?
        .strip_prefix('/')
}

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

pub fn conventional_path(convention: &Convention, root: &str, syntax: Syntax) -> String {
    let path = join(root, convention.path);
    if syntax == convention.syntax {
        return path;
    }
    let stem = path
        .rsplit_once('.')
        .map_or(path.as_str(), |(stem, _)| stem);
    match syntax {
        Syntax::Json => format!("{stem}.json"),
        Syntax::Yaml => format!("{stem}.yaml"),
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
