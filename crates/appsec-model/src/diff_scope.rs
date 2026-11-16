use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffScope {
    active: bool,
    files: BTreeSet<String>,
}

fn normalize(path: &str) -> String {
    let mut normalized = path.trim().replace('\\', "/");
    while let Some(rest) = normalized.strip_prefix("./") {
        normalized = rest.to_string();
    }
    while let Some(rest) = normalized.strip_prefix('/') {
        normalized = rest.to_string();
    }
    normalized
}

impl DiffScope {
    pub fn inactive() -> Self {
        DiffScope::default()
    }

    pub fn active<I, S>(files: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        DiffScope {
            active: true,
            files: files.into_iter().map(|f| normalize(f.as_ref())).collect(),
        }
    }

    pub fn new<I, S>(active: bool, files: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if active {
            DiffScope::active(files)
        } else {
            DiffScope::inactive()
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn contains(&self, file: &str) -> bool {
        self.files.contains(&normalize(file))
    }

    pub fn allows(&self, file: &str) -> bool {
        !self.active || self.contains(file)
    }

    pub fn refusal(&self, file: &str) -> Option<String> {
        if self.allows(file) {
            return None;
        }
        let shown = if file.trim().is_empty() {
            "<no file>"
        } else {
            file
        };
        Some(format!(
            "{shown} is outside the --diff-scope changed-file set ({} changed file(s)); \
             this run did not analyze it and must not modify it",
            self.files.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_inactive_scope_allows_every_file() {
        let scope = DiffScope::inactive();
        assert!(!scope.is_active());
        assert!(scope.allows("anything/at/all.py"));
        assert!(scope.refusal("anything/at/all.py").is_none());
    }

    #[test]
    fn the_default_is_the_inactive_scope() {
        assert_eq!(DiffScope::default(), DiffScope::inactive());
    }

    #[test]
    fn an_active_scope_allows_only_its_own_files() {
        let scope = DiffScope::active(["src/app.py", "src/other.py"]);
        assert!(scope.is_active());
        assert!(scope.allows("src/app.py"));
        assert!(scope.contains("src/other.py"));
        assert!(!scope.allows("vendor/lib.py"));
    }

    #[test]
    fn an_active_scope_with_no_files_allows_nothing() {
        let scope = DiffScope::active(Vec::<String>::new());
        assert!(scope.is_active());
        assert!(!scope.allows("src/app.py"));
    }

    #[test]
    fn new_selects_active_or_inactive_from_the_flag() {
        assert!(!DiffScope::new(false, ["src/app.py"]).is_active());
        assert!(DiffScope::new(false, ["src/app.py"]).allows("vendor/lib.py"));
        assert!(DiffScope::new(true, ["src/app.py"]).is_active());
        assert!(!DiffScope::new(true, ["src/app.py"]).allows("vendor/lib.py"));
    }

    #[test]
    fn paths_are_normalized_on_both_sides_of_the_comparison() {
        let scope = DiffScope::active(["./src/app.py", "/src/abs.py", "src\\win.py"]);
        assert!(scope.allows("src/app.py"));
        assert!(scope.allows("./src/app.py"));
        assert!(scope.allows("/src/app.py"));
        assert!(scope.allows("src/abs.py"));
        assert!(scope.allows("src\\win.py"));
        assert!(scope.allows("  src/win.py  "));
        assert!(scope.allows(".//src/app.py"));
    }

    #[test]
    fn a_path_that_only_ends_with_a_changed_file_is_out_of_scope() {
        let scope = DiffScope::active(["src/app.py"]);
        assert!(!scope.allows("vendor/copy/src/app.py"));
        assert!(!scope.allows("app.py"));
    }

    #[test]
    fn refusal_names_the_file_the_flag_and_the_changed_file_count() {
        let scope = DiffScope::active(["src/app.py"]);
        let reason = scope.refusal("vendor/lib.py").unwrap();
        assert!(reason.contains("vendor/lib.py"), "{reason}");
        assert!(reason.contains("--diff-scope"), "{reason}");
        assert!(reason.contains("1 changed file(s)"), "{reason}");
    }

    #[test]
    fn refusal_of_an_empty_path_is_still_readable() {
        let scope = DiffScope::active(["src/app.py"]);
        let reason = scope.refusal("   ").unwrap();
        assert!(reason.contains("<no file>"), "{reason}");
    }
}
