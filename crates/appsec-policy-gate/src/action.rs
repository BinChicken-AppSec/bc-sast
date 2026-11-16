#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Patch,
    GuidanceOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(Action::Patch, Action::GuidanceOnly);
    }
}
