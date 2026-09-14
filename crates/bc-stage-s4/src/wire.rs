//! Local wire-string mapping for `ChunkSize`, matching this project's
//! established convention (e.g. `bc-stage-s6`/`bc-stage-s3`'s own
//! `wire.rs`) of keeping enum-to-Python-`Literal`-string mappings local to
//! the consuming crate rather than growing `bc-model` per caller.

use bc_model::ChunkSize;

pub fn chunk_size_str(size: ChunkSize) -> &'static str {
    match size {
        ChunkSize::Small => "small",
        ChunkSize::Medium => "medium",
        ChunkSize::Large => "large",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_maps_to_its_python_literal_string() {
        assert_eq!(chunk_size_str(ChunkSize::Small), "small");
        assert_eq!(chunk_size_str(ChunkSize::Medium), "medium");
        assert_eq!(chunk_size_str(ChunkSize::Large), "large");
    }
}
