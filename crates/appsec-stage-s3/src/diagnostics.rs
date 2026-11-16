use std::collections::BTreeMap;

use appsec_model::Chunk;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecomposeDiagnostics {
    pub llm_chunks: usize,
    pub taint_chunks: usize,
    pub catchall_chunks: usize,
    pub specialist_chunks: usize,
    pub fallback_chunks: usize,
    pub lens_chunks: BTreeMap<String, usize>,
    pub gated_off_lenses: Vec<String>,
    pub forced_coverage_files: usize,
    pub unreachable_files: usize,
    pub invalid_chunks_dropped: usize,
    pub empty_chunks_dropped: usize,
    pub unknown_file_ids: usize,
    pub relocated_paths: usize,
    pub dropped_paths: usize,
    pub fallback_chunks_capped: usize,
    pub fallback_files_trimmed: usize,
    pub threats_covered: usize,
    pub threats_counted: usize,
    pub no_threats_prompt: bool,
}

impl DecomposeDiagnostics {
    pub(crate) fn count_kinds(&mut self, chunks: &[Chunk]) {
        for c in chunks {
            if let Some(lens) = &c.specialist {
                self.specialist_chunks += 1;
                *self.lens_chunks.entry(lens.clone()).or_default() += 1;
            } else if c.id.starts_with("taint-") {
                self.taint_chunks += 1;
            } else if c.id.starts_with("catchall-") {
                self.catchall_chunks += 1;
            } else if c.id.starts_with("threat-") && c.id.contains("-fallback") {
                self.fallback_chunks += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::ChunkSize;

    fn chunk(id: &str, specialist: Option<&str>) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: ChunkSize::Small,
            risk_rank: 1,
            files: Vec::new(),
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: None,
            languages: Vec::new(),
            specialist: specialist.map(String::from),
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: String::new(),
        }
    }

    #[test]
    fn count_kinds_buckets_chunks_by_their_producer() {
        let mut d = DecomposeDiagnostics::default();
        d.count_kinds(&[
            chunk("taint-01", None),
            chunk("catchall-01", None),
            chunk("catchall-02", None),
            chunk("spec-crypto-01", Some("crypto")),
            chunk("spec-csrf-01", Some("csrf")),
            chunk("spec-csrf-02", Some("csrf")),
            chunk("threat-t1-fallback", None),
            chunk("threat-model-chunk", None),
            chunk("chunk-01", None),
        ]);
        assert_eq!(d.taint_chunks, 1);
        assert_eq!(d.catchall_chunks, 2);
        assert_eq!(d.specialist_chunks, 3);
        assert_eq!(d.fallback_chunks, 1);
        assert_eq!(d.lens_chunks["csrf"], 2);
        assert_eq!(d.lens_chunks["crypto"], 1);
    }
}
