//! Typed counters for one S3 run, for the report's Pipeline Diagnostics.
//! Upstream prints these to stderr and bumps process-global counters; here
//! they are returned by [`crate::run_decompose_with_diagnostics`] so the
//! caller decides where they go.

use std::collections::BTreeMap;

use bc_model::Chunk;

/// What one decomposition produced and what its guards cut.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecomposeDiagnostics {
    /// Strategist chunks kept after parsing, normalization and the
    /// empty-chunk drop.
    pub llm_chunks: usize,
    /// Chunks produced per kind, counted before any `--diff-scope` trim.
    pub taint_chunks: usize,
    pub catchall_chunks: usize,
    pub specialist_chunks: usize,
    pub fallback_chunks: usize,
    /// Specialist chunks per lens.
    pub lens_chunks: BTreeMap<String, usize>,
    /// Configured lenses whose surface gate found nothing to review.
    pub gated_off_lenses: Vec<String>,
    /// Non-source files `catchall_mode: reachable_only` re-added because
    /// nothing else would review them.
    pub forced_coverage_files: usize,
    /// Files `catchall_mode: reachable_only` dropped from the sweep.
    pub unreachable_files: usize,
    /// Strategist chunks that failed validation on their own and were
    /// dropped while the rest of the reply was salvaged.
    pub invalid_chunks_dropped: usize,
    /// Strategist chunks dropped because none of their files resolved.
    pub empty_chunks_dropped: usize,
    /// `F###` ids in the reply that named no inventory file.
    pub unknown_file_ids: usize,
    /// Paths in the reply recovered by a unique suffix match.
    pub relocated_paths: usize,
    /// Paths in the reply that resolved to no file (or several).
    pub dropped_paths: usize,
    /// Threat-fallback chunks `max_threat_fallback_chunks` suppressed.
    pub fallback_chunks_capped: usize,
    /// Candidate files a threat-fallback chunk dropped to stay within
    /// `risk_chunk_loc`.
    pub fallback_files_trimmed: usize,
    /// Threats with at least one chunk, over threats that count toward
    /// coverage (baseline dispositions naming no code surface excluded).
    pub threats_covered: usize,
    pub threats_counted: usize,
    /// Whether the strategist prompt used the no-threats variant.
    pub no_threats_prompt: bool,
}

impl DecomposeDiagnostics {
    /// Fill the per-kind counts from the final chunk list, by id prefix
    /// (the one naming contract every producer in this crate follows).
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
    use bc_model::ChunkSize;

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
