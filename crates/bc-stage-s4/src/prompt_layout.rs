//! How one deep-dive call's prompt is split between the request's cache
//! prefix and its user text, ported from upstream v1.4.0
//! `s4_deepdive.py::_single_run`'s `cache_prefix` construction.
//!
//! Three layouts, chosen per chunk:
//!
//! - **Open-ended, no shard** (risk, catch-all, taint-discover and threat
//!   fallback chunks): the cache prefix is the scan-constant
//!   [`crate::shared_context::shared_context_block`]; the user text is
//!   [`crate::prompts::build_prompt`], SOURCE CODE last.
//! - **Shard-major specialist** (`chunk.shard_id` non-empty): the prefix
//!   is the shared block followed by the shard's SOURCE CODE, which every
//!   lens on that shard sees byte-identical; the user text is
//!   [`crate::prompts::build_shard_prompt`], led by the research lens.
//! - **Confirm/refute** (a taint chunk under `taint_prompt_mode:
//!   confirm_refute`): no prefix at all. It is a single-shot verdict whose
//!   only text common to other calls is the system prompt, so a prefix
//!   would spend an Anthropic breakpoint slot for nothing.
//!
//! The transport decides whether a prefix is actually marked or keyed
//! (size floors, the operator's kill switch); this module only decides
//! which bytes are stable. See `docs/llm-transport.md`.
//!
//! **Separator, a small divergence from Python.** Upstream hands the bare
//! shared block over as the non-shard prefix. The OpenAI dialect
//! concatenates prefix and user text with no separator (the caller owns
//! it), which would glue the trust rule's last sentence onto `RESEARCH
//! LENS:`. This port ends that prefix with the same blank line the shard
//! prefix already has, which also makes the non-shard prefix a strict
//! byte prefix of every shard prefix.

use bc_model::{Chunk, ContextPackage};

use crate::prompts::{
    build_confirm_refute_prompt, build_prompt, build_shard_prompt, shard_source_block,
};

/// One deep-dive call's prompt, split for caching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepdivePrompt {
    /// The first user turn's text, after the prefix.
    pub user: String,
    /// [`bc_llm_client::ChatRequest::cache_prefix`].
    pub cache_prefix: Option<String>,
    /// [`bc_llm_client::ChatRequest::cache_key`] material. See
    /// [`cache_key`].
    pub cache_key: String,
}

/// Whether `chunk` gets the confirm/refute prompt instead of the
/// open-ended hunt: it carries a static taint path and the operator
/// opted in with `taint_prompt_mode: confirm_refute`.
pub fn uses_confirm_refute(chunk: &Chunk, taint_prompt_mode: &str) -> bool {
    !chunk.path_funcs.is_empty() && taint_prompt_mode == "confirm_refute"
}

/// Whether `chunk`'s cache prefix carries its shard's source, i.e.
/// whether the lenses on its shard can share one cached prefix. This is
/// the set shard gating applies to (see [`crate::shard_gate`]).
pub fn shares_shard_prefix(chunk: &Chunk, taint_prompt_mode: &str) -> bool {
    !chunk.shard_id.is_empty() && !uses_confirm_refute(chunk, taint_prompt_mode)
}

/// OpenAI `prompt_cache_key` material: `s4:<shard_id>` for a shard's
/// chunks, `s4:shared` otherwise. Constants and S3's own `shard-NN` ids
/// only, never a repository path or content; the transport hashes it
/// with the model and a digest of the prefix before anything is sent.
pub fn cache_key(chunk: &Chunk) -> String {
    let bucket = if chunk.shard_id.is_empty() {
        "shared"
    } else {
        chunk.shard_id.as_str()
    };
    format!("s4:{bucket}")
}

/// Build the prompt for one call. `shared` is the scan's
/// [`crate::shared_context::shared_context_block`], rendered once by the
/// caller; `code` and `sliced` are as in
/// [`crate::prompts::build_confirm_refute_prompt`].
pub fn deepdive_prompt(
    chunk: &Chunk,
    ctx: &ContextPackage,
    code: &str,
    taint_prompt_mode: &str,
    sliced: bool,
    shared: &str,
) -> DeepdivePrompt {
    let (user, cache_prefix) = if uses_confirm_refute(chunk, taint_prompt_mode) {
        (build_confirm_refute_prompt(chunk, ctx, code, sliced), None)
    } else if chunk.shard_id.is_empty() {
        (
            build_prompt(chunk, ctx, code),
            Some(format!("{shared}\n\n")),
        )
    } else {
        (
            build_shard_prompt(chunk, ctx, code),
            Some(format!("{shared}\n\n{}", shard_source_block(code))),
        )
    };
    DeepdivePrompt {
        user,
        cache_prefix,
        cache_key: cache_key(chunk),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::ChunkSize;

    fn chunk(id: &str, shard: &str, specialist: Option<&str>) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: ChunkSize::Small,
            risk_rank: 1,
            files: vec!["a.py".to_string()],
            focus_entry_points: Vec::new(),
            hypothesis: format!("{id} hypothesis"),
            related_cves: Vec::new(),
            threat_id: None,
            languages: vec!["python".to_string()],
            specialist: specialist.map(str::to_string),
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: shard.to_string(),
        }
    }

    fn taint_chunk() -> Chunk {
        Chunk {
            path_funcs: vec!["a.py::src".to_string(), "a.py::sink".to_string()],
            source_ref: "a.py::src".to_string(),
            sink_ref: "a.py:9".to_string(),
            ..chunk("taint-01", "", None)
        }
    }

    #[test]
    fn a_normal_chunk_puts_the_shared_block_in_the_prefix_and_the_code_in_the_user_text() {
        let p = deepdive_prompt(
            &chunk("risk-01", "", None),
            &ContextPackage::default(),
            "CODE_BODY",
            "discover",
            false,
            "SHARED",
        );
        assert_eq!(p.cache_prefix.as_deref(), Some("SHARED\n\n"));
        assert!(p.user.starts_with("RESEARCH LENS:\n"));
        assert!(p.user.contains("SOURCE CODE:\nCODE_BODY\n\n"));
        assert!(!p.user.contains("SHARED"));
        assert_eq!(p.cache_key, "s4:shared");
    }

    #[test]
    fn a_shard_chunk_moves_its_source_into_the_prefix_after_the_shared_block() {
        let p = deepdive_prompt(
            &chunk("spec-crypto-01", "shard-01", Some("crypto")),
            &ContextPackage::default(),
            "CODE_BODY",
            "discover",
            false,
            "SHARED",
        );
        assert_eq!(
            p.cache_prefix.as_deref(),
            Some("SHARED\n\nSOURCE CODE:\nCODE_BODY\n\n")
        );
        assert!(!p.user.contains("CODE_BODY"));
        assert!(p.user.starts_with("RESEARCH LENS:\n"));
        assert_eq!(p.cache_key, "s4:shard-01");
    }

    #[test]
    fn every_lens_on_one_shard_shares_a_byte_identical_prefix_but_not_user_text() {
        let ctx = ContextPackage::default();
        let a = deepdive_prompt(
            &chunk("spec-crypto-01", "shard-01", Some("crypto")),
            &ctx,
            "same code",
            "discover",
            false,
            "SHARED",
        );
        let b = deepdive_prompt(
            &chunk("spec-logic-bug-01", "shard-01", Some("logic-bug")),
            &ctx,
            "same code",
            "discover",
            false,
            "SHARED",
        );
        assert_eq!(a.cache_prefix, b.cache_prefix);
        assert_eq!(a.cache_key, b.cache_key);
        assert_ne!(a.user, b.user);
        // The non-shard prefix is a byte prefix of the shard one, so an
        // implicit prefix cache can reuse the shared block across both.
        let normal = deepdive_prompt(
            &chunk("risk-01", "", None),
            &ctx,
            "other code",
            "discover",
            false,
            "SHARED",
        );
        assert!(a
            .cache_prefix
            .unwrap()
            .starts_with(&normal.cache_prefix.unwrap()));
    }

    #[test]
    fn confirm_refute_gets_no_prefix_but_keeps_the_stage_key() {
        let p = deepdive_prompt(
            &taint_chunk(),
            &ContextPackage::default(),
            "CODE_BODY",
            "confirm_refute",
            true,
            "SHARED",
        );
        assert_eq!(p.cache_prefix, None);
        assert!(p
            .user
            .starts_with("TASK: confirm or refute ONE candidate taint path."));
        assert!(p.user.contains("CODE_BODY"));
        assert!(!p.user.contains("SHARED"));
        assert_eq!(p.cache_key, "s4:shared");
    }

    #[test]
    fn a_taint_chunk_under_discover_uses_the_normal_layout() {
        let p = deepdive_prompt(
            &taint_chunk(),
            &ContextPackage::default(),
            "CODE_BODY",
            "discover",
            false,
            "SHARED",
        );
        assert_eq!(p.cache_prefix.as_deref(), Some("SHARED\n\n"));
        assert!(p.user.contains("SOURCE CODE:\nCODE_BODY"));
    }

    #[test]
    fn only_open_ended_shard_chunks_share_a_shard_prefix() {
        assert!(shares_shard_prefix(
            &chunk("s", "shard-01", Some("x")),
            "discover"
        ));
        assert!(!shares_shard_prefix(&chunk("r", "", None), "discover"));
        let mut sharded_taint = taint_chunk();
        sharded_taint.shard_id = "shard-01".to_string();
        assert!(!shares_shard_prefix(&sharded_taint, "confirm_refute"));
        assert!(shares_shard_prefix(&sharded_taint, "discover"));
    }
}
