use appsec_model::{Chunk, ContextPackage};

use crate::prompts::{
    build_confirm_refute_prompt, build_prompt, build_shard_prompt, shard_source_block,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepdivePrompt {
    pub user: String,
    pub cache_prefix: Option<String>,
    pub cache_key: String,
}

pub fn uses_confirm_refute(chunk: &Chunk, taint_prompt_mode: &str) -> bool {
    !chunk.path_funcs.is_empty() && taint_prompt_mode == "confirm_refute"
}

pub fn shares_shard_prefix(chunk: &Chunk, taint_prompt_mode: &str) -> bool {
    !chunk.shard_id.is_empty() && !uses_confirm_refute(chunk, taint_prompt_mode)
}

pub fn cache_key(chunk: &Chunk) -> String {
    let bucket = if chunk.shard_id.is_empty() {
        "shared"
    } else {
        chunk.shard_id.as_str()
    };
    format!("s4:{bucket}")
}

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
    use appsec_model::ChunkSize;

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
