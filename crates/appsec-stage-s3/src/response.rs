use appsec_model::{Chunk, TaskManifest};
use serde_json::Value;

use crate::inventory::IdInventory;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    None,
    Ids,
    Paths,
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Shapes {
    pub shapes: Vec<Shape>,
    pub raw_paths: Vec<Vec<String>>,
}

impl Shapes {
    fn retain_indices(&mut self, kept: &[usize], total: usize) {
        if self.shapes.len() == total {
            self.shapes = kept.iter().map(|&i| self.shapes[i]).collect();
            self.raw_paths = kept
                .iter()
                .map(|&i| std::mem::take(&mut self.raw_paths[i]))
                .collect();
        } else {
            *self = Shapes::default();
        }
    }
}

fn string_items(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

pub fn prepare_chunk_shapes(data: &mut Value, inv: &IdInventory) -> Shapes {
    let mut out = Shapes::default();
    let Some(chunks) = data.get_mut("chunks").and_then(Value::as_array_mut) else {
        return out;
    };
    for item in chunks.iter_mut() {
        let Some(obj) = item.as_object_mut() else {
            out.shapes.push(Shape::None);
            out.raw_paths.push(Vec::new());
            continue;
        };
        let has_ids = obj.get("file_ids").is_some_and(Value::is_array);
        let has_paths = obj.get("files").is_some_and(Value::is_array);
        let (shape, raw) = match (has_ids, has_paths) {
            (true, true) => (Shape::Mixed, string_items(obj.get("files"))),
            (true, false) => (Shape::Ids, Vec::new()),
            (false, true) => (Shape::Paths, Vec::new()),
            (false, false) => (Shape::None, Vec::new()),
        };
        if has_ids {
            let ids = obj.remove("file_ids").unwrap_or(Value::Null);
            obj.insert("files".to_string(), ids);
        }
        out.shapes.push(shape);
        out.raw_paths.push(raw);

        let resolved: Vec<String> = string_items(obj.get("focus_entry_point_ids"))
            .iter()
            .filter_map(|eid| inv.entry_points.get(eid))
            .map(|e| e.function.clone())
            .filter(|f| !f.is_empty())
            .collect();
        if !resolved.is_empty() {
            let mut focus = string_items(obj.get("focus_entry_points"));
            for f in resolved {
                if !focus.contains(&f) {
                    focus.push(f);
                }
            }
            obj.insert(
                "focus_entry_points".to_string(),
                Value::Array(focus.into_iter().map(Value::String).collect()),
            );
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub enum Parsed {
    Whole(TaskManifest, Shapes),
    Salvaged {
        manifest: TaskManifest,
        shapes: Shapes,
        kept: usize,
        total: usize,
        error: String,
    },
    Unusable(String),
}

pub fn parse(raw: &str, inv: &IdInventory) -> Parsed {
    let mut data = match appsec_json_repair::extract_json(raw) {
        Ok(v) => v,
        Err(e) => return Parsed::Unusable(e.to_string()),
    };
    let mut shapes = prepare_chunk_shapes(&mut data, inv);
    let error = match serde_json::from_value::<TaskManifest>(data.clone()) {
        Ok(manifest) => return Parsed::Whole(manifest, shapes),
        Err(e) => e.to_string(),
    };
    let Some(items) = data.get("chunks").and_then(Value::as_array) else {
        return Parsed::Unusable(error);
    };
    let total = items.len();
    let (kept_idx, chunks): (Vec<usize>, Vec<Chunk>) = items
        .iter()
        .enumerate()
        .filter_map(|(i, item)| {
            serde_json::from_value::<Chunk>(item.clone())
                .ok()
                .map(|c| (i, c))
        })
        .unzip();
    if chunks.is_empty() {
        return Parsed::Unusable(error);
    }
    shapes.retain_indices(&kept_idx, total);
    let rationale = data
        .get("rationale")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Parsed::Salvaged {
        manifest: TaskManifest {
            chunks,
            rationale,
            unreachable_files: Vec::new(),
        },
        shapes,
        kept: kept_idx.len(),
        total,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::{ContextPackage, EntryPoint, EntryPointKind};
    use serde_json::json;

    fn inventory() -> IdInventory {
        let ctx = ContextPackage {
            all_files: vec!["a.py".into(), "b.py".into()],
            entry_points: vec![EntryPoint {
                file: "a.py".into(),
                function: "handler".into(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: true,
            }],
            ..ContextPackage::default()
        };
        IdInventory::build(&ctx)
    }

    #[test]
    fn shapes_are_recorded_per_chunk_and_file_ids_move_into_files() {
        let mut data = json!({"chunks": [
            {"id": "c1", "file_ids": ["F001"]},
            {"id": "c2", "files": ["a.py"]},
            {"id": "c3", "file_ids": ["F002"], "files": ["b.py", 7]},
            {"id": "c4"},
            "not an object",
        ]});
        let shapes = prepare_chunk_shapes(&mut data, &inventory());
        assert_eq!(
            shapes.shapes,
            vec![
                Shape::Ids,
                Shape::Paths,
                Shape::Mixed,
                Shape::None,
                Shape::None
            ]
        );
        assert_eq!(shapes.raw_paths[2], vec!["b.py".to_string()]);
        assert!(shapes.raw_paths[0].is_empty());
        assert_eq!(data["chunks"][0]["files"], json!(["F001"]));
        assert!(data["chunks"][0].get("file_ids").is_none());
        assert_eq!(data["chunks"][2]["files"], json!(["F002"]));
    }

    #[test]
    fn focus_entry_point_ids_resolve_to_function_names_without_duplicates() {
        let mut data = json!({"chunks": [
            {"id": "c1", "focus_entry_point_ids": ["E001", "E999", 3],
             "focus_entry_points": ["handler", "other"]},
            {"id": "c2", "focus_entry_point_ids": ["E001"]},
            {"id": "c3", "focus_entry_point_ids": ["E404"]},
        ]});
        prepare_chunk_shapes(&mut data, &inventory());
        assert_eq!(
            data["chunks"][0]["focus_entry_points"],
            json!(["handler", "other"])
        );
        assert_eq!(data["chunks"][1]["focus_entry_points"], json!(["handler"]));
        assert!(data["chunks"][2].get("focus_entry_points").is_none());
    }

    #[test]
    fn a_reply_without_a_chunks_array_records_no_shapes() {
        let mut data = json!({"rationale": "r"});
        assert_eq!(
            prepare_chunk_shapes(&mut data, &inventory()),
            Shapes::default()
        );
    }

    #[test]
    fn a_well_formed_reply_parses_whole() {
        let raw = json!({"rationale": "r", "chunks": [{"id": "c1", "file_ids": ["F001"]}]});
        let parsed = parse(&raw.to_string(), &inventory());
        assert!(matches!(
            &parsed,
            Parsed::Whole(m, shapes)
                if m.chunks[0].files == vec!["F001".to_string()]
                    && shapes.shapes == vec![Shape::Ids]
        ));
    }

    #[test]
    fn one_off_schema_chunk_is_dropped_and_the_rest_salvaged() {
        let raw = json!({"rationale": "why", "chunks": [
            {"id": "c1", "file_ids": ["F001"]},
            {"file_ids": ["F002"]},
            {"id": "c3", "files": ["b.py"]},
        ]});
        let parsed = parse(&raw.to_string(), &inventory());
        let ids = |m: &TaskManifest| m.chunks.iter().map(|c| c.id.clone()).collect::<Vec<_>>();
        assert!(matches!(
            &parsed,
            Parsed::Salvaged { manifest, shapes, kept: 2, total: 3, error }
                if manifest.rationale == "why"
                    && ids(manifest) == vec!["c1", "c3"]
                    && shapes.shapes == vec![Shape::Ids, Shape::Paths]
                    && shapes.raw_paths.len() == 2
                    && !error.is_empty()
        ));
    }

    #[test]
    fn a_salvaged_reply_with_a_non_string_rationale_keeps_an_empty_one() {
        let raw = json!({"rationale": 5, "unreachable_files": 3, "chunks": [{"id": "c1"}]});
        let parsed = parse(&raw.to_string(), &inventory());
        assert!(
            matches!(&parsed, Parsed::Salvaged { manifest, .. } if manifest.rationale.is_empty())
        );
    }

    #[test]
    fn nothing_salvageable_is_unusable() {
        let inv = inventory();
        assert!(matches!(parse("not json {{{", &inv), Parsed::Unusable(_)));
        assert!(matches!(parse("{}", &inv), Parsed::Unusable(_)));
        let raw = json!({"chunks": [{"no_id": true}]}).to_string();
        assert!(matches!(parse(&raw, &inv), Parsed::Unusable(_)));
    }

    #[test]
    fn retain_indices_clears_misaligned_shapes() {
        let mut s = Shapes {
            shapes: vec![Shape::Ids],
            raw_paths: vec![Vec::new()],
        };
        s.retain_indices(&[0], 2);
        assert_eq!(s, Shapes::default());
    }
}
