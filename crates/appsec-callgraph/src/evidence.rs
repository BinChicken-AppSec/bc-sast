use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::graph::{fn_id, resolve_called_fids};
use crate::scan::{
    CallArgFact, CallSite, ContainerWriteFact, FieldReadFact, FieldWriteFact, FileIndex,
    ReflectionFact, ResponseDataflowFact, ReturnFact, VarAssignFact,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaintSymbolRef {
    pub qnode: String,
    pub symbol: String,
    pub kind: String,
}

impl TaintSymbolRef {
    fn new(qnode: &str, symbol: impl Into<String>, kind: &str) -> Self {
        TaintSymbolRef {
            qnode: qnode.to_string(),
            symbol: symbol.into(),
            kind: kind.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaintTransferEdge {
    pub file: String,
    pub line: usize,
    pub function_qnode: String,
    pub src: TaintSymbolRef,
    pub dst: TaintSymbolRef,
    pub transfer_kind: String,
    pub reflected_targets: Vec<String>,
    pub confidence: Option<String>,
    pub is_speculative: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaintEvidencePath {
    pub source_ref: String,
    pub sink_ref: String,
    pub path_funcs: Vec<String>,
    pub edges: Vec<TaintTransferEdge>,
    pub sink_cwe: Vec<String>,
    pub sanitized: bool,
}

const SANITIZER_NAMES: &[&str] = &[
    "escape",
    "quote",
    "sanitize",
    "clean",
    "encode",
    "validate",
    "strip_tags",
    "html_escape",
    "xml_escape",
    "quote_plus",
    "urlencode",
    "bleach_clean",
    "prepared_statement",
    "parameterized",
    "to_int",
    "int",
    "float",
    "bool",
];

fn param_symbol(slot: usize) -> String {
    format!("__p{slot}")
}

#[derive(Debug, Default)]
pub struct FactIndex<'a> {
    assigns: BTreeMap<String, Vec<&'a VarAssignFact>>,
    returns: BTreeMap<String, Vec<&'a ReturnFact>>,
    call_args: BTreeMap<String, Vec<&'a CallArgFact>>,
    field_writes: BTreeMap<String, Vec<&'a FieldWriteFact>>,
    field_reads: BTreeMap<String, Vec<&'a FieldReadFact>>,
    container_writes: BTreeMap<String, Vec<&'a ContainerWriteFact>>,
    params: BTreeMap<String, &'a [String]>,
}

impl<'a> FactIndex<'a> {
    pub fn build(indices: &'a [FileIndex]) -> Self {
        let mut out = FactIndex::default();
        for idx in indices {
            for f in &idx.functions {
                if !f.params.is_empty() {
                    out.params
                        .entry(fn_id(&idx.file, &f.name))
                        .or_insert(&f.params);
                }
            }
            for a in &idx.assigns {
                out.assigns
                    .entry(fn_id(&idx.file, &a.function_qnode))
                    .or_default()
                    .push(a);
            }
            for r in &idx.returns {
                out.returns
                    .entry(fn_id(&idx.file, &r.function_qnode))
                    .or_default()
                    .push(r);
            }
            for c in &idx.call_args {
                out.call_args
                    .entry(fn_id(&idx.file, &c.function_qnode))
                    .or_default()
                    .push(c);
            }
            for f in &idx.field_writes {
                out.field_writes
                    .entry(fn_id(&idx.file, &f.function_qnode))
                    .or_default()
                    .push(f);
            }
            for f in &idx.field_reads {
                out.field_reads
                    .entry(fn_id(&idx.file, &f.function_qnode))
                    .or_default()
                    .push(f);
            }
            for c in &idx.container_writes {
                out.container_writes
                    .entry(fn_id(&idx.file, &c.function_qnode))
                    .or_default()
                    .push(c);
            }
        }
        out
    }

    pub fn has_phase1_facts(&self, path_fids: &[String]) -> bool {
        path_fids.iter().any(|fid| {
            self.assigns.contains_key(fid)
                || self.returns.contains_key(fid)
                || self.call_args.contains_key(fid)
        })
    }
}

pub struct PathResolver<'a> {
    pub fn_defs_by_name: &'a BTreeMap<String, Vec<String>>,
    pub fn_meta: &'a BTreeMap<String, (String, usize, usize)>,
    pub file_index: &'a BTreeMap<String, &'a FileIndex>,
    pub max_targets: usize,
}

impl PathResolver<'_> {
    fn targets_for(&self, caller_file: &str, cf: &CallArgFact) -> Vec<String> {
        resolve_called_fids(
            caller_file,
            &cf.function_qnode,
            &cf.receiver,
            &cf.callee_name,
            self.fn_defs_by_name,
            self.fn_meta,
            self.file_index,
            self.max_targets,
        )
    }
}

fn find_matching_call_facts<'a>(
    call_facts: &[&'a CallArgFact],
    line: usize,
    method: &str,
    receiver: &str,
) -> Vec<&'a CallArgFact> {
    call_facts
        .iter()
        .filter(|cf| cf.line == line && cf.callee_name == method)
        .filter(|cf| receiver.is_empty() || cf.receiver.is_empty() || receiver == cf.receiver)
        .copied()
        .collect()
}

#[derive(Default)]
struct TaintState {
    tainted_locals: BTreeSet<String>,
    local_origin: BTreeMap<String, String>,
    tainted_param_slots: BTreeSet<usize>,
    param_slot_of: BTreeMap<String, usize>,
    params_known: bool,
    tainted_fields: BTreeSet<(String, String)>,
    tainted_containers: BTreeSet<String>,
    sanitized_locals: BTreeSet<String>,
}

fn seed_source_taint(
    src_fid: &str,
    source: &CallSite,
    facts: &FactIndex,
    state: &mut TaintState,
) -> Vec<TaintTransferEdge> {
    let mut edges = Vec::new();
    let src_ref = TaintSymbolRef::new(src_fid, format!("source@{}", source.line), "arg");
    let empty = Vec::new();
    let call_facts = find_matching_call_facts(
        facts.call_args.get(src_fid).unwrap_or(&empty),
        source.line,
        &source.method,
        &source.receiver,
    );
    for cf in call_facts {
        let Some(target) = cf.target_symbol.as_ref().filter(|t| !t.is_empty()) else {
            continue;
        };
        state.tainted_locals.insert(target.clone());
        state
            .local_origin
            .insert(target.clone(), "source".to_string());
        edges.push(TaintTransferEdge {
            file: source.file.clone(),
            line: source.line,
            function_qnode: src_fid.to_string(),
            src: src_ref.clone(),
            dst: TaintSymbolRef::new(src_fid, target.clone(), "local"),
            transfer_kind: "source".to_string(),
            ..Default::default()
        });
    }
    edges
}

fn apply_field_writes(
    fid: &str,
    file: &str,
    field_writes: &[&FieldWriteFact],
    state: &mut TaintState,
) -> Vec<TaintTransferEdge> {
    let mut edges = Vec::new();
    for fw in field_writes {
        let Some(src_sym) = fw.src_symbol.as_ref().filter(|s| !s.is_empty()) else {
            continue;
        };
        if !state.tainted_locals.contains(src_sym) {
            continue;
        }
        let key = (fw.receiver.clone(), fw.field.clone());
        if !state.tainted_fields.insert(key) {
            continue;
        }
        edges.push(TaintTransferEdge {
            file: file.to_string(),
            line: fw.line,
            function_qnode: fid.to_string(),
            src: TaintSymbolRef::new(fid, src_sym.clone(), "local"),
            dst: TaintSymbolRef::new(fid, format!("{}.{}", fw.receiver, fw.field), "field"),
            transfer_kind: "field_write".to_string(),
            ..Default::default()
        });
    }
    edges
}

fn apply_field_reads(
    fid: &str,
    file: &str,
    field_reads: &[&FieldReadFact],
    state: &mut TaintState,
) -> Vec<TaintTransferEdge> {
    let mut edges = Vec::new();
    for fr in field_reads {
        let Some(dst_sym) = fr.dst_symbol.as_ref().filter(|s| !s.is_empty()) else {
            continue;
        };
        let exact = (fr.receiver.clone(), fr.field.clone());
        let wildcard = (fr.receiver.clone(), "*".to_string());
        if !state.tainted_fields.contains(&exact) && !state.tainted_fields.contains(&wildcard) {
            continue;
        }
        if !state.tainted_locals.insert(dst_sym.clone()) {
            continue;
        }
        edges.push(TaintTransferEdge {
            file: file.to_string(),
            line: fr.line,
            function_qnode: fid.to_string(),
            src: TaintSymbolRef::new(fid, format!("{}.{}", fr.receiver, fr.field), "field"),
            dst: TaintSymbolRef::new(fid, dst_sym.clone(), "local"),
            transfer_kind: "field_read".to_string(),
            ..Default::default()
        });
    }
    edges
}

fn apply_container_writes(
    fid: &str,
    file: &str,
    container_writes: &[&ContainerWriteFact],
    state: &mut TaintState,
) -> Vec<TaintTransferEdge> {
    let mut edges = Vec::new();
    for cw in container_writes {
        let Some(element) = cw.element_symbol.as_ref().filter(|s| !s.is_empty()) else {
            continue;
        };
        if !state.tainted_locals.contains(element) {
            continue;
        }
        if !state.tainted_containers.insert(cw.container_symbol.clone()) {
            continue;
        }
        edges.push(TaintTransferEdge {
            file: file.to_string(),
            line: cw.line,
            function_qnode: fid.to_string(),
            src: TaintSymbolRef::new(fid, element.clone(), "local"),
            dst: TaintSymbolRef::new(fid, cw.container_symbol.clone(), "container"),
            transfer_kind: "container_put".to_string(),
            ..Default::default()
        });
    }
    edges
}

fn apply_sanitizers(
    fid: &str,
    file: &str,
    call_facts: &[&CallArgFact],
    state: &mut TaintState,
) -> Vec<TaintTransferEdge> {
    let mut edges = Vec::new();
    for cf in call_facts {
        if !SANITIZER_NAMES.contains(&cf.callee_name.as_str()) {
            continue;
        }
        let dst_sym = cf
            .target_symbol
            .clone()
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| "__sanitized".to_string());
        let tainted_inputs: Vec<String> = cf
            .arg_symbols
            .iter()
            .filter(|s| state.tainted_locals.contains(*s))
            .cloned()
            .collect();
        let tainted_containers: Vec<String> = cf
            .arg_symbols
            .iter()
            .filter(|s| state.tainted_containers.contains(*s))
            .cloned()
            .collect();
        if tainted_inputs.is_empty() && tainted_containers.is_empty() {
            continue;
        }
        for s in tainted_inputs {
            state.tainted_locals.remove(&s);
            edges.push(TaintTransferEdge {
                file: file.to_string(),
                line: cf.line,
                function_qnode: fid.to_string(),
                src: TaintSymbolRef::new(fid, s, "local"),
                dst: TaintSymbolRef::new(fid, dst_sym.clone(), "local"),
                transfer_kind: "sanitize".to_string(),
                ..Default::default()
            });
        }
        for s in tainted_containers {
            state.tainted_containers.remove(&s);
            edges.push(TaintTransferEdge {
                file: file.to_string(),
                line: cf.line,
                function_qnode: fid.to_string(),
                src: TaintSymbolRef::new(fid, s, "container"),
                dst: TaintSymbolRef::new(fid, dst_sym.clone(), "local"),
                transfer_kind: "sanitize".to_string(),
                ..Default::default()
            });
        }
        if let Some(target) = cf.target_symbol.as_ref().filter(|t| !t.is_empty()) {
            state.sanitized_locals.insert(target.clone());
        }
    }
    edges
}

fn apply_local_aliases(
    fid: &str,
    file: &str,
    assigns: &[&VarAssignFact],
    state: &mut TaintState,
) -> Vec<TaintTransferEdge> {
    let mut edges = Vec::new();
    let mut changed = true;
    while changed {
        changed = false;
        for a in assigns {
            let Some(src_sym) = a.src_symbol.as_ref().filter(|s| !s.is_empty()) else {
                continue;
            };
            if a.dst_symbol.is_empty() {
                continue;
            }
            if !state.tainted_locals.contains(src_sym)
                || state.tainted_locals.contains(&a.dst_symbol)
            {
                continue;
            }
            state.tainted_locals.insert(a.dst_symbol.clone());
            let origin = state
                .local_origin
                .get(src_sym)
                .cloned()
                .unwrap_or_else(|| "local".to_string());
            state.local_origin.insert(a.dst_symbol.clone(), origin);
            edges.push(TaintTransferEdge {
                file: file.to_string(),
                line: a.line,
                function_qnode: fid.to_string(),
                src: TaintSymbolRef::new(fid, src_sym.clone(), "local"),
                dst: TaintSymbolRef::new(fid, a.dst_symbol.clone(), "local"),
                transfer_kind: "assign".to_string(),
                ..Default::default()
            });
            changed = true;
        }
    }
    edges
}

fn call_tainted_arg_slots(
    cf: &CallArgFact,
    state: &TaintState,
    include_containers: bool,
) -> BTreeMap<usize, (String, String)> {
    let mut out = BTreeMap::new();
    for (idx, sym) in cf.arg_symbols.iter().enumerate() {
        let slot = cf.arg_slots.get(idx).copied().unwrap_or(idx);
        if out.contains_key(&slot) {
            continue;
        }
        if state.tainted_locals.contains(sym) {
            let entry = match state.param_slot_of.get(sym) {
                Some(p) => (param_symbol(*p), "param".to_string()),
                None => (sym.clone(), "local".to_string()),
            };
            out.insert(slot, entry);
        } else if !state.params_known && state.tainted_param_slots.contains(&slot) {
            out.insert(slot, (param_symbol(slot), "param".to_string()));
        } else if include_containers && state.tainted_containers.contains(sym) {
            out.insert(slot, (sym.clone(), "container".to_string()));
        }
    }
    out
}

fn callee_may_return_tainted(callee_fid: &str, facts: &FactIndex) -> bool {
    facts
        .returns
        .get(callee_fid)
        .is_some_and(|rets| rets.iter().any(|r| r.symbol.is_some()))
}

fn apply_return_to_local(
    fid: &str,
    file: &str,
    facts: &FactIndex,
    resolver: &PathResolver,
    state: &mut TaintState,
) -> Vec<TaintTransferEdge> {
    let mut edges = Vec::new();
    let empty = Vec::new();
    let call_facts: Vec<&CallArgFact> = facts.call_args.get(fid).unwrap_or(&empty).to_vec();
    for cf in call_facts {
        let Some(target) = cf.target_symbol.as_ref().filter(|t| !t.is_empty()) else {
            continue;
        };
        if call_tainted_arg_slots(cf, state, false).is_empty() {
            continue;
        }
        let targets = resolver.targets_for(file, cf);
        if targets.is_empty() {
            continue;
        }
        if !targets
            .iter()
            .any(|callee| callee_may_return_tainted(callee, facts))
        {
            continue;
        }
        if !state.tainted_locals.insert(target.clone()) {
            continue;
        }
        state
            .local_origin
            .insert(target.clone(), "return".to_string());
        edges.push(TaintTransferEdge {
            file: file.to_string(),
            line: cf.line,
            function_qnode: fid.to_string(),
            src: TaintSymbolRef::new(&targets[0], "return", "return"),
            dst: TaintSymbolRef::new(fid, target.clone(), "local"),
            transfer_kind: "return_to_local".to_string(),
            ..Default::default()
        });
    }
    edges
}

fn transfer_closure(
    fid: &str,
    file: &str,
    facts: &FactIndex,
    resolver: &PathResolver,
    state: &mut TaintState,
) -> Vec<TaintTransferEdge> {
    let mut edges = Vec::new();
    let empty_calls: Vec<&CallArgFact> = Vec::new();
    let empty_fw: Vec<&FieldWriteFact> = Vec::new();
    let empty_fr: Vec<&FieldReadFact> = Vec::new();
    let empty_cw: Vec<&ContainerWriteFact> = Vec::new();
    let empty_as: Vec<&VarAssignFact> = Vec::new();
    loop {
        let before = (
            state.tainted_locals.len(),
            state.tainted_fields.len(),
            state.tainted_containers.len(),
        );
        edges.extend(apply_sanitizers(
            fid,
            file,
            facts.call_args.get(fid).unwrap_or(&empty_calls),
            state,
        ));
        edges.extend(apply_field_writes(
            fid,
            file,
            facts.field_writes.get(fid).unwrap_or(&empty_fw),
            state,
        ));
        edges.extend(apply_field_reads(
            fid,
            file,
            facts.field_reads.get(fid).unwrap_or(&empty_fr),
            state,
        ));
        edges.extend(apply_container_writes(
            fid,
            file,
            facts.container_writes.get(fid).unwrap_or(&empty_cw),
            state,
        ));
        edges.extend(apply_local_aliases(
            fid,
            file,
            facts.assigns.get(fid).unwrap_or(&empty_as),
            state,
        ));
        edges.extend(apply_return_to_local(fid, file, facts, resolver, state));
        let after = (
            state.tainted_locals.len(),
            state.tainted_fields.len(),
            state.tainted_containers.len(),
        );
        if after.0 <= before.0 && after.1 <= before.1 && after.2 <= before.2 {
            break;
        }
    }
    edges
}

pub fn build_taint_evidence_for_path(
    source: &CallSite,
    sink: &CallSite,
    path_fids: &[String],
    facts: &FactIndex,
    resolver: &PathResolver,
) -> Option<TaintEvidencePath> {
    let src_fid = path_fids.first()?;
    let src_ref = format!("{}:{}", source.file, source.line);
    let sink_ref = format!("{}:{}", sink.file, sink.line);

    let mut state = TaintState::default();
    let mut edges = seed_source_taint(src_fid, source, facts, &mut state);
    let empty_calls: Vec<&CallArgFact> = Vec::new();

    for (idx, fid) in path_fids.iter().enumerate() {
        let file = resolver
            .fn_meta
            .get(fid)
            .map(|(f, _, _)| f.clone())
            .unwrap_or_else(|| source.file.clone());

        edges.extend(transfer_closure(fid, &file, facts, resolver, &mut state));

        if idx == path_fids.len() - 1 {
            let sink_calls = find_matching_call_facts(
                facts.call_args.get(fid).unwrap_or(&empty_calls),
                sink.line,
                &sink.method,
                &sink.receiver,
            );
            for cf in sink_calls {
                let slots = call_tainted_arg_slots(cf, &state, true);
                if !slots.is_empty() {
                    for (slot, (sym, kind)) in &slots {
                        if kind == "container" {
                            edges.push(TaintTransferEdge {
                                file: sink.file.clone(),
                                line: sink.line,
                                function_qnode: fid.clone(),
                                src: TaintSymbolRef::new(fid, sym.clone(), "container"),
                                dst: TaintSymbolRef::new(fid, format!("arg{slot}"), "arg"),
                                transfer_kind: "container_get".to_string(),
                                ..Default::default()
                            });
                            continue;
                        }
                        let transfer = if kind == "local"
                            && state.local_origin.get(sym).map(String::as_str) == Some("return")
                        {
                            "return_to_sink"
                        } else {
                            "local_to_sink"
                        };
                        edges.push(TaintTransferEdge {
                            file: sink.file.clone(),
                            line: sink.line,
                            function_qnode: fid.clone(),
                            src: TaintSymbolRef::new(fid, sym.clone(), kind),
                            dst: TaintSymbolRef::new(fid, format!("arg{slot}"), "arg"),
                            transfer_kind: transfer.to_string(),
                            ..Default::default()
                        });
                    }
                    return Some(TaintEvidencePath {
                        source_ref: src_ref,
                        sink_ref,
                        path_funcs: path_fids.to_vec(),
                        edges,
                        sink_cwe: sink_cwe_of(sink),
                        sanitized: false,
                    });
                }
                if !state.sanitized_locals.is_empty()
                    && cf
                        .arg_symbols
                        .iter()
                        .any(|a| state.sanitized_locals.contains(a))
                {
                    return Some(TaintEvidencePath {
                        source_ref: src_ref,
                        sink_ref,
                        path_funcs: path_fids.to_vec(),
                        edges,
                        sink_cwe: sink_cwe_of(sink),
                        sanitized: true,
                    });
                }
            }
            return None;
        }

        let next_fid = &path_fids[idx + 1];
        let mut next_slots: BTreeSet<usize> = BTreeSet::new();
        let mut next_edges: Vec<TaintTransferEdge> = Vec::new();
        for cf in facts.call_args.get(fid).unwrap_or(&empty_calls) {
            if !resolver
                .targets_for(&file, cf)
                .iter()
                .any(|t| t == next_fid)
            {
                continue;
            }
            let slots = call_tainted_arg_slots(cf, &state, false);
            if slots.is_empty() {
                continue;
            }
            for (slot, (sym, kind)) in &slots {
                next_slots.insert(*slot);
                next_edges.push(TaintTransferEdge {
                    file: file.clone(),
                    line: cf.line,
                    function_qnode: fid.clone(),
                    src: TaintSymbolRef::new(fid, sym.clone(), kind),
                    dst: TaintSymbolRef::new(next_fid, param_symbol(*slot), "param"),
                    transfer_kind: "arg_to_param".to_string(),
                    ..Default::default()
                });
            }
        }
        if next_slots.is_empty() {
            let sanitized_crosses = !state.sanitized_locals.is_empty()
                && facts
                    .call_args
                    .get(fid)
                    .unwrap_or(&empty_calls)
                    .iter()
                    .any(|cf| {
                        cf.arg_symbols
                            .iter()
                            .any(|a| state.sanitized_locals.contains(a))
                            && resolver
                                .targets_for(&file, cf)
                                .iter()
                                .any(|t| t == next_fid)
                    });
            if sanitized_crosses {
                return Some(TaintEvidencePath {
                    source_ref: src_ref,
                    sink_ref,
                    path_funcs: path_fids.to_vec(),
                    edges,
                    sink_cwe: sink_cwe_of(sink),
                    sanitized: true,
                });
            }
            return None;
        }
        edges.extend(next_edges);
        state.tainted_param_slots = next_slots;
        state.tainted_locals.clear();
        state.local_origin.clear();
        state.param_slot_of.clear();
        state.params_known = facts.params.contains_key(next_fid);
        if let Some(names) = facts.params.get(next_fid) {
            for slot in &state.tainted_param_slots {
                if let Some(name) = names.get(*slot) {
                    state.tainted_locals.insert(name.clone());
                    state.local_origin.insert(name.clone(), "param".to_string());
                    state.param_slot_of.insert(name.clone(), *slot);
                }
            }
        }
        state.tainted_fields.clear();
        state.tainted_containers.clear();
    }

    None
}

fn sink_cwe_of(sink: &CallSite) -> Vec<String> {
    if sink.cwe.is_empty() {
        Vec::new()
    } else {
        vec![sink.cwe.clone()]
    }
}

pub fn fallback_evidence(
    source: &CallSite,
    sink: &CallSite,
    path_fids: &[String],
) -> TaintEvidencePath {
    TaintEvidencePath {
        source_ref: format!("{}:{}", source.file, source.line),
        sink_ref: format!("{}:{}", sink.file, sink.line),
        path_funcs: path_fids.to_vec(),
        edges: Vec::new(),
        sink_cwe: sink_cwe_of(sink),
        sanitized: false,
    }
}

pub fn build_symbol_table(indices: &[FileIndex]) -> BTreeSet<String> {
    let mut table = BTreeSet::new();
    for idx in indices {
        for fd in &idx.functions {
            table.insert(fn_id(&idx.file, &fd.name));
            table.insert(fd.name.clone());
            if !fd.class_name.is_empty() {
                table.insert(format!("{}.{}", fd.class_name, fd.name));
            }
        }
    }
    table
}

static LITERAL_NAME_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_$][A-Za-z0-9_.$]*$").unwrap());

fn confidence_rank(c: &str) -> u8 {
    match c {
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

fn raise_confidence(current: &str, floor: &str) -> String {
    if confidence_rank(floor) > confidence_rank(current) {
        floor.to_string()
    } else {
        current.to_string()
    }
}

pub fn resolve_reflection_targets(
    fact: &ReflectionFact,
    symbol_table: &BTreeSet<String>,
) -> (Vec<String>, String) {
    let mut targets: Vec<String> = Vec::new();
    let mut confidence = "low".to_string();

    for sym in &fact.target_symbols {
        let sym = sym.trim();
        if sym.is_empty() {
            continue;
        }
        if !LITERAL_NAME_RX.is_match(sym) {
            targets.push("*UNKNOWN*".to_string());
            continue;
        }
        if symbol_table.contains(sym) {
            targets.push(sym.to_string());
            confidence = "high".to_string();
            continue;
        }
        let suffixed: Vec<&String> = symbol_table
            .iter()
            .filter(|k| k.ends_with(&format!(".{sym}")) || k.ends_with(&format!("::{sym}")))
            .collect();
        if !suffixed.is_empty() {
            targets.extend(suffixed.iter().take(3).map(|k| (*k).clone()));
            confidence = if suffixed.len() == 1 {
                "high"
            } else {
                "medium"
            }
            .to_string();
            continue;
        }
        targets.push(sym.to_string());
        confidence = raise_confidence(&confidence, "medium");
    }

    if targets.is_empty() {
        targets.push("*UNKNOWN*".to_string());
    }
    (targets, confidence)
}

fn emit_reflection_taint_edges(
    source_sym: &TaintSymbolRef,
    fact: &ReflectionFact,
    resolved: &[String],
    confidence: &str,
) -> Vec<TaintTransferEdge> {
    let file = source_sym
        .qnode
        .split_once("::")
        .map(|(f, _)| f.to_string())
        .unwrap_or_default();
    resolved
        .iter()
        .map(|target| TaintTransferEdge {
            file: file.clone(),
            line: fact.line,
            function_qnode: fact.function_qnode.clone(),
            src: source_sym.clone(),
            dst: TaintSymbolRef::new(target, target.clone(), "local"),
            transfer_kind: "reflect".to_string(),
            reflected_targets: resolved.to_vec(),
            confidence: Some(confidence.to_string()),
            is_speculative: Some(true),
        })
        .collect()
}

pub fn apply_reflection_to_taint(
    taint_state: &BTreeSet<String>,
    reflection_facts: &[ReflectionFact],
    symbol_table: &BTreeSet<String>,
    fid: &str,
) -> Vec<TaintTransferEdge> {
    let mut emitted = Vec::new();
    for rf in reflection_facts {
        if !rf.function_qnode.is_empty() {
            let bare = rf.function_qnode.rsplit("::").next().unwrap_or_default();
            if !fid.ends_with(bare) {
                continue;
            }
        }
        let tainted_inputs: Vec<&String> = rf
            .target_symbols
            .iter()
            .filter(|s| taint_state.contains(*s))
            .collect();
        if tainted_inputs.is_empty() {
            continue;
        }
        let (resolved, conf) = resolve_reflection_targets(rf, symbol_table);
        for sym in tainted_inputs {
            let source_sym = TaintSymbolRef::new(fid, sym.clone(), "local");
            emitted.extend(emit_reflection_taint_edges(
                &source_sym,
                rf,
                &resolved,
                &conf,
            ));
        }
    }
    emitted
}

pub fn emit_framework_entry_points(indices: &[FileIndex]) -> Vec<crate::EntryPoint> {
    let mut defined_in: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for idx in indices {
        for f in &idx.functions {
            defined_in
                .entry(f.name.as_str())
                .or_default()
                .insert(idx.file.as_str());
        }
    }
    let mut out = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let qualified_guards: BTreeSet<&str> = indices
        .iter()
        .flat_map(|idx| idx.auth_guards.iter())
        .filter(|g| g.requires_auth && g.function_qnode.contains('#'))
        .map(|g| g.function_qnode.as_str())
        .collect();
    for idx in indices {
        let mut guarded: BTreeMap<&str, bool> = BTreeMap::new();
        for g in &idx.auth_guards {
            let e = guarded.entry(g.function_qnode.as_str()).or_insert(true);
            *e = *e && g.requires_auth;
        }
        let qnodes = idx
            .framework_markers
            .iter()
            .map(|m| m.function_qnode.as_str())
            .chain(idx.route_facts.iter().map(|r| r.function_qnode.as_str()));
        for qnode in qnodes {
            if qnode.is_empty() {
                continue;
            }
            let fn_name = qnode.rsplit("::").next().unwrap_or(qnode).to_string();
            let owners = defined_in.get(fn_name.as_str());
            let file = match owners {
                Some(files) if files.contains(idx.file.as_str()) => idx.file.clone(),
                Some(files) if files.len() == 1 => (*files.iter().next().unwrap()).to_string(),
                _ => idx.file.clone(),
            };
            if !seen.insert((file.clone(), fn_name.clone())) {
                continue;
            }
            let reachable_from_unauth = !guarded.get(fn_name.as_str()).copied().unwrap_or(false)
                && !qualified_guards.contains(fn_name.as_str());
            out.push(crate::EntryPoint {
                file,
                function: fn_name,
                kind: "framework".to_string(),
                reachable_from_unauth,
            });
        }
    }
    out
}

fn response_type_cwe(response_type: &str) -> &'static str {
    match response_type {
        "html" => "CWE-79",
        "xml" => "CWE-611",
        "text" => "CWE-117",
        _ => "CWE-90",
    }
}

pub fn response_dataflow_by_fid(
    indices: &[FileIndex],
) -> BTreeMap<String, Vec<&ResponseDataflowFact>> {
    let mut out: BTreeMap<String, Vec<&ResponseDataflowFact>> = BTreeMap::new();
    for idx in indices {
        for rdf in &idx.response_dataflow {
            if rdf.function_qnode.is_empty() {
                continue;
            }
            out.entry(fn_id(&idx.file, &rdf.function_qnode))
                .or_default()
                .push(rdf);
        }
    }
    out
}

pub fn apply_response_dataflow(
    evidence: &mut [TaintEvidencePath],
    by_fid: &BTreeMap<String, Vec<&ResponseDataflowFact>>,
) {
    if by_fid.is_empty() {
        return;
    }
    for ep in evidence.iter_mut() {
        let mut extra: BTreeSet<String> = BTreeSet::new();
        for pf in &ep.path_funcs {
            for rdf in by_fid.get(pf).into_iter().flatten() {
                extra.insert(response_type_cwe(&rdf.response_type).to_string());
            }
        }
        if extra.is_empty() {
            continue;
        }
        let mut merged: BTreeSet<String> = ep.sink_cwe.iter().cloned().collect();
        merged.extend(extra);
        ep.sink_cwe = merged.into_iter().collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{FrameworkMarkerFact, FuncDef, RouteTaintFact};

    fn index(file: &str) -> FileIndex {
        FileIndex {
            file: file.to_string(),
            language: "python".to_string(),
            ..Default::default()
        }
    }

    fn func(name: &str) -> FuncDef {
        FuncDef {
            name: name.to_string(),
            start_line: 1,
            end_line: 99,
            class_name: String::new(),
            params: Vec::new(),
        }
    }

    fn site(file: &str, line: usize, containing_fn: &str, method: &str, cwe: &str) -> CallSite {
        CallSite {
            file: file.to_string(),
            line,
            receiver: String::new(),
            method: method.to_string(),
            containing_fn: containing_fn.to_string(),
            snippet: String::new(),
            matched_rule: "r".to_string(),
            cwe: cwe.to_string(),
            role: "source".to_string(),
            kind: "network".to_string(),
            semantic_family: String::new(),
            owasp_top10_2025: Vec::new(),
        }
    }

    fn call(
        f: &str,
        line: usize,
        callee: &str,
        args: &[&str],
        target: Option<&str>,
    ) -> CallArgFact {
        CallArgFact {
            function_qnode: f.to_string(),
            line,
            callee_name: callee.to_string(),
            receiver: String::new(),
            arg_symbols: args.iter().map(|s| s.to_string()).collect(),
            arg_slots: Vec::new(),
            target_symbol: target.map(String::from),
        }
    }

    #[test]
    fn a_tainted_symbol_taints_the_slot_it_was_passed_in_not_its_list_index() {
        let mut cf = call("f", 3, "g", &["x"], None);
        cf.arg_slots = vec![1];
        let state = TaintState {
            tainted_locals: ["x".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let slots = call_tainted_arg_slots(&cf, &state, false);
        assert_eq!(slots.keys().copied().collect::<Vec<_>>(), vec![1]);

        let mut both = call("f", 3, "g", &["x", "y"], None);
        both.arg_slots = vec![0, 0];
        let state = TaintState {
            tainted_locals: ["x".to_string(), "y".to_string()].into_iter().collect(),
            ..Default::default()
        };
        let slots = call_tainted_arg_slots(&both, &state, false);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[&0].0, "x");
    }

    fn assign(f: &str, line: usize, dst: &str, src: Option<&str>) -> VarAssignFact {
        VarAssignFact {
            function_qnode: f.to_string(),
            line,
            dst_symbol: dst.to_string(),
            src_symbol: src.map(String::from),
            src_call: None,
        }
    }

    fn evidence_of(
        indices: &[FileIndex],
        source: &CallSite,
        sink: &CallSite,
        path: &[&str],
    ) -> Option<TaintEvidencePath> {
        let facts = FactIndex::build(indices);
        let mut fn_defs_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut fn_meta: BTreeMap<String, (String, usize, usize)> = BTreeMap::new();
        let mut file_index: BTreeMap<String, &FileIndex> = BTreeMap::new();
        for i in indices {
            file_index.insert(i.file.clone(), i);
            for fd in &i.functions {
                let fid = fn_id(&i.file, &fd.name);
                fn_meta.insert(fid.clone(), (i.file.clone(), fd.start_line, fd.end_line));
                fn_defs_by_name
                    .entry(fd.name.clone())
                    .or_default()
                    .push(fid);
            }
        }
        let resolver = PathResolver {
            fn_defs_by_name: &fn_defs_by_name,
            fn_meta: &fn_meta,
            file_index: &file_index,
            max_targets: 3,
        };
        let path: Vec<String> = path.iter().map(|s| s.to_string()).collect();
        build_taint_evidence_for_path(source, sink, &path, &facts, &resolver)
    }

    fn kinds(ev: &TaintEvidencePath) -> Vec<&str> {
        ev.edges.iter().map(|e| e.transfer_kind.as_str()).collect()
    }

    #[test]
    fn has_phase1_facts_is_false_without_any_assign_return_or_call_fact() {
        let idx = index("a.py");
        let facts = FactIndex::build(std::slice::from_ref(&idx));
        assert!(!facts.has_phase1_facts(&["a.py::f".to_string()]));
    }

    #[test]
    fn has_phase1_facts_sees_a_return_fact_on_any_path_function() {
        let mut idx = index("a.py");
        idx.returns.push(ReturnFact {
            function_qnode: "g".to_string(),
            line: 2,
            symbol: Some("x".to_string()),
        });
        let facts = FactIndex::build(std::slice::from_ref(&idx));
        assert!(facts.has_phase1_facts(&["a.py::f".to_string(), "a.py::g".to_string()]));
    }

    #[test]
    fn param_symbol_names_the_slot() {
        assert_eq!(param_symbol(2), "__p2");
    }

    #[test]
    fn fallback_evidence_carries_the_refs_but_no_edges() {
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 4, "f", "system", "CWE-78");
        let ev = fallback_evidence(&s, &k, &["a.py::f".to_string()]);
        assert_eq!(ev.source_ref, "a.py:3");
        assert_eq!(ev.sink_ref, "a.py:4");
        assert_eq!(ev.sink_cwe, vec!["CWE-78".to_string()]);
        assert!(ev.edges.is_empty());
        assert!(!ev.sanitized);
    }

    #[test]
    fn a_sink_with_no_cwe_carries_an_empty_cwe_list() {
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 4, "f", "system", "");
        assert!(fallback_evidence(&s, &k, &[]).sink_cwe.is_empty());
    }

    #[test]
    fn an_empty_path_has_no_evidence() {
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 4, "f", "system", "");
        assert!(evidence_of(&[index("a.py")], &s, &k, &[]).is_none());
    }

    #[test]
    fn a_source_assigned_and_aliased_into_a_sink_argument_is_grounded() {
        let mut idx = index("a.py");
        idx.functions.push(func("f"));
        idx.call_args.push(call("f", 3, "get", &[], Some("raw")));
        idx.assigns.push(assign("f", 4, "cmd", Some("raw")));
        idx.call_args.push(call("f", 5, "system", &["cmd"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 5, "f", "system", "CWE-78");
        let ev = evidence_of(&[idx], &s, &k, &["a.py::f"]).unwrap();
        assert_eq!(kinds(&ev), vec!["source", "assign", "local_to_sink"]);
        assert_eq!(ev.edges[0].dst.symbol, "raw");
        assert_eq!(ev.edges[2].dst.symbol, "arg0");
        assert!(!ev.sanitized);
    }

    #[test]
    fn a_source_call_with_no_assignment_target_grounds_nothing() {
        let mut idx = index("a.py");
        idx.functions.push(func("f"));
        idx.call_args.push(call("f", 3, "get", &[], None));
        idx.call_args.push(call("f", 5, "system", &["cmd"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 5, "f", "system", "CWE-78");
        assert!(evidence_of(&[idx], &s, &k, &["a.py::f"]).is_none());
    }

    #[test]
    fn a_sink_call_that_was_never_recorded_grounds_nothing() {
        let mut idx = index("a.py");
        idx.functions.push(func("f"));
        idx.call_args.push(call("f", 3, "get", &[], Some("raw")));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 5, "f", "system", "CWE-78");
        assert!(evidence_of(&[idx], &s, &k, &["a.py::f"]).is_none());
    }

    #[test]
    fn a_call_fact_with_a_different_receiver_does_not_match_the_site() {
        let mut idx = index("a.py");
        idx.functions.push(func("f"));
        let mut cf = call("f", 3, "get", &[], Some("raw"));
        cf.receiver = "other".to_string();
        idx.call_args.push(cf);
        idx.call_args.push(call("f", 5, "system", &["raw"], None));
        let mut s = site("a.py", 3, "f", "get", "");
        s.receiver = "request".to_string();
        let k = site("a.py", 5, "f", "system", "CWE-78");
        assert!(evidence_of(&[idx], &s, &k, &["a.py::f"]).is_none());
    }

    #[test]
    fn a_value_neutralized_before_the_sink_is_reported_as_sanitized() {
        let mut idx = index("a.py");
        idx.functions.push(func("f"));
        idx.call_args.push(call("f", 3, "get", &[], Some("raw")));
        idx.call_args
            .push(call("f", 4, "escape", &["raw"], Some("safe")));
        idx.call_args.push(call("f", 5, "system", &["safe"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 5, "f", "system", "CWE-78");
        let ev = evidence_of(&[idx], &s, &k, &["a.py::f"]).unwrap();
        assert!(ev.sanitized);
        assert!(kinds(&ev).contains(&"sanitize"));
    }

    #[test]
    fn a_sanitizer_with_no_assignment_target_names_a_placeholder_symbol() {
        let mut idx = index("a.py");
        idx.functions.push(func("f"));
        idx.call_args.push(call("f", 3, "get", &[], Some("raw")));
        idx.call_args.push(call("f", 4, "escape", &["raw"], None));
        idx.call_args.push(call("f", 5, "system", &["raw"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 5, "f", "system", "CWE-78");
        assert!(evidence_of(&[idx], &s, &k, &["a.py::f"]).is_none());
    }

    #[test]
    fn a_tainted_container_passed_to_a_sanitizer_is_neutralized_too() {
        let mut idx = index("a.py");
        idx.functions.push(func("f"));
        idx.call_args.push(call("f", 3, "get", &[], Some("raw")));
        idx.container_writes.push(ContainerWriteFact {
            function_qnode: "f".to_string(),
            line: 4,
            container_symbol: "bag".to_string(),
            element_symbol: Some("raw".to_string()),
        });
        idx.call_args
            .push(call("f", 5, "escape", &["bag"], Some("safe")));
        idx.call_args.push(call("f", 6, "system", &["safe"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 6, "f", "system", "CWE-78");
        let ev = evidence_of(&[idx], &s, &k, &["a.py::f"]).unwrap();
        assert!(ev.sanitized);
        assert!(ev
            .edges
            .iter()
            .any(|e| e.transfer_kind == "sanitize" && e.src.kind == "container"));
    }

    #[test]
    fn taint_travels_through_a_field_write_and_back_out_of_a_read() {
        let mut idx = index("a.py");
        idx.functions.push(func("f"));
        idx.call_args.push(call("f", 3, "get", &[], Some("raw")));
        idx.field_writes.push(FieldWriteFact {
            function_qnode: "f".to_string(),
            line: 4,
            receiver: "self".to_string(),
            field: "buf".to_string(),
            src_symbol: Some("raw".to_string()),
        });
        idx.field_reads.push(FieldReadFact {
            function_qnode: "f".to_string(),
            line: 5,
            receiver: "self".to_string(),
            field: "buf".to_string(),
            dst_symbol: Some("out".to_string()),
        });
        idx.call_args.push(call("f", 6, "system", &["out"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 6, "f", "system", "CWE-78");
        let ev = evidence_of(&[idx], &s, &k, &["a.py::f"]).unwrap();
        assert_eq!(
            kinds(&ev),
            vec!["source", "field_write", "field_read", "local_to_sink"]
        );
    }

    #[test]
    fn field_facts_without_a_tainted_endpoint_propagate_nothing() {
        let mut idx = index("a.py");
        idx.functions.push(func("f"));
        idx.call_args.push(call("f", 3, "get", &[], Some("raw")));
        idx.field_writes.push(FieldWriteFact {
            function_qnode: "f".to_string(),
            line: 4,
            receiver: "self".to_string(),
            field: "buf".to_string(),
            src_symbol: Some("other".to_string()),
        });
        idx.field_writes.push(FieldWriteFact {
            function_qnode: "f".to_string(),
            line: 4,
            receiver: "self".to_string(),
            field: "n".to_string(),
            src_symbol: None,
        });
        idx.field_reads.push(FieldReadFact {
            function_qnode: "f".to_string(),
            line: 5,
            receiver: "self".to_string(),
            field: "buf".to_string(),
            dst_symbol: None,
        });
        idx.field_reads.push(FieldReadFact {
            function_qnode: "f".to_string(),
            line: 5,
            receiver: "self".to_string(),
            field: "cold".to_string(),
            dst_symbol: Some("out".to_string()),
        });
        idx.call_args.push(call("f", 6, "system", &["raw"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 6, "f", "system", "CWE-78");
        let ev = evidence_of(&[idx], &s, &k, &["a.py::f"]).unwrap();
        assert_eq!(kinds(&ev), vec!["source", "local_to_sink"]);
    }

    #[test]
    fn a_field_read_off_a_wildcard_receiver_still_taints_its_destination() {
        let mut state = TaintState::default();
        state
            .tainted_fields
            .insert(("self".to_string(), "*".to_string()));
        let fr = FieldReadFact {
            function_qnode: "f".to_string(),
            line: 5,
            receiver: "self".to_string(),
            field: "anything".to_string(),
            dst_symbol: Some("out".to_string()),
        };
        let edges = apply_field_reads("a.py::f", "a.py", &[&fr], &mut state);
        assert_eq!(edges.len(), 1);
        assert!(state.tainted_locals.contains("out"));
        assert!(apply_field_reads("a.py::f", "a.py", &[&fr], &mut state).is_empty());
    }

    #[test]
    fn a_repeated_field_write_emits_only_one_edge() {
        let mut state = TaintState::default();
        state.tainted_locals.insert("raw".to_string());
        let fw = FieldWriteFact {
            function_qnode: "f".to_string(),
            line: 4,
            receiver: "self".to_string(),
            field: "buf".to_string(),
            src_symbol: Some("raw".to_string()),
        };
        assert_eq!(
            apply_field_writes("a.py::f", "a.py", &[&fw, &fw], &mut state).len(),
            1
        );
    }

    #[test]
    fn a_repeated_container_write_emits_only_one_edge() {
        let mut state = TaintState::default();
        state.tainted_locals.insert("raw".to_string());
        let cw = ContainerWriteFact {
            function_qnode: "f".to_string(),
            line: 4,
            container_symbol: "bag".to_string(),
            element_symbol: Some("raw".to_string()),
        };
        let none = ContainerWriteFact {
            element_symbol: None,
            ..cw.clone()
        };
        assert_eq!(
            apply_container_writes("a.py::f", "a.py", &[&cw, &cw, &none], &mut state).len(),
            1
        );
    }

    #[test]
    fn a_tainted_container_read_at_the_sink_emits_its_own_hop() {
        let mut idx = index("a.py");
        idx.functions.push(func("f"));
        idx.call_args.push(call("f", 3, "get", &[], Some("raw")));
        idx.container_writes.push(ContainerWriteFact {
            function_qnode: "f".to_string(),
            line: 4,
            container_symbol: "bag".to_string(),
            element_symbol: Some("raw".to_string()),
        });
        idx.call_args.push(call("f", 5, "system", &["bag"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 5, "f", "system", "CWE-78");
        let ev = evidence_of(&[idx], &s, &k, &["a.py::f"]).unwrap();
        assert_eq!(kinds(&ev), vec!["source", "container_put", "container_get"]);
    }

    #[test]
    fn alias_chains_reach_a_fixpoint() {
        let mut state = TaintState::default();
        state.tainted_locals.insert("a".to_string());
        state
            .local_origin
            .insert("a".to_string(), "source".to_string());
        let c_from_b = assign("f", 3, "c", Some("b"));
        let b_from_a = assign("f", 2, "b", Some("a"));
        let no_src = assign("f", 4, "d", None);
        let no_dst = VarAssignFact {
            dst_symbol: String::new(),
            ..assign("f", 5, "x", Some("a"))
        };
        let edges = apply_local_aliases(
            "a.py::f",
            "a.py",
            &[&c_from_b, &b_from_a, &no_src, &no_dst],
            &mut state,
        );
        assert_eq!(edges.len(), 2);
        assert!(state.tainted_locals.contains("c"));
        assert_eq!(state.local_origin.get("c"), Some(&"source".to_string()));
    }

    #[test]
    fn a_tainted_argument_returned_by_a_callee_taints_the_assignment_target() {
        let mut caller = index("a.py");
        caller.functions.push(func("f"));
        caller.call_args.push(call("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call("f", 4, "helper", &["raw"], Some("out")));
        caller
            .call_args
            .push(call("f", 5, "system", &["out"], None));
        let mut callee = index("b.py");
        callee.functions.push(func("helper"));
        callee.returns.push(ReturnFact {
            function_qnode: "helper".to_string(),
            line: 2,
            symbol: Some("v".to_string()),
        });
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 5, "f", "system", "CWE-78");
        let ev = evidence_of(&[caller, callee], &s, &k, &["a.py::f"]).unwrap();
        assert_eq!(
            kinds(&ev),
            vec!["source", "return_to_local", "return_to_sink"]
        );
        assert_eq!(ev.edges[1].src.qnode, "b.py::helper");
    }

    #[test]
    fn a_callee_that_returns_nothing_hands_back_no_taint() {
        let mut caller = index("a.py");
        caller.functions.push(func("f"));
        caller.call_args.push(call("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call("f", 4, "helper", &["raw"], Some("out")));
        caller
            .call_args
            .push(call("f", 5, "system", &["out"], None));
        let mut callee = index("b.py");
        callee.functions.push(func("helper"));
        callee.returns.push(ReturnFact {
            function_qnode: "helper".to_string(),
            line: 2,
            symbol: None,
        });
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 5, "f", "system", "CWE-78");
        assert!(evidence_of(&[caller, callee], &s, &k, &["a.py::f"]).is_none());
    }

    #[test]
    fn an_unresolvable_or_untainted_call_hands_back_no_taint() {
        let mut caller = index("a.py");
        caller.functions.push(func("f"));
        caller.call_args.push(call("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call("f", 4, "missing", &["raw"], Some("out")));
        caller
            .call_args
            .push(call("f", 5, "f", &["cold"], Some("out2")));
        caller.call_args.push(call("f", 6, "f", &["raw"], None));
        caller
            .call_args
            .push(call("f", 7, "system", &["raw"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 7, "f", "system", "CWE-78");
        let ev = evidence_of(&[caller], &s, &k, &["a.py::f"]).unwrap();
        assert_eq!(kinds(&ev), vec!["source", "local_to_sink"]);
    }

    #[test]
    fn a_tainted_parameter_is_resolved_by_name_in_the_callee() {
        let mut caller = index("a.py");
        caller.functions.push(func("f"));
        caller.call_args.push(call("f", 3, "get", &[], Some("raw")));
        let mut hop = call("f", 4, "run_cmd", &["raw"], None);
        hop.arg_slots = vec![1];
        caller.call_args.push(hop);
        let mut callee = index("b.py");
        let mut run_cmd = func("run_cmd");
        run_cmd.params = vec!["flag".to_string(), "c".to_string()];
        callee.functions.push(run_cmd);
        callee
            .call_args
            .push(call("run_cmd", 2, "system", &["c"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("b.py", 2, "run_cmd", "system", "CWE-78");
        let ev = evidence_of(&[caller, callee], &s, &k, &["a.py::f", "b.py::run_cmd"]).unwrap();
        assert_eq!(kinds(&ev), vec!["source", "arg_to_param", "local_to_sink"]);
        let sink_edge = ev.edges.last().unwrap();
        assert_eq!(sink_edge.src.symbol, "__p1");
        assert_eq!(sink_edge.src.kind, "param");
    }

    #[test]
    fn a_known_parameter_list_disables_the_positional_coincidence() {
        let mut caller = index("a.py");
        caller.functions.push(func("f"));
        caller.call_args.push(call("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call("f", 4, "run_cmd", &["raw"], None));
        let mut callee = index("b.py");
        let mut run_cmd = func("run_cmd");
        run_cmd.params = vec!["flag".to_string(), "c".to_string()];
        callee.functions.push(run_cmd);
        callee
            .call_args
            .push(call("run_cmd", 2, "system", &["other"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("b.py", 2, "run_cmd", "system", "CWE-78");
        assert!(evidence_of(&[caller, callee], &s, &k, &["a.py::f", "b.py::run_cmd"]).is_none());
    }

    #[test]
    fn a_sink_call_whose_arguments_carry_no_symbols_grounds_nothing() {
        let mut caller = index("a.py");
        caller.functions.push(func("f"));
        caller.call_args.push(call("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call("f", 4, "sink_fn", &["raw"], None));
        let mut callee = index("b.py");
        callee.functions.push(func("sink_fn"));
        callee
            .call_args
            .push(call("sink_fn", 9, "system", &[], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("b.py", 9, "sink_fn", "system", "CWE-78");
        assert!(evidence_of(&[caller, callee], &s, &k, &["a.py::f", "b.py::sink_fn"]).is_none());
    }

    #[test]
    fn a_tainted_parameter_slot_reaches_the_sink_in_the_callee() {
        let mut caller = index("a.py");
        caller.functions.push(func("f"));
        caller.call_args.push(call("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call("f", 4, "sink_fn", &["raw"], None));
        let mut callee = index("b.py");
        callee.functions.push(func("sink_fn"));
        callee
            .call_args
            .push(call("sink_fn", 9, "system", &["p"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("b.py", 9, "sink_fn", "system", "CWE-78");
        let ev = evidence_of(&[caller, callee], &s, &k, &["a.py::f", "b.py::sink_fn"]).unwrap();
        assert_eq!(kinds(&ev), vec!["source", "arg_to_param", "local_to_sink"]);
        assert_eq!(ev.edges[1].dst.symbol, "__p0");
        assert_eq!(ev.edges[2].src.symbol, "__p0");
        assert_eq!(ev.edges[2].src.kind, "param");
        assert_eq!(ev.path_funcs.len(), 2);
    }

    #[test]
    fn a_value_sanitized_before_the_call_boundary_is_reported_as_sanitized() {
        let mut caller = index("a.py");
        caller.functions.push(func("f"));
        caller.call_args.push(call("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call("f", 4, "escape", &["raw"], Some("safe")));
        caller
            .call_args
            .push(call("f", 5, "sink_fn", &["safe"], None));
        let mut callee = index("b.py");
        callee.functions.push(func("sink_fn"));
        callee
            .call_args
            .push(call("sink_fn", 9, "system", &["p"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("b.py", 9, "sink_fn", "system", "CWE-78");
        let ev = evidence_of(&[caller, callee], &s, &k, &["a.py::f", "b.py::sink_fn"]).unwrap();
        assert!(ev.sanitized);
        assert!(kinds(&ev).contains(&"sanitize"));
        assert!(!kinds(&ev).contains(&"arg_to_param"));
    }

    #[test]
    fn a_sanitized_value_that_does_not_reach_the_next_function_still_drops_the_path() {
        let mut caller = index("a.py");
        caller.functions.push(func("f"));
        caller.call_args.push(call("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call("f", 4, "escape", &["raw"], Some("safe")));
        caller
            .call_args
            .push(call("f", 5, "elsewhere", &["safe"], None));
        caller
            .call_args
            .push(call("f", 6, "sink_fn", &["cold"], None));
        let mut callee = index("b.py");
        callee.functions.push(func("sink_fn"));
        callee.functions.push(func("elsewhere"));
        callee
            .call_args
            .push(call("sink_fn", 9, "system", &["p"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("b.py", 9, "sink_fn", "system", "CWE-78");
        assert!(evidence_of(&[caller, callee], &s, &k, &["a.py::f", "b.py::sink_fn"]).is_none());
    }

    #[test]
    fn a_call_boundary_with_no_tainted_argument_drops_the_path() {
        let mut caller = index("a.py");
        caller.functions.push(func("f"));
        caller.call_args.push(call("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call("f", 4, "sink_fn", &["cold"], None));
        let mut callee = index("b.py");
        callee.functions.push(func("sink_fn"));
        callee
            .call_args
            .push(call("sink_fn", 9, "system", &[], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("b.py", 9, "sink_fn", "system", "CWE-78");
        assert!(evidence_of(&[caller, callee], &s, &k, &["a.py::f", "b.py::sink_fn"]).is_none());
    }

    #[test]
    fn a_call_that_does_not_reach_the_next_path_function_is_ignored() {
        let mut caller = index("a.py");
        caller.functions.push(func("f"));
        caller.functions.push(func("elsewhere"));
        caller.call_args.push(call("f", 3, "get", &[], Some("raw")));
        caller
            .call_args
            .push(call("f", 4, "elsewhere", &["raw"], None));
        let mut callee = index("b.py");
        callee.functions.push(func("sink_fn"));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("b.py", 9, "sink_fn", "system", "CWE-78");
        assert!(evidence_of(&[caller, callee], &s, &k, &["a.py::f", "b.py::sink_fn"]).is_none());
    }

    #[test]
    fn a_path_function_with_no_metadata_falls_back_to_the_source_file() {
        let mut idx = index("a.py");
        idx.call_args.push(call("f", 3, "get", &[], Some("raw")));
        idx.call_args.push(call("f", 5, "system", &["raw"], None));
        let s = site("a.py", 3, "f", "get", "");
        let k = site("a.py", 5, "f", "system", "CWE-78");
        let ev = evidence_of(&[idx], &s, &k, &["a.py::f"]).unwrap();
        assert_eq!(ev.edges[0].file, "a.py");
    }

    #[test]
    fn the_symbol_table_indexes_qualified_bare_and_class_names() {
        let mut idx = index("a.py");
        idx.functions.push(FuncDef {
            name: "run".to_string(),
            start_line: 1,
            end_line: 2,
            class_name: "Job".to_string(),
            params: Vec::new(),
        });
        let table = build_symbol_table(&[idx]);
        assert!(table.contains("a.py::run"));
        assert!(table.contains("run"));
        assert!(table.contains("Job.run"));
    }

    #[test]
    fn confidence_is_raised_by_rank_not_lexicographically() {
        assert_eq!(raise_confidence("high", "medium"), "high");
        assert_eq!(raise_confidence("low", "medium"), "medium");
    }

    #[test]
    fn a_target_naming_a_known_symbol_resolves_with_high_confidence() {
        let table = BTreeSet::from(["run".to_string()]);
        let fact = ReflectionFact {
            target_symbols: vec!["run".to_string()],
            ..Default::default()
        };
        let (targets, conf) = resolve_reflection_targets(&fact, &table);
        assert_eq!(targets, vec!["run".to_string()]);
        assert_eq!(conf, "high");
    }

    #[test]
    fn a_single_suffix_match_is_high_and_several_are_medium() {
        let one = BTreeSet::from(["a.py::run".to_string()]);
        let fact = ReflectionFact {
            target_symbols: vec!["run".to_string()],
            ..Default::default()
        };
        let (targets, conf) = resolve_reflection_targets(&fact, &one);
        assert_eq!(targets, vec!["a.py::run".to_string()]);
        assert_eq!(conf, "high");

        let many = BTreeSet::from([
            "a.py::run".to_string(),
            "b.py::run".to_string(),
            "Job.run".to_string(),
            "c.py::run".to_string(),
        ]);
        let (targets, conf) = resolve_reflection_targets(&fact, &many);
        assert_eq!(targets.len(), 3);
        assert_eq!(conf, "medium");
    }

    #[test]
    fn a_concrete_but_unknown_name_is_kept_at_medium_confidence() {
        let fact = ReflectionFact {
            target_symbols: vec!["Unknown".to_string()],
            ..Default::default()
        };
        let (targets, conf) = resolve_reflection_targets(&fact, &BTreeSet::new());
        assert_eq!(targets, vec!["Unknown".to_string()]);
        assert_eq!(conf, "medium");
    }

    #[test]
    fn a_non_literal_target_resolves_to_the_unknown_placeholder() {
        let fact = ReflectionFact {
            target_symbols: vec!["a + b".to_string(), "  ".to_string()],
            ..Default::default()
        };
        let (targets, conf) = resolve_reflection_targets(&fact, &BTreeSet::new());
        assert_eq!(targets, vec!["*UNKNOWN*".to_string()]);
        assert_eq!(conf, "low");
    }

    #[test]
    fn a_fact_with_no_targets_at_all_resolves_to_the_unknown_placeholder() {
        let (targets, _) = resolve_reflection_targets(&ReflectionFact::default(), &BTreeSet::new());
        assert_eq!(targets, vec!["*UNKNOWN*".to_string()]);
    }

    #[test]
    fn a_tainted_reflective_target_emits_one_speculative_edge_per_target() {
        let fact = ReflectionFact {
            function_qnode: "f".to_string(),
            line: 7,
            call_type: "getattr".to_string(),
            target_symbols: vec!["name".to_string()],
            receiver: String::new(),
            language: "python".to_string(),
        };
        let table = BTreeSet::from(["a.py::name".to_string()]);
        let ts = BTreeSet::from(["name".to_string()]);
        let edges = apply_reflection_to_taint(&ts, &[fact], &table, "a.py::f");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].transfer_kind, "reflect");
        assert_eq!(edges[0].file, "a.py");
        assert_eq!(edges[0].confidence, Some("high".to_string()));
        assert_eq!(edges[0].is_speculative, Some(true));
        assert_eq!(edges[0].reflected_targets, vec!["a.py::name".to_string()]);
    }

    #[test]
    fn reflection_facts_from_another_function_or_with_clean_targets_emit_nothing() {
        let other_fn = ReflectionFact {
            function_qnode: "g".to_string(),
            target_symbols: vec!["name".to_string()],
            ..Default::default()
        };
        let clean = ReflectionFact {
            function_qnode: "f".to_string(),
            target_symbols: vec!["cold".to_string()],
            ..Default::default()
        };
        let ts = BTreeSet::from(["name".to_string()]);
        assert!(
            apply_reflection_to_taint(&ts, &[other_fn, clean], &BTreeSet::new(), "a.py::f")
                .is_empty()
        );
    }

    #[test]
    fn a_reflection_fact_with_no_function_scope_is_not_filtered_out() {
        let fact = ReflectionFact {
            function_qnode: String::new(),
            target_symbols: vec!["name".to_string()],
            ..Default::default()
        };
        let ts = BTreeSet::from(["name".to_string()]);
        let edges = apply_reflection_to_taint(&ts, &[fact], &BTreeSet::new(), "a.py::f");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].file, "a.py");
    }

    #[test]
    fn framework_entry_points_come_from_markers_and_routes_and_dedupe() {
        let mut idx = index("a.py");
        idx.framework_markers.push(FrameworkMarkerFact {
            function_qnode: "show".to_string(),
            marker_name: "@RequestParam".to_string(),
            ..Default::default()
        });
        idx.framework_markers.push(FrameworkMarkerFact {
            function_qnode: "show".to_string(),
            marker_name: "@PathVariable".to_string(),
            ..Default::default()
        });
        idx.framework_markers.push(FrameworkMarkerFact {
            function_qnode: String::new(),
            ..Default::default()
        });
        idx.route_facts.push(RouteTaintFact {
            function_qnode: "b.py::other".to_string(),
            ..Default::default()
        });
        let eps = emit_framework_entry_points(&[idx]);
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].function, "show");
        assert_eq!(eps[0].kind, "framework");
        assert_eq!(eps[1].function, "other");
        assert_eq!(eps[1].file, "a.py");
    }

    #[test]
    fn a_framework_entry_point_with_no_auth_evidence_is_reachable_from_unauth() {
        let mut idx = index("a.py");
        idx.route_facts.push(RouteTaintFact {
            function_qnode: "show".to_string(),
            ..Default::default()
        });
        let eps = emit_framework_entry_points(&[idx]);
        assert_eq!(eps.len(), 1);
        assert!(eps[0].reachable_from_unauth);
    }

    #[test]
    fn an_auth_guarded_framework_entry_point_is_not_reachable_from_unauth() {
        let mut idx = index("a.py");
        idx.route_facts.push(RouteTaintFact {
            function_qnode: "show".to_string(),
            ..Default::default()
        });
        idx.route_facts.push(RouteTaintFact {
            function_qnode: "open_health".to_string(),
            ..Default::default()
        });
        idx.auth_guards.push(crate::scan::AuthGuardFact {
            function_qnode: "show".to_string(),
            marker_name: "@login_required".to_string(),
            requires_auth: true,
            ..Default::default()
        });
        idx.auth_guards.push(crate::scan::AuthGuardFact {
            function_qnode: "open_health".to_string(),
            marker_name: "[AllowAnonymous]".to_string(),
            requires_auth: false,
            ..Default::default()
        });
        let eps = emit_framework_entry_points(&[idx]);
        let by = |f: &str| {
            eps.iter()
                .find(|e| e.function == f)
                .unwrap()
                .reachable_from_unauth
        };
        assert!(!by("show"));
        assert!(by("open_health"));
    }

    #[test]
    fn a_controller_qualified_guard_reaches_the_route_table_in_another_file() {
        let mut routes = index("config/routes.rb");
        routes.route_facts.push(RouteTaintFact {
            function_qnode: "users#show".to_string(),
            ..Default::default()
        });
        routes.route_facts.push(RouteTaintFact {
            function_qnode: "pages#about".to_string(),
            ..Default::default()
        });
        let mut controller = index("app/controllers/users_controller.rb");
        controller.auth_guards.push(crate::scan::AuthGuardFact {
            function_qnode: "users#show".to_string(),
            marker_name: "authenticate_user!".to_string(),
            requires_auth: true,
            ..Default::default()
        });
        let eps = emit_framework_entry_points(&[routes, controller]);
        let by = |f: &str| {
            eps.iter()
                .find(|e| e.function == f)
                .unwrap()
                .reachable_from_unauth
        };
        assert!(!by("users#show"));
        assert!(by("pages#about"));
    }

    #[test]
    fn a_bare_guard_name_stays_file_local() {
        let mut routes = index("a.py");
        routes.route_facts.push(RouteTaintFact {
            function_qnode: "list".to_string(),
            ..Default::default()
        });
        let mut other = index("b.py");
        other.auth_guards.push(crate::scan::AuthGuardFact {
            function_qnode: "list".to_string(),
            marker_name: "@login_required".to_string(),
            requires_auth: true,
            ..Default::default()
        });
        let eps = emit_framework_entry_points(&[routes, other]);
        assert!(eps[0].reachable_from_unauth);
    }

    #[test]
    fn response_types_map_to_their_injection_cwe() {
        assert_eq!(response_type_cwe("html"), "CWE-79");
        assert_eq!(response_type_cwe("xml"), "CWE-611");
        assert_eq!(response_type_cwe("text"), "CWE-117");
        assert_eq!(response_type_cwe("json"), "CWE-90");
        assert_eq!(response_type_cwe("???"), "CWE-90");
    }

    #[test]
    fn a_response_write_on_a_path_function_widens_the_paths_cwe_set() {
        let mut idx = index("a.py");
        idx.response_dataflow.push(ResponseDataflowFact {
            function_qnode: "f".to_string(),
            line: 5,
            from_symbol: "x".to_string(),
            to_sink: "HttpResponse".to_string(),
            framework: "django".to_string(),
            response_type: "html".to_string(),
        });
        idx.response_dataflow.push(ResponseDataflowFact {
            function_qnode: String::new(),
            ..Default::default()
        });
        let by_fid = response_dataflow_by_fid(std::slice::from_ref(&idx));
        let mut evidence = vec![
            TaintEvidencePath {
                path_funcs: vec!["a.py::f".to_string()],
                sink_cwe: vec!["CWE-78".to_string()],
                ..Default::default()
            },
            TaintEvidencePath {
                path_funcs: vec!["a.py::g".to_string()],
                sink_cwe: vec!["CWE-78".to_string()],
                ..Default::default()
            },
        ];
        apply_response_dataflow(&mut evidence, &by_fid);
        assert_eq!(
            evidence[0].sink_cwe,
            vec!["CWE-78".to_string(), "CWE-79".to_string()]
        );
        assert_eq!(evidence[1].sink_cwe, vec!["CWE-78".to_string()]);
    }

    #[test]
    fn no_response_facts_leaves_every_path_untouched() {
        let mut evidence = vec![TaintEvidencePath {
            sink_cwe: vec!["CWE-78".to_string()],
            ..Default::default()
        }];
        apply_response_dataflow(&mut evidence, &BTreeMap::new());
        assert_eq!(evidence[0].sink_cwe, vec!["CWE-78".to_string()]);
    }
}
