// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! S6's system/user prompts, ported from `s6_verify.py`'s `SYSTEM` /
//! `_controls_for` / `_callers_of` / `_candidate_qnodes_for_finding` /
//! `_callgraph_context_for_finding` / `_build_user_prompt`.

use std::sync::LazyLock;

use bc_model::{ContextPackage, Control, Finding};
use bc_repo_analysis::GraphView;

use crate::wire::{control_kind_str, ep_kind_str};

/// Language rules the verifier gets wrong often enough, and expensively
/// enough, to state outright. The first two are traced to a live
/// 2026-09-06 Juice Shop scan where the verifier confirmed 5 impossible
/// race conditions at 8/10 and 3 XSS findings on default-escaped template
/// syntax at 8-9/10.
///
/// The bar for an entry here is deliberately high: a fact must decide the
/// verdict **on its own** and hold **without exception**, so the verifier
/// can stop at it. "Usually safe" belongs in `bc_stage_s4::hints`, where a
/// researcher is told where to look, not in a rule that ends an
/// investigation. That is why, for instance, the parameterized-SQL entry
/// spells out the identifier case (a table or column name a placeholder
/// cannot carry) rather than saying "prepared statements are safe", and
/// why the Rust entry names `unsafe`/FFI as the escape hatch rather than
/// claiming Rust has no memory bugs.
///
/// A separate `const` rather than more text inside [`SYSTEM`]'s `format!`
/// purely so the brace-heavy template syntax below (`{{{ }}}`, `{!! !!}`,
/// `{% autoescape %}`) can be written literally instead of doubled.
/// Spliced in as `SYSTEM`'s first argument, so it is still one canonical
/// string built once — see `SYSTEM`'s own note on prompt caching.
///
/// The deterministic half of the first two rules lives in
/// `bc_stage_s5::lang_gates`, which settles the unambiguous cases before
/// a verification session is ever spent on them; this block is what
/// catches the rest. `language_facts_agree_with_the_s5_lang_gates` in this
/// module's tests holds the two halves to the same claims.
const LANGUAGE_FACTS: &str = "LANGUAGE FACTS THAT DECIDE A VERDICT ON THEIR OWN
  Race conditions in JavaScript/TypeScript (CWE-362/366/367). Node runs ONE
  JavaScript thread on a run-to-completion event loop: a synchronous block
  cannot be interrupted, and two requests cannot interleave inside one. A race
  therefore requires BOTH (i) an asynchronous boundary — `await`, `.then`, a
  completion callback, a timer, any I/O — sitting BETWEEN the check and the act
  on the same state, and (ii) shared mutable state another request can reach
  (module-level, a singleton, `app.locals`, a DB row, a cache, the filesystem).
  `counter++`, `obj.n += 1` and `if (!x.done) { x.done = true }` with nothing
  awaited in between are NOT races — FALSE_POSITIVE. State confined to one
  request (`req.*`, a local) is not shared. `async` on the enclosing function
  proves nothing by itself; registering a handler (`socket.on`, `router.get`)
  is not a boundary either, since each invocation of the body runs to
  completion. Genuine concurrency needs `worker_threads`/`cluster`/
  `SharedArrayBuffer`, or a shared store behind multiple processes.

  Template auto-escaping (CWE-79/80). These constructs are HTML-escaped by the
  engine BY DEFAULT — escaping covers `<`, `>`, `&`, quotes AND `=`, so even an
  unquoted attribute value is safe: Handlebars/Mustache `{{ x }}`; Pug/Jade
  `#{x}`, `tag= x`, `attr=x`; EJS `<%= x %>`; Jinja2/Django/Twig `{{ x }}`;
  Rails ERB `<%= x %>`; Razor `@x`; Blade `{{ $x }}`; Vue `{{ x }}` / `:attr`;
  React `{x}`; Angular `{{ x }}`. Only these are RAW: `{{{ }}}` / `{{& }}`;
  `!{ }` / `!=` / `unescaped`; `<%- %>`; `|safe` / `|raw` / `Markup()` /
  `{% autoescape false %}`; `<%== %>` / `raw()` / `.html_safe`; `@Html.Raw` /
  `HtmlString`; `{!! !!}`; `v-html`; `dangerouslySetInnerHTML`; `[innerHTML]` /
  `bypassSecurityTrust*`; `{@html}`. An XSS finding on a default-escaped
  construct is a FALSE_POSITIVE unless you can show the value later reaches a
  raw construct, or the construct sits in a NON-HTML context where escaping
  does not help: inside `<script>`/`<style>`, in an `on*=` handler, in a
  `href`/`src`/`action` that could become `javascript:`/`data:`, or in a CSS
  value. Check which of those it is before deciding — the context is the whole
  question.

  Parameterized SQL (CWE-89/564). A statement is not injectable when the
  statement TEXT is fixed and EVERY user-derived value reaches the driver
  through a placeholder. These bind, and an injection finding on one of them
  is a FALSE_POSITIVE: Java `PreparedStatement` with `?` plus `setString`/
  `setInt`/`setObject`; C# `SqlCommand` with `SqlParameter`/`AddWithValue`,
  Dapper's `@p` anonymous-object parameters, EF Core LINQ, and EF Core
  `FromSqlInterpolated`/`ExecuteSqlInterpolated` (which turn the
  interpolation holes into parameters); Python DB-API `execute(sql, params)`
  and SQLAlchemy `text(...).bindparams` or ORM filters; Go
  `db.Query`/`QueryRow`/`Exec(sql, args...)` with `$1`/`?` markers; PHP PDO
  `prepare` plus `bindValue`/`bindParam`/`execute([...])` and mysqli
  `bind_param`; Ruby ActiveRecord `where(hash)`, `where(\"a = ?\", x)`,
  `where(\"a = :k\", k: x)`; Node `mysql2`/`pg` with `?`/`$1` and a values
  array, and Knex/Sequelize bindings; Rust `sqlx::query!`/`query_as!` or
  `.bind(...)`, and Diesel. It stays a TRUE_POSITIVE when the value is
  concatenated or interpolated into the statement text instead — JDBC
  `Statement.executeQuery(\"... \" + x)`, EF Core `FromSqlRaw`/`ExecuteSqlRaw`
  on a built string, Python f-string or `%`-built SQL, Go `fmt.Sprintf` into
  the query, PDO `query()`/`exec()`, ActiveRecord `where(\"a = #{x}\")` or
  `find_by_sql`, Slick's `#$` splice, `format!`-built `sqlx::query(...)` —
  and ALWAYS when the spliced part is an identifier no placeholder can carry
  (table name, column name, ORDER BY column, sort direction), which is only
  safe behind an allow-list. Read which of the two shapes the code uses; the
  presence of a `prepare` call elsewhere in the function decides nothing.

  Rust memory safety (CWE-416/415/362/787). Safe Rust cannot produce a
  use-after-free, a double free, or a data race: the borrow checker and the
  `Send`/`Sync` bounds rule them out at compile time, and an out-of-range
  index panics rather than writing. A finding of one of those classes is a
  FALSE_POSITIVE unless the flow passes through an `unsafe` block, an
  `unsafe impl Send`/`Sync`, or an `extern \"C\"` FFI call — name that
  construct or drop the finding. Panics, deadlocks, `mem::forget` leaks and
  logic races over external state (a file, a row, an API) are still possible
  in safe code and are judged on the ordinary criteria.

  Go concurrency (CWE-362/366). Goroutines are real parallelism on real OS
  threads, so the JavaScript event-loop rule above does NOT apply to Go — a
  plain, synchronous-looking read-modify-write is exactly where Go races
  live. A race is a TRUE_POSITIVE when state outlives a single request (a
  package-level var, a field on a shared handler/client/struct, a map, a
  cache) AND more than one goroutine reaches it AND nothing orders the
  accesses: no `sync.Mutex`/`RWMutex` held across both, no channel hand-off
  giving one owner at a time, no `sync.Once`, no `atomic.*`, no
  `WaitGroup`/`errgroup` join between the write and the read. It is a
  FALSE_POSITIVE when the state is per-request (a local, a value only one
  goroutine captures, request-context values) or when every access already
  sits under the same lock or behind one channel owner.

  Java atomicity (CWE-362/366/367). A check-then-act is NOT a race when both
  halves execute inside one `synchronized` block or method on the SAME
  monitor, inside one `ReentrantLock` acquire/release, or inside a single
  `ConcurrentHashMap` `compute`/`computeIfAbsent`/`computeIfPresent`/`merge`/
  `putIfAbsent` call, whose mapping function runs atomically for that key —
  FALSE_POSITIVE. It IS a race when the two halves are SEPARATE calls
  (`containsKey` then `put`, `get` then `put`, `size` then `add`), because
  per-call atomicity says nothing about the gap between calls, or when the
  two halves synchronize on different objects.

  C/C++ bounded vs unbounded copies (CWE-120/121/122/787). `strcpy`,
  `strcat`, `sprintf`, `vsprintf`, `gets` and `scanf(\"%s\")` with no field
  width take no destination size and overflow on any oversized source.
  `snprintf`/`strlcpy`/`strlcat` given the destination's real size,
  `fgets(buf, sizeof buf, f)`, and `memcpy`/`strncpy` with a length the code
  derived from the DESTINATION are bounded — an overflow finding on one of
  those is a FALSE_POSITIVE unless the size argument is itself wrong or
  attacker-influenced (`sizeof(ptr)` after a parameter decayed, a length read
  out of the source data, an off-by-one that forgets the NUL). Judge
  separately, and do not confuse with an overflow: `strncpy` leaves the
  destination UNTERMINATED when the source fills it, which is a real defect
  in whatever reads it next.

  Python and Ruby interpreter locks (CWE-362/367). The GIL serializes
  bytecode and nothing more: it is released around every I/O call and by C
  extensions, and it does not exist across processes at all — which is how
  these apps are deployed (gunicorn/uwsgi workers, Puma clusters, Celery,
  Sidekiq). So \"the GIL prevents this\" is NEVER a reason to refute a
  check-then-act across a file, a database row, a cache entry or an HTTP
  call: `os.path.exists` then `open`, `SELECT` then `UPDATE` with no
  `SELECT ... FOR UPDATE` or unique constraint, `find_or_create_by`,
  check-then-`mkdir` — those are judged on the ordinary criteria and are
  routinely TRUE_POSITIVE. Only a single bytecode operation on an in-process
  object is atomic, and `x += 1` is not one of those.

  Framework-guarded routes (CWE-284/285/287/306/862/863). Read the ENTRY
  POINTS section before judging any 'this handler has no authorization
  check' finding. An entry point marked `[GUARDED — not reachable without
  auth]` is a route the framework itself gates: Laravel's
  `Route::middleware(['auth'])->group`, Ktor's `authenticate(\"…\")`, Rails'
  `before_action :authenticate_user!`, axum's
  `.route_layer(middleware::from_fn(…))`, Spring's `@PreAuthorize`, ASP.NET's
  `[Authorize]`. Such a route HAS an authorization check for every request
  that reaches its handler, running before a line of the handler executes —
  so the handler having no check of its own is the normal, correct shape,
  not a defect. A missing-authorization finding on such a handler is a
  FALSE_POSITIVE unless it shows the guard is
  bypassable (a path that skips the middleware, a route registered outside
  the guarded group, a filter with an `except:`/`AllowAnonymous` covering
  this action) or mis-registered. Say which; do not confirm on the handler's
  own silence. The reverse is evidence too: an entry point marked
  `[UNAUTH-REACHABLE]` means S0 found NO guard on that route, which supports
  a missing-authorization finding on a sensitive action behind it. Entry
  points with neither marker are not framework routes and settle nothing —
  reason about them from the code.
  A guard changes WHO can reach the handler, never WHETHER its code is
  vulnerable: injection, path traversal, SSRF, deserialization, command
  execution or any other flow on a guarded route stays TRUE_POSITIVE — an
  authenticated user, an operator or an insider is still an attacker for
  those classes. Never refute such a finding with \"protected by the
  middleware\"; the guard only refutes the missing-authorization claim.
";

/// What an entry point's `reachable_from_unauth` is allowed to say in the
/// prompt.
///
/// The absence of `[UNAUTH-REACHABLE]` used to be the only signal that a
/// route was guarded, and it is invisible — a 2026-09-07 polyglot run had
/// the verifier confirm "missing authorization" on four handlers whose
/// entry points were right there in this list saying otherwise. Guarded
/// routes now say so.
///
/// Only `EntryPointKind::Framework` earns either marker.
/// `reachable_from_unauth` is `#[serde(default)]`, so an S1 agent that
/// never mentions the field leaves it `false` — which would read as
/// "guarded" while actually meaning "unknown". Only S0's framework plane
/// sets it from the guard facts `bc_callgraph::framework` extracted, so
/// only S0's entry points are labeled; the rest are printed bare, which
/// the LANGUAGE FACTS block tells the verifier settles nothing. The same
/// rule gates `bc_stage_s5::route_gates`, the deterministic half of this.
///
/// The `true` arm has to be `Framework`-gated for exactly the reason the
/// `false` arm does, and for a while it was not: a bare `(_, true)` handed
/// `[UNAUTH-REACHABLE]` to any kind, while the LANGUAGE FACTS block tells
/// the verifier that marker means the seed plane found no guard on the
/// route. `reachable_from_unauth` is a free field in S1's own reply schema
/// (`bc_stage_s1::prompts`), so on a non-`Framework` entry point a `true`
/// there is a survey model's guess being presented to the verifier as a
/// static-analysis fact. Those rows are printed bare instead, and the
/// block's closing sentence — entry points with neither marker settle
/// nothing — is what covers them.
fn auth_marker(e: &bc_model::EntryPoint) -> &'static str {
    match (e.kind, e.reachable_from_unauth) {
        (bc_model::EntryPointKind::Framework, false) => " [GUARDED — not reachable without auth]",
        (bc_model::EntryPointKind::Framework, true) => " [UNAUTH-REACHABLE]",
        _ => "",
    }
}

/// Built once via `LazyLock` rather than a plain `const &str` since
/// `EXCLUSION_RULES` lives in the separate `bc-prompts` crate and `concat!`
/// only accepts literal tokens, not a cross-crate `const` path — still
/// exactly one canonical `String` computed once and reused byte-identically
/// for every call, which is what the prompt-caching concern actually needs.
pub static SYSTEM: LazyLock<String> = LazyLock::new(|| {
    // A plain (non-`\`-continued) multi-line literal below — every physical
    // source newline is a real character in the compiled string, so each
    // line's own leading whitespace survives verbatim. `\`-continuation
    // across an indented line silently eats that line's leading
    // whitespace (confirmed by compiling and diffing against Python), the
    // same class of bug `bc_prompts::EXCLUSION_RULES` already avoids by
    // using this exact style.
    format!(
        "You are the second-opinion reviewer in a SAST pipeline. A scanner
has produced the finding below; assume it is WRONG until you have personally
confirmed it in the source. Your only output that matters is a
TRUE_POSITIVE / FALSE_POSITIVE verdict plus a CVSS vector.

Tools available: Read, Glob, Grep. Use them — do not reason from the snippet
alone.

WORKFLOW
  A. Start from the CALL GRAPH CONTEXT section in the user prompt (it is
     tree-sitter-derived graph metadata from prior stages). Validate those
     edges in code with Grep/Read; do not assume they are perfect.
  B. Open the cited file at the cited line. Establish what the code really
     does (the scanner's description is a claim, not evidence).
  C. Walk the call chain outward: follow callers/callees from graph context,
     then verify each hop in source. Continue backward until you reach an
     external entry point or run out of callers. No external entry point →
     not exploitable.
  D. Try to kill the finding. Look specifically for: input validation or
     allow-lists earlier in the flow; framework-level encoding /
     parameterisation; type or length constraints; auth/authz gates in front
     of the route; feature flags or config that disable the path in prod;
     the code being test-only or simply never invoked.
  E. If you found a defence in (D), probe it: does it cover every route into
     the sink, or only the one you happened to read? Can edge-case input
     (encoding tricks, nulls, oversized values) slip past it?

If the call graph is sparse/ambiguous for this finding, say that clearly and
fall back to broader code-led verification (imports, router wiring, dispatch,
and upstream callers discovered via Grep). Missing graph edges are NOT enough
to refute a finding by themselves.

{}

{}

DECISION RULE
  TRUE_POSITIVE  — only when (B) reached an external/lower-privileged entry
                   point AND (C)/(D) found no defence that fully closes the
                   path AND the impact is real, not hypothetical.
  FALSE_POSITIVE — any one of: no external caller; an upstream control fully
                   neutralises the input; the scanner mis-read the code
                   (wrong sink, wrong class, wrong file).

Confidence 8–10 means you actively searched for the opposite verdict and
could not support it. Confidence ≤5 means you are guessing — say so.

═══════════════════════════════════════════════════════════════════════════
CVSS 3.1 BASE VECTOR — required on the line directly after VERDICT
═══════════════════════════════════════════════════════════════════════════
  AV  N network · A adjacent · L local · P physical
  AC  L trivial · H needs race/MITM/unusual state
  PR  N none · L any authenticated user · H admin/operator
  UI  N none · R victim must act
  S   U same component · C crosses a security boundary
  C/I/A  H full · L limited · N none

Score the vector against the claimed impact even when returning
FALSE_POSITIVE (it feeds severity calibration downstream).

Last two lines of your reply MUST match exactly:
VERDICT: TRUE_POSITIVE|FALSE_POSITIVE (confidence: N/10) — brief reason
CVSS: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_",
        LANGUAGE_FACTS,
        bc_prompts::EXCLUSION_RULES
    )
});

/// One-shot verdict-format repair re-ask, ported from `s6_verify.py::
/// _repair_verdict_prompt` (v1.4.0): the S6 analogue of S2/S4's JSON
/// repair prompt. S6's contract is the two-line VERDICT/CVSS footer, not
/// JSON, so it needs its own prompt.
///
/// It asks ONLY for the two lines to be RESTATED and deliberately does not
/// reopen the analysis: the failure was one of shape, not judgment, and
/// re-litigating a security verdict could flip a correct answer, which is
/// worse than the drop this exists to avoid. The same reasoning is why the
/// verdict parser is not loosened instead. The contract lines are
/// byte-identical to the tail of [`SYSTEM`]; the one prose dash upstream
/// has is a colon here (house style), which changes no instruction.
pub fn repair_verdict_prompt(raw: &str) -> String {
    format!(
        "REPAIR TASK:
Your previous reply reached a conclusion but did not end with the two required
lines, so the pipeline could not read your verdict. Do NOT reconsider or change
your conclusion: restate it now in the exact required format and output NOTHING
ELSE:

VERDICT: TRUE_POSITIVE|FALSE_POSITIVE (confidence: N/10) \u{2014} brief reason
CVSS: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_

YOUR PREVIOUS REPLY:
{raw}
"
    )
}

fn controls_for(file: &str, controls: &[Control]) -> Vec<String> {
    controls
        .iter()
        .filter_map(|c| {
            let hit = c.protects.is_empty()
                || c.protects
                    .iter()
                    .any(|g| bc_repo_analysis::fnmatch(file, g));
            if !hit {
                return None;
            }
            let note = if c.notes.is_empty() {
                String::new()
            } else {
                format!(" — {}", c.notes)
            };
            Some(format!(
                "  - [{}] {} protects this path{note}",
                control_kind_str(c.kind),
                c.name
            ))
        })
        .collect()
}

/// `ctx.call_graph` is a `BTreeMap` (sorted-by-caller-name iteration),
/// unlike the Python original's insertion-ordered `dict` — an accepted,
/// pre-existing divergence from `bc-model`'s own type choice, not
/// introduced here. Immaterial beyond which 15 callers are picked when a
/// file has more than `limit`.
fn callers_of(file: &str, ctx: &ContextPackage, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for (caller, callees) in &ctx.call_graph {
        let hit = callees.iter().any(|cal| {
            let qf = bc_repo_analysis::q_file(cal);
            qf == file || qf.ends_with(&format!("/{file}"))
        });
        if !hit {
            continue;
        }
        out.push(format!("  - {caller}"));
        if out.len() >= limit {
            break;
        }
    }
    out
}

/// Best-effort qnodes for the finding location: spans corroborate the
/// precise function, the call graph's file membership is the fallback.
/// Ported from `_candidate_qnodes_for_finding`.
fn candidate_qnodes_for_finding(f: &Finding, view: &GraphView) -> Vec<String> {
    bc_repo_analysis::qnodes_at(
        view,
        &f.file,
        f.line_start.max(1),
        f.line_end.max(f.line_start).max(1),
        6,
        false,
    )
}

/// Tree-sitter-derived call-graph context for one finding: graph size, the
/// finding's own (possibly AST-backfilled) refs, and the callers/callees
/// around each candidate qnode at the finding's location. Ported from
/// `_callgraph_context_for_finding`.
///
/// The Python original headed this block "sqlite-hydrated", which was true
/// of it: `s6_verify.py` read the graph back out of the harness's SQLite
/// artifact store. Here it is not. The only SQLite in this workspace is
/// `bc_checkpoint::sqlite_store`, the resume checkpoint; `ctx.call_graph`
/// is `bc_callgraph`'s tree-sitter output, carried in memory through the
/// `ContextPackage` (S0's AST graph where the seed plane ran, else S1's
/// agent-reported edges supplemented by `bc_repo_analysis`). Telling the
/// verifier the edges came out of a database it could in principle query
/// misdescribes both their provenance and their reliability, so the header
/// names what actually produced them.
fn callgraph_context_for_finding(f: &Finding, ctx: &ContextPackage, view: &GraphView) -> String {
    if ctx.call_graph.is_empty() {
        return "CALL GRAPH CONTEXT (tree-sitter-derived): (none available)".to_string();
    }

    let cands = candidate_qnodes_for_finding(f, view);

    let mut lines = vec![
        "CALL GRAPH CONTEXT (tree-sitter-derived; validate each edge with Grep/Read):".to_string(),
        format!("  - graph nodes: {}", ctx.call_graph.len()),
        format!(
            "  - graph edges: {}",
            ctx.call_graph.values().map(Vec::len).sum::<usize>()
        ),
    ];
    if let Some(source_ref) = f.source_ref.as_deref().filter(|s| !s.is_empty()) {
        let marker = if f.backfilled_refs.iter().any(|r| r == "source_ref") {
            " (inferred from AST, unverified)"
        } else {
            ""
        };
        lines.push(format!("  - finding.source_ref: {source_ref}{marker}"));
    }
    if let Some(sink_ref) = f.sink_ref.as_deref().filter(|s| !s.is_empty()) {
        let marker = if f.backfilled_refs.iter().any(|r| r == "sink_ref") {
            " (inferred from AST, unverified)"
        } else {
            ""
        };
        lines.push(format!("  - finding.sink_ref: {sink_ref}{marker}"));
    }

    if cands.is_empty() {
        lines.push("  - candidate functions at finding location: (none)".to_string());
        lines.push(
            "  - action: use Grep on file/class symbols to recover callers/callees from code"
                .to_string(),
        );
        return lines.join("\n");
    }

    lines.push("  - candidate functions at/near finding line:".to_string());
    for qn in &cands {
        lines.push(format!("    - {qn}"));
    }

    for qn in &cands {
        let callers: Vec<&String> = view
            .rev
            .get(qn)
            .map(|v| v.iter().take(8).collect())
            .unwrap_or_default();
        let callees: Vec<&String> = view
            .forward
            .get(qn)
            .map(|v| v.iter().take(8).collect())
            .unwrap_or_default();
        lines.push(format!("  - around {qn}:"));
        if callers.is_empty() {
            lines.push("    - caller -> (none in graph)".to_string());
        } else {
            for c in callers {
                lines.push(format!("    - caller -> {c} -> {qn}"));
            }
        }
        if callees.is_empty() {
            lines.push("    - callee -> (none in graph)".to_string());
        } else {
            for c in callees {
                lines.push(format!("    - callee -> {qn} -> {c}"));
            }
        }
    }

    lines.join("\n")
}

pub fn build_user_prompt(f: &Finding, ctx: &ContextPackage, view: &GraphView) -> String {
    let pre = if f.preconditions.is_empty() {
        "  (none listed)".to_string()
    } else {
        f.preconditions
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let eps: Vec<String> = ctx
        .entry_points
        .iter()
        .map(|e| {
            format!(
                "  - {}: {} @ {}{}",
                ep_kind_str(e.kind),
                e.function,
                e.file,
                auth_marker(e)
            )
        })
        .collect();
    let ep_block = if eps.is_empty() {
        String::new()
    } else {
        let mut b = format!(
            "KNOWN EXTERNAL ENTRY POINTS (from architecture scan):\n{}",
            eps[..eps.len().min(25)].join("\n")
        );
        if eps.len() > 25 {
            b.push_str(&format!("\n  ...(+{} more)", eps.len() - 25));
        }
        b
    };

    let callers = callers_of(&f.file, ctx, 15);
    let cg_block = if callers.is_empty() {
        String::new()
    } else {
        format!(
            "KNOWN CALLERS OF THIS FILE (from call graph — verify with Grep):\n{}",
            callers.join("\n")
        )
    };

    let controls = controls_for(&f.file, &ctx.design_controls);
    let ctl_block = if controls.is_empty() {
        String::new()
    } else {
        format!(
            "DESIGN CONTROLS IN EFFECT ON THIS PATH:\n{}\nYou MUST demonstrate a bypass of these controls to return TRUE_POSITIVE. If the control fully mitigates the finding, return FALSE_POSITIVE.",
            controls.join("\n")
        )
    };

    let notes_block = if ctx.notes.is_empty() {
        String::new()
    } else {
        format!("ARCHITECTURE NOTES:\n{}", ctx.notes)
    };

    let compliance_block = if ctx.compliance_guidance.is_empty() {
        String::new()
    } else {
        format!("COMPLIANCE GUIDANCE:\n{}", ctx.compliance_guidance)
    };

    // `cg_focus` always emits at least a "(none available)" line, so `arch`
    // is never empty now that it's included — unlike `ep_block`/`cg_block`/
    // `ctl_block`/`notes_block`/`compliance_block`, which stay individually
    // optional.
    let cg_focus = callgraph_context_for_finding(f, ctx, view);

    let arch_parts: Vec<&str> = [
        cg_focus.as_str(),
        ep_block.as_str(),
        cg_block.as_str(),
        ctl_block.as_str(),
        notes_block.as_str(),
        compliance_block.as_str(),
    ]
    .into_iter()
    .filter(|b| !b.is_empty())
    .collect();
    let arch_display = arch_parts.join("\n\n");

    let exploit_scenario = if f.exploit_scenario.is_empty() {
        "(not provided)"
    } else {
        &f.exploit_scenario
    };

    format!(
        "FINDING TO VERIFY:\n\
File: {}\n\
Line: {}-{}\n\
Category: {}\n\
Title: {}\n\
\n\
Description:\n\
{}\n\
\n\
Exploit scenario:\n\
{exploit_scenario}\n\
\n\
Preconditions:\n\
{pre}\n\
\n\
Code snippet (as reported by scanner — verify against actual file):\n\
{}\n\
\n\
═══════════════════════════════════════════════════════════════════════════\n\
ARCHITECTURE CONTEXT (from prior repo analysis and the tree-sitter callgraph — use as\n\
starting points, but VERIFY against actual code; this may be incomplete or\n\
stale):\n\
═══════════════════════════════════════════════════════════════════════════\n\
{arch_display}\n\
\n\
Investigate using Read/Grep. Start with CALL GRAPH CONTEXT, and if it is\n\
ambiguous/incomplete for this finding, expand to broader code-led tracing.\n\
Then end with the two required VERDICT and CVSS lines.",
        f.file,
        f.line_start,
        f.line_end,
        f.vuln_class.as_str(),
        f.title,
        f.description,
        f.code_snippet,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{ControlKind, EntryPoint, EntryPointKind, VulnClass};

    fn minimal_finding() -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "c".to_string(),
            file: "src/app.py".to_string(),
            line_start: 10,
            line_end: 12,
            vuln_class: VulnClass::Injection,
            cwe: None,
            title: "SQL injection in handler".to_string(),
            impact: String::new(),
            description: "user input flows into a raw query".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "cur.execute('SELECT ' + user_in)".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.8,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        }
    }

    fn minimal_ctx() -> ContextPackage {
        ContextPackage {
            seed_taint_paths: Default::default(),
            seed_taint_evidence: Default::default(),
            def_spans: Default::default(),
            repo_root: "/repo".to_string(),
            language: "python".to_string(),
            call_graph: Default::default(),
            call_graph_files: Default::default(),
            entry_points: Vec::new(),
            unsafe_sinks: Vec::new(),
            modules: Vec::new(),
            all_files: Vec::new(),
            excluded: Default::default(),
            known_cves: Vec::new(),
            design_controls: Vec::new(),
            changed_files: Default::default(),
            diff_scope_active: false,
            app_profile: None,
            threat_model: None,
            notes: String::new(),
            compliance_guidance: String::new(),
        }
    }

    fn view(ctx: &ContextPackage) -> GraphView {
        GraphView::new(ctx)
    }

    #[test]
    fn system_prompt_splices_in_exclusion_rules_and_ends_with_the_two_line_grammar() {
        assert!(SYSTEM.contains(bc_prompts::EXCLUSION_RULES));
        assert!(SYSTEM.contains("VERDICT: TRUE_POSITIVE|FALSE_POSITIVE"));
        assert!(SYSTEM.contains("CVSS: CVSS:3.1/AV:_"));
    }

    /// Matches `s6_verify.py:69-91` — step A (start from the call graph),
    /// step C's graph-first wording, and the trailing "missing graph edges
    /// are NOT enough to refute" paragraph, all previously absent.
    #[test]
    fn system_prompt_leads_with_call_graph_context_and_warns_against_refuting_on_missing_edges() {
        assert!(SYSTEM.contains("A. Start from the CALL GRAPH CONTEXT section in the user prompt"));
        assert!(SYSTEM.contains(
            "C. Walk the call chain outward: follow callers/callees from graph context,"
        ));
        assert!(SYSTEM
            .contains("Missing graph edges are NOT enough\nto refute a finding by themselves."));
    }

    /// The `\`-continuation indentation-stripping bug (see `bc_prompts::
    /// EXCLUSION_RULES`'s own doc comment on why it avoids that style):
    /// every WORKFLOW/DECISION RULE/CVSS bullet must keep its real leading
    /// whitespace in the COMPILED string, not just the source.
    /// The 5 impossible CWE-362 findings the 2026-09-06 Juice Shop scan
    /// confirmed at 8/10: the verifier has to be told the event-loop rule
    /// outright, because it will not derive it under time pressure.
    #[test]
    fn system_prompt_states_the_javascript_event_loop_rule() {
        let p = &*SYSTEM;
        assert!(p.contains("run-to-completion event loop"), "{p}");
        assert!(p.contains("asynchronous boundary"), "{p}");
        assert!(p.contains("are NOT races — FALSE_POSITIVE"), "{p}");
        assert!(p.contains("worker_threads"), "{p}");
        // Registering a handler is not a boundary — the shape that made
        // `registerWebsocketEvents.ts` look like a race.
        assert!(p.contains("socket.on"), "{p}");
    }

    /// The 3 XSS findings on default-escaped syntax the same scan
    /// confirmed at 8-9/10.
    #[test]
    fn system_prompt_states_which_template_constructs_are_raw() {
        let p = &*SYSTEM;
        assert!(p.contains("HTML-escaped by the"), "{p}");
        // The Handlebars point the `{{userEmail}}` field case turned on:
        // escaping covers `=`, so an unquoted attribute is still safe.
        assert!(p.contains("quotes AND `=`"), "{p}");
        for raw in [
            "{{{ }}}",
            "!{ }",
            "<%- %>",
            "|safe",
            ".html_safe",
            "@Html.Raw",
            "{!! !!}",
            "v-html",
            "dangerouslySetInnerHTML",
            "[innerHTML]",
            "{@html}",
        ] {
            assert!(p.contains(raw), "missing raw construct {raw} in {p}");
        }
        // And the contexts where escaping is not the whole answer.
        assert!(p.contains("javascript:`/`data:"), "{p}");
    }

    /// The single highest-volume verdict in the pipeline: an injection
    /// finding on a query the driver already parameterizes. The fact has
    /// to name the binding spelling in each language, or the verifier
    /// cannot tell it from the concatenating one.
    #[test]
    fn system_prompt_lists_the_binding_and_the_concatenating_sql_spellings() {
        let p = &*SYSTEM;
        assert!(p.contains("Parameterized SQL (CWE-89/564)"), "{p}");
        for bound in [
            "`PreparedStatement` with `?`",
            "`SqlParameter`",
            "EF Core LINQ",
            "`FromSqlInterpolated`",
            "`execute(sql, params)`",
            "`Exec(sql, args...)`",
            "`prepare` plus `bindValue`",
            "`bind_param`",
            "`where(hash)`",
            "`sqlx::query!`",
            "Diesel",
        ] {
            assert!(p.contains(bound), "missing bound spelling {bound}");
        }
        for injectable in [
            "`FromSqlRaw`",
            "`fmt.Sprintf` into",
            "`find_by_sql`",
            "Slick's `#$` splice",
            "table name, column name, ORDER BY column",
        ] {
            assert!(
                p.contains(injectable),
                "missing injectable spelling {injectable}"
            );
        }
        assert!(p.contains("is a FALSE_POSITIVE"), "{p}");
        assert!(p.contains("stays a TRUE_POSITIVE"), "{p}");
    }

    /// Safe Rust closes the memory-safety classes outright — but only
    /// safe Rust, so the fact has to name the escape hatch as precisely as
    /// the guarantee.
    #[test]
    fn system_prompt_confines_rust_memory_bugs_to_unsafe_and_ffi() {
        let p = &*SYSTEM;
        assert!(
            p.contains("Rust memory safety (CWE-416/415/362/787)"),
            "{p}"
        );
        assert!(p.contains("Safe Rust cannot produce a"), "{p}");
        assert!(
            p.contains("unless the flow passes through an `unsafe` block"),
            "{p}"
        );
        assert!(p.contains("`unsafe impl Send`"), "{p}");
        assert!(p.contains("FFI call"), "{p}");
        // And the classes safe Rust does NOT rule out, so the fact is not
        // read as "Rust findings are always false positives".
        assert!(p.contains("Panics, deadlocks"), "{p}");
    }

    /// Go is where the JS event-loop rule above does the most damage if
    /// it is over-generalized, so the Go entry says outright that it does
    /// not apply.
    #[test]
    fn system_prompt_says_the_event_loop_rule_does_not_apply_to_go() {
        let p = &*SYSTEM;
        assert!(p.contains("Go concurrency (CWE-362/366)"), "{p}");
        assert!(p.contains("real parallelism on real OS"), "{p}");
        assert!(p.contains("does NOT apply to Go"), "{p}");
        for ordering in [
            "`sync.Mutex`/`RWMutex`",
            "channel hand-off",
            "`sync.Once`",
            "`atomic.*`",
        ] {
            assert!(
                p.contains(ordering),
                "missing Go ordering primitive {ordering}"
            );
        }
    }

    #[test]
    fn system_prompt_states_which_java_constructs_are_atomic() {
        let p = &*SYSTEM;
        assert!(p.contains("Java atomicity (CWE-362/366/367)"), "{p}");
        assert!(
            p.contains("`synchronized` block or method on the SAME"),
            "{p}"
        );
        assert!(p.contains("`ReentrantLock`"), "{p}");
        assert!(p.contains("`computeIfAbsent`"), "{p}");
        assert!(p.contains("`putIfAbsent`"), "{p}");
        // The other half: two atomic calls in a row are not one atomic step.
        assert!(p.contains("`containsKey` then `put`"), "{p}");
    }

    #[test]
    fn system_prompt_separates_bounded_from_unbounded_c_copies() {
        let p = &*SYSTEM;
        assert!(p.contains("C/C++ bounded vs unbounded copies"), "{p}");
        for unbounded in ["`strcpy`", "`strcat`", "`sprintf`", "`gets`"] {
            assert!(p.contains(unbounded), "missing unbounded call {unbounded}");
        }
        for bounded in [
            "`snprintf`/`strlcpy`/`strlcat`",
            "`fgets(buf, sizeof buf, f)`",
        ] {
            assert!(p.contains(bounded), "missing bounded call {bounded}");
        }
        assert!(p.contains("`sizeof(ptr)` after a parameter decayed"), "{p}");
        // A bounded copy is still allowed to leave the buffer unterminated.
        assert!(
            p.contains("destination UNTERMINATED when the source fills it"),
            "{p}"
        );
    }

    /// The mirror image of the JavaScript entry: a lock that serializes
    /// bytecode is not an event loop, and the verifier must not borrow the
    /// Node reasoning for Python or Ruby.
    #[test]
    fn system_prompt_refuses_the_gil_as_a_defense_against_a_race() {
        let p = &*SYSTEM;
        assert!(p.contains("Python and Ruby interpreter locks"), "{p}");
        assert!(p.contains("NEVER a reason to refute a"), "{p}");
        assert!(p.contains("`os.path.exists` then `open`"), "{p}");
        assert!(p.contains("`find_or_create_by`"), "{p}");
        assert!(p.contains("`x += 1` is not one of those"), "{p}");
    }

    /// The prose facts above and `bc_stage_s5::lang_gates` are two halves
    /// of the same two rules — the gates settle the unambiguous cases
    /// before a session is paid for, the prompt catches the rest. They
    /// must not disagree: anything the gate DROPS the prompt must call a
    /// false positive, and anything the gate KEEPS the prompt must leave
    /// open. This runs the real gates and checks the prompt says the same.
    #[test]
    fn language_facts_agree_with_the_s5_lang_gates() {
        use bc_stage_s5::lang_gates;

        let p = &*SYSTEM;

        // 1a. A synchronous `++` on shared state: the gate drops it…
        let mut sync_race = minimal_finding();
        sync_race.file = "routes/captcha.ts".to_string();
        sync_race.cwe = Some("CWE-362".to_string());
        sync_race.code_snippet = "req.app.locals.captchaId++;".to_string();
        assert!(lang_gates::could_apply(&sync_race));
        let window = lang_gates::SourceWindow::read(&sync_race, None);
        assert_eq!(
            lang_gates::synchronous_js_race(&sync_race, &window),
            Some(lang_gates::SYNC_JS_REASON)
        );
        // …and the prompt calls exactly that shape a false positive.
        assert!(p.contains("`counter++`"), "{p}");
        assert!(p.contains("are NOT races — FALSE_POSITIVE"), "{p}");
        assert!(lang_gates::SYNC_JS_REASON.contains("cannot race"));

        // 1b. An `await` between check and act: the gate keeps it, and the
        // prompt requires exactly that boundary before calling it a race.
        let mut awaited = sync_race.clone();
        awaited.code_snippet = "if (!u.done) {\n  await save(u);\n  u.done = true;\n}".to_string();
        let window = lang_gates::SourceWindow::read(&awaited, None);
        assert_eq!(lang_gates::synchronous_js_race(&awaited, &window), None);
        assert!(p.contains("an asynchronous boundary — `await`"), "{p}");

        // 2a. A default-escaped Handlebars field: the gate drops it…
        let mut escaped = minimal_finding();
        escaped.file = "views/dataErasureForm.hbs".to_string();
        escaped.cwe = Some("CWE-79".to_string());
        escaped.code_snippet = "<p>{{ userEmail }}</p>".to_string();
        assert!(lang_gates::could_apply(&escaped));
        let window = lang_gates::SourceWindow::read(&escaped, None);
        assert_eq!(
            lang_gates::template_autoescaped(&escaped, &window).as_deref(),
            Some("template engine escapes this construct by default (handlebars)")
        );
        // …and the prompt lists `{{ x }}` as escaped by default.
        assert!(p.contains("Handlebars/Mustache `{{ x }}`"), "{p}");
        assert!(p.contains("is a FALSE_POSITIVE unless you can show"), "{p}");

        // 2b. The triple-stash is raw: the gate keeps it, and the prompt
        // lists the identical construct among the raw ones.
        let mut raw = escaped.clone();
        raw.code_snippet = "<p>{{{ userEmail }}}</p>".to_string();
        let window = lang_gates::SourceWindow::read(&raw, None);
        assert_eq!(lang_gates::template_autoescaped(&raw, &window), None);
        assert!(p.contains("Only these are RAW: `{{{ }}}`"), "{p}");

        // 3. The gates are JS/TS- and template-only by construction, so
        // the facts this change adds for other languages cannot collide
        // with them — the same finding shape in Go is not even a
        // candidate, which is why the Go entry has to say in words that
        // the JavaScript rule does not travel.
        let mut go_race = sync_race.clone();
        go_race.file = "internal/handler/count.go".to_string();
        assert!(!lang_gates::could_apply(&go_race));
        assert!(p.contains("does NOT apply to Go"), "{p}");
    }

    /// The four 2026-09-07 polyglot false positives the verifier confirmed
    /// at high confidence. The fact has to name the marker the user prompt
    /// actually prints, or the verifier cannot act on it.
    #[test]
    fn system_prompt_states_that_a_framework_guarded_route_has_an_authorization_check() {
        let p = &*SYSTEM;
        assert!(
            p.contains("Framework-guarded routes (CWE-284/285/287/306/862/863)"),
            "{p}"
        );
        // The guard refutes only the authorization claim — never an injection
        // class on the same route (a live Go run refuted a path traversal as
        // "protected by RequireAdmin").
        assert!(
            p.contains("A guard changes WHO can reach the handler, never WHETHER its code is"),
            "{p}"
        );
        // The exact marker `build_user_prompt` stamps on such an entry point.
        assert!(
            p.contains("[GUARDED — not reachable without\n  auth]"),
            "{p}"
        );
        for spelling in [
            "Route::middleware(['auth'])->group",
            "before_action :authenticate_user!",
            ".route_layer(middleware::from_fn(…))",
            "@PreAuthorize",
            "[Authorize]",
        ] {
            assert!(p.contains(spelling), "missing guard spelling {spelling}");
        }
        assert!(
            p.contains("FALSE_POSITIVE unless it shows the guard is"),
            "{p}"
        );
        // Both halves: the marker also works as evidence FOR a finding…
        assert!(
            p.contains("`[UNAUTH-REACHABLE]` means S0 found NO guard"),
            "{p}"
        );
        // …and an unlabeled entry point settles nothing.
        assert!(p.contains("neither marker are not framework routes"), "{p}");
    }

    /// The prompt's half of the route-guard rule and
    /// `bc_stage_s5::route_gates`' half must not disagree either: what the
    /// gate DROPS the prompt must call a false positive, and what the gate
    /// KEEPS — an open route, or a claim that the guard itself is broken —
    /// the prompt must leave open.
    #[test]
    fn language_facts_agree_with_the_s5_route_gate() {
        use bc_model::{EntryPoint, EntryPointKind};
        use bc_stage_s5::route_gates::RouteIndex;

        let p = &*SYSTEM;

        let eps = [
            EntryPoint {
                file: "routes/web.php".to_string(),
                function: "OpsConsoleController@runMaintenance".to_string(),
                kind: EntryPointKind::Framework,
                reachable_from_unauth: false,
            },
            EntryPoint {
                file: "routes/web.php".to_string(),
                function: "ReportController@search".to_string(),
                kind: EntryPointKind::Framework,
                reachable_from_unauth: true,
            },
        ];
        let routes = RouteIndex::new(&eps);

        let mut authz = minimal_finding();
        authz.file = "routes/web.php".to_string();
        authz.cwe = Some("CWE-862".to_string());
        authz.title = "Missing Authorization Check".to_string();
        authz.description = "The handler performs no authorization check.".to_string();

        // The claim is in scope for the gate…
        assert!(bc_stage_s5::route_gates::could_apply(&authz, &routes));
        // …and the prompt states the same rule the gate applies.
        assert!(
            p.contains("HAS an authorization check for every request"),
            "{p}"
        );

        // A bypass claim is out of scope for the gate, and the prompt
        // names exactly that as what keeps the finding alive.
        let mut bypass = authz.clone();
        bypass.description =
            "The auth middleware can be bypassed with a trailing slash.".to_string();
        assert!(!bc_stage_s5::route_gates::could_apply(&bypass, &routes));
        assert!(p.contains("bypassable"), "{p}");

        // And with no framework entry point at all the gate is inert,
        // which is the case the prompt hands back to ordinary reasoning.
        assert!(!bc_stage_s5::route_gates::could_apply(
            &authz,
            &RouteIndex::new(&[])
        ));
    }

    #[test]
    fn system_prompt_preserves_bullet_indentation() {
        assert!(SYSTEM.contains("\n  A. Start from"));
        assert!(SYSTEM.contains("\n     tree-sitter-derived"));
        assert!(SYSTEM.contains("\n  TRUE_POSITIVE  — only when"));
        assert!(SYSTEM.contains("\n                   point AND"));
        assert!(SYSTEM.contains("\n  AV  N network"));
    }

    /// Matches `s6_verify.py:378,383-385` in shape — the architecture-context
    /// header crediting the callgraph as a source, and the closing instruction
    /// to start verification from CALL GRAPH CONTEXT. The word is deliberately
    /// NOT Python's "sqlite": that harness really did read the graph back out
    /// of a SQLite artifact store, and this one does not (see
    /// `callgraph_context_for_finding`), so the header names tree-sitter.
    #[test]
    fn build_user_prompt_credits_the_callgraph_by_its_real_provenance_and_says_to_start_there() {
        let ctx = minimal_ctx();
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(prompt.contains(
            "ARCHITECTURE CONTEXT (from prior repo analysis and the tree-sitter callgraph"
        ));
        assert!(!prompt.contains("sqlite"), "{prompt}");
        assert!(!prompt.contains("SQLite"), "{prompt}");
        assert!(
            prompt.contains("Start with CALL GRAPH CONTEXT, and if it is\nambiguous/incomplete")
        );
    }

    #[test]
    fn build_user_prompt_defaults_when_context_is_empty() {
        let ctx = minimal_ctx();
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(prompt.contains("File: src/app.py"));
        assert!(prompt.contains("Line: 10-12"));
        assert!(prompt.contains("Category: injection"));
        assert!(prompt.contains("  (none listed)"));
        assert!(prompt.contains("(not provided)"));
        assert!(prompt.contains("CALL GRAPH CONTEXT (tree-sitter-derived): (none available)"));
    }

    #[test]
    fn build_user_prompt_includes_preconditions_and_exploit_scenario_when_present() {
        let mut f = minimal_finding();
        f.preconditions = vec!["attacker controls user_in".to_string()];
        f.exploit_scenario = "attacker sends a crafted request".to_string();
        let ctx = minimal_ctx();
        let prompt = build_user_prompt(&f, &ctx, &view(&ctx));
        assert!(prompt.contains("  - attacker controls user_in"));
        assert!(prompt.contains("attacker sends a crafted request"));
    }

    /// Neither marker is earned by a non-`Framework` entry point, in EITHER
    /// direction. `reachable_from_unauth` is a free field in S1's reply
    /// schema, so on a `Network` row a `true` is the survey model's opinion —
    /// and the LANGUAGE FACTS block tells the verifier `[UNAUTH-REACHABLE]`
    /// means the seed plane found no guard, which would make that opinion
    /// read as a static-analysis fact. Only S0's framework plane sets the
    /// field from evidence, so only `Framework` rows are labeled.
    #[test]
    fn build_user_prompt_shows_entry_points_and_leaves_non_framework_kinds_unmarked() {
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![
            EntryPoint {
                file: "api.py".to_string(),
                function: "handle".to_string(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: true,
            },
            EntryPoint {
                file: "cli.py".to_string(),
                function: "main".to_string(),
                kind: EntryPointKind::Cli,
                reachable_from_unauth: false,
            },
        ];
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(prompt.contains("KNOWN EXTERNAL ENTRY POINTS"));
        // A model-asserted `true` on a network entry point is not evidence,
        // so the row prints bare rather than claiming S0 found no guard.
        assert!(prompt.contains("  - network: handle @ api.py\n"));
        assert!(!prompt.contains("handle @ api.py [UNAUTH-REACHABLE]"));
        assert!(!prompt.contains("handle @ api.py [GUARDED"));
        // A CLI entry point's `false` is the serde default, not evidence,
        // so it earns no marker either way.
        assert!(prompt.contains("  - cli: main @ cli.py"));
        assert!(!prompt.contains("main @ cli.py [UNAUTH-REACHABLE]"));
        assert!(!prompt.contains("main @ cli.py [GUARDED"));
        // And the block that reads those bare rows says they settle nothing.
        let p = &*SYSTEM;
        assert!(
            p.contains("neither marker are not framework routes and settle nothing"),
            "{p}"
        );
    }

    /// The 2026-09-07 polyglot false positives: four handlers whose entry
    /// points said `reachable_from_unauth: false` were confirmed as
    /// "missing authorization" anyway, because the only thing the prompt
    /// rendered was the ABSENCE of `[UNAUTH-REACHABLE]` — nothing a model
    /// can read. A guarded framework route now says so in words.
    #[test]
    fn build_user_prompt_marks_a_guarded_framework_route_as_guarded() {
        let mut ctx = minimal_ctx();
        ctx.entry_points = vec![
            EntryPoint {
                file: "routes/web.php".to_string(),
                function: "OpsConsoleController@runMaintenance".to_string(),
                kind: EntryPointKind::Framework,
                reachable_from_unauth: false,
            },
            EntryPoint {
                file: "routes/web.php".to_string(),
                function: "ReportController@search".to_string(),
                kind: EntryPointKind::Framework,
                reachable_from_unauth: true,
            },
        ];
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(prompt.contains("OpsConsoleController@runMaintenance @ routes/web.php [GUARDED"));
        assert!(prompt.contains("[GUARDED — not reachable without auth]"));
        assert!(prompt.contains(
            "  - framework: ReportController@search @ routes/web.php [UNAUTH-REACHABLE]"
        ));
    }

    #[test]
    fn build_user_prompt_truncates_entry_points_beyond_25_with_a_count_suffix() {
        let mut ctx = minimal_ctx();
        ctx.entry_points = (0..30)
            .map(|i| EntryPoint {
                file: format!("f{i}.py"),
                function: format!("fn{i}"),
                kind: EntryPointKind::Network,
                reachable_from_unauth: false,
            })
            .collect();
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(prompt.contains("...(+5 more)"));
    }

    #[test]
    fn build_user_prompt_shows_known_callers_matching_by_qualified_file() {
        let mut ctx = minimal_ctx();
        ctx.call_graph.insert(
            "module.caller_fn".to_string(),
            vec!["src/app.py::handler".to_string()],
        );
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(prompt.contains("KNOWN CALLERS OF THIS FILE"));
        assert!(prompt.contains("  - module.caller_fn"));
    }

    #[test]
    fn callers_of_stops_at_the_15_caller_limit() {
        let mut ctx = minimal_ctx();
        for i in 0..20 {
            ctx.call_graph.insert(
                format!("caller_{i:02}"),
                vec!["src/app.py::handler".to_string()],
            );
        }
        let callers = callers_of("src/app.py", &ctx, 15);
        assert_eq!(callers.len(), 15);
    }

    #[test]
    fn callers_of_skips_callers_that_do_not_reference_the_file() {
        let mut ctx = minimal_ctx();
        ctx.call_graph.insert(
            "unrelated_caller".to_string(),
            vec!["other/file.py::helper".to_string()],
        );
        ctx.call_graph.insert(
            "real_caller".to_string(),
            vec!["src/app.py::handler".to_string()],
        );
        let callers = callers_of("src/app.py", &ctx, 15);
        assert_eq!(callers, vec!["  - real_caller".to_string()]);
    }

    #[test]
    fn build_user_prompt_shows_design_controls_and_the_bypass_instruction() {
        let mut ctx = minimal_ctx();
        ctx.design_controls = vec![Control {
            name: "WAF".to_string(),
            kind: ControlKind::Auth,
            protects: vec!["src/*.py".to_string()],
            notes: "blocks SQLi".to_string(),
        }];
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(prompt.contains("DESIGN CONTROLS IN EFFECT ON THIS PATH"));
        assert!(prompt.contains("[auth] WAF protects this path — blocks SQLi"));
        assert!(prompt.contains("You MUST demonstrate a bypass"));
    }

    #[test]
    fn build_user_prompt_control_with_no_protects_globs_is_global() {
        let mut ctx = minimal_ctx();
        ctx.design_controls = vec![Control {
            name: "Global".to_string(),
            kind: ControlKind::Other,
            protects: Vec::new(),
            notes: String::new(),
        }];
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(prompt.contains("[other] Global protects this path"));
    }

    #[test]
    fn build_user_prompt_control_that_does_not_match_is_omitted() {
        let mut ctx = minimal_ctx();
        ctx.design_controls = vec![Control {
            name: "Irrelevant".to_string(),
            kind: ControlKind::Other,
            protects: vec!["other/*.py".to_string()],
            notes: String::new(),
        }];
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(!prompt.contains("DESIGN CONTROLS IN EFFECT"));
    }

    #[test]
    fn build_user_prompt_includes_architecture_notes() {
        let mut ctx = minimal_ctx();
        ctx.notes = "legacy monolith, migrating to microservices".to_string();
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(prompt.contains("ARCHITECTURE NOTES:\nlegacy monolith"));
    }

    #[test]
    fn build_user_prompt_includes_compliance_guidance_when_present() {
        let mut ctx = minimal_ctx();
        ctx.compliance_guidance = "Prioritize PCI-DSS Req 6 findings.".to_string();
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(prompt.contains("COMPLIANCE GUIDANCE:\nPrioritize PCI-DSS Req 6 findings."));
    }

    #[test]
    fn build_user_prompt_omits_compliance_guidance_when_absent() {
        let ctx = minimal_ctx();
        let prompt = build_user_prompt(&minimal_finding(), &ctx, &view(&ctx));
        assert!(!prompt.contains("COMPLIANCE GUIDANCE"));
    }

    // ── candidate_qnodes_for_finding / callgraph_context_for_finding ──────

    #[test]
    fn callgraph_context_for_finding_with_no_graph_at_all() {
        let ctx = minimal_ctx();
        let out = callgraph_context_for_finding(&minimal_finding(), &ctx, &view(&ctx));
        assert_eq!(
            out,
            "CALL GRAPH CONTEXT (tree-sitter-derived): (none available)"
        );
    }

    #[test]
    fn callgraph_context_for_finding_with_a_graph_but_no_candidates_at_the_finding_location() {
        let mut ctx = minimal_ctx();
        // Populates the graph, but with nodes in an unrelated file.
        ctx.call_graph
            .insert("other.py::a".to_string(), vec!["other.py::b".to_string()]);
        let out = callgraph_context_for_finding(&minimal_finding(), &ctx, &view(&ctx));
        assert!(out.contains("  - graph nodes: 1"));
        assert!(out.contains("  - graph edges: 1"));
        assert!(out.contains("  - candidate functions at finding location: (none)"));
        assert!(out.contains("use Grep on file/class symbols"));
    }

    #[test]
    fn callgraph_context_for_finding_reports_source_and_sink_refs_without_a_marker() {
        let mut ctx = minimal_ctx();
        ctx.call_graph
            .insert("other.py::a".to_string(), vec!["other.py::b".to_string()]);
        let mut f = minimal_finding();
        f.source_ref = Some("src/app.py:1".to_string());
        f.sink_ref = Some("src/app.py:10".to_string());
        let out = callgraph_context_for_finding(&f, &ctx, &view(&ctx));
        assert!(out.contains("  - finding.source_ref: src/app.py:1\n"));
        assert!(out.contains("  - finding.sink_ref: src/app.py:10\n"));
    }

    #[test]
    fn callgraph_context_for_finding_marks_backfilled_refs_as_inferred() {
        let mut ctx = minimal_ctx();
        ctx.call_graph
            .insert("other.py::a".to_string(), vec!["other.py::b".to_string()]);
        let mut f = minimal_finding();
        f.source_ref = Some("src/app.py:1".to_string());
        f.sink_ref = Some("src/app.py:10".to_string());
        f.backfilled_refs = vec!["source_ref".to_string(), "sink_ref".to_string()];
        let out = callgraph_context_for_finding(&f, &ctx, &view(&ctx));
        assert!(
            out.contains("  - finding.source_ref: src/app.py:1 (inferred from AST, unverified)")
        );
        assert!(out.contains("  - finding.sink_ref: src/app.py:10 (inferred from AST, unverified)"));
    }

    #[test]
    fn callgraph_context_for_finding_empty_string_refs_are_omitted() {
        let mut ctx = minimal_ctx();
        ctx.call_graph
            .insert("other.py::a".to_string(), vec!["other.py::b".to_string()]);
        let mut f = minimal_finding();
        f.source_ref = Some(String::new());
        f.sink_ref = Some(String::new());
        let out = callgraph_context_for_finding(&f, &ctx, &view(&ctx));
        assert!(!out.contains("finding.source_ref"));
        assert!(!out.contains("finding.sink_ref"));
    }

    #[test]
    fn callgraph_context_for_finding_lists_candidates_with_callers_and_callees() {
        let mut ctx = minimal_ctx();
        ctx.call_graph.insert(
            "caller.py::caller_fn".to_string(),
            vec!["src/app.py::handler".to_string()],
        );
        ctx.call_graph.insert(
            "src/app.py::handler".to_string(),
            vec!["callee.py::callee_fn".to_string()],
        );
        let out = candidate_qnodes_for_finding(&minimal_finding(), &view(&ctx));
        assert_eq!(out, vec!["src/app.py::handler".to_string()]);

        let full = callgraph_context_for_finding(&minimal_finding(), &ctx, &view(&ctx));
        assert!(full.contains("  - candidate functions at/near finding line:"));
        assert!(full.contains("    - src/app.py::handler"));
        assert!(full.contains("  - around src/app.py::handler:"));
        assert!(full.contains("    - caller -> caller.py::caller_fn -> src/app.py::handler"));
        assert!(full.contains("    - callee -> src/app.py::handler -> callee.py::callee_fn"));
    }

    #[test]
    fn callgraph_context_for_finding_candidate_with_no_callers_or_callees_says_none_in_graph() {
        let mut ctx = minimal_ctx();
        // The only edge is unrelated, so `src/app.py::handler` (the sole
        // qnode the call graph places in the finding's file) has neither
        // callers nor callees of its own.
        ctx.call_graph
            .insert("src/app.py::handler".to_string(), Vec::new());
        ctx.call_graph
            .insert("other.py::a".to_string(), vec!["other.py::b".to_string()]);
        let out = callgraph_context_for_finding(&minimal_finding(), &ctx, &view(&ctx));
        assert!(out.contains("    - caller -> (none in graph)"));
        assert!(out.contains("    - callee -> (none in graph)"));
    }
}
