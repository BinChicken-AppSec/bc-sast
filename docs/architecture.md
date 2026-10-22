# Architecture

Crate map and data flow for `bc-sast`.

## Workspace layout

The workspace is organized in dependency tiers: each crate depends only on
crates in a lower or equal tier, never a higher one. Tiers follow the
relative-path dependency edges in each crate's `Cargo.toml`, not directory
naming.

```
crates/
  Tier 0: pure logic, no I/O, no intra-workspace deps
    appsec-cvss: CVSS 3.1 base/environmental scoring (FIRST.org spec)
    appsec-cwe: CWE id -> canonical MITRE name lookup
    appsec-dedup-core: generic same-file/vuln-class/line-tolerance dup clustering
    appsec-json-repair: pulls a JSON object/array out of a prose-wrapped LLM response
    appsec-metrics: pure ScanMetrics building blocks (timestamps, LOC counts)
    appsec-pathjail: path confinement + UNC/SMB-redirection rejection (CWE-22)
    appsec-pipeline-core: the shared PipelineStage/StageOutcome/StageError contract
    appsec-pricing: exact per-call token cost from a vendored models.dev price table
    appsec-prompts: shared, byte-identical prompt-cache-friendly prompt blocks
    appsec-redact: card/PII/credential redaction (Luhn/IIN/SSN-gated)
    appsec-validation-scoring: deterministic S11 fix-scoring engine (4 weighted gates)
    appsec-yaml: purpose-built YAML subset parser for this project's own configs, with a strict mode for third-party files
    appsec-xml: purpose-built XML 1.0 reader/writer for SOAP/WSDL, XSD and OData CSDL (no DTDs, bounded, namespace-aware, span-based minimal edits)

  Tier 1: I/O boundaries and cross-cutting infrastructure
    appsec-api-spec: pure API description support (OpenAPI, GraphQL, AsyncAPI, OpenRPC, Protocol Buffers, RAML, API Blueprint, WSDL, OData CSDL): detection, placement, validation, emission and repair checks (appsec-yaml, appsec-xml, appsec-redact, regex)
    appsec-model: cross-stage domain model (ContextPackage, Finding, FinalReport)
    appsec-config: YAML config load + step-defaults merge + ${VAR} env expansion (appsec-yaml, appsec-pathjail)
    appsec-checkpoint: CheckpointStore trait + Null/SQLite implementations
    appsec-diffcapture: pre-edit snapshot, git-diff capture, per-file revert (appsec-pathjail)
    appsec-gateway-http: TLS-aware reqwest::Client construction for talking to an AI gateway (appsec-pathjail)
    appsec-llm-client: dialect-agnostic LlmClient/ToolExecutor trait boundary
    appsec-repo-analysis: deterministic repo walk, call-graph, taint-path chunking (appsec-model)
    appsec-callgraph: LLM-free tree-sitter scanner + call graph + structured taint
                  evidence engine behind S0 (appsec-json-repair, appsec-yaml)

  Tier 2: dialect/tool implementations and report builders
    appsec-llm-anthropic / appsec-llm-openai: Anthropic Messages / OpenAI Chat Completions + Responses LlmClient dialects
    appsec-llm-agentic: dialect-agnostic multi-turn agentic tool-use loop
    appsec-sandbox-tools: jailed local Read/Glob/Grep(/Edit/Write) ToolExecutor
    appsec-enrich: post-S7 CMDB-driven environmental CVSS + OffensivePriority
    appsec-report-md / appsec-sarif / appsec-csv: FinalReport -> report.md / report.sarif / report.csv renderers
    appsec-compliance: embedded framework presets, prompt-guidance splice, requirement tagging
    appsec-thirdparty: Checkmarx/Snyk/Semgrep/Aikido/Sonatype report-file parsers
    appsec-thirdparty-api: the same five vendors' live REST clients (shared retry helper)
    appsec-policy-gate: deterministic, no-LLM S10 remediation eligibility gate
    appsec-github: GitHub PR comment sync (inline + fallback, idempotent)

  Tier 3: pipeline stages
    appsec-stage-s0: static seed, the tree-sitter seeding stage wrapping appsec-callgraph
    appsec-stage-s1 through appsec-stage-s8: the scan pipeline (see Data flow below)
    appsec-stage-s10: remediation stage
    appsec-stage-s11: fix-validation stage

  Tier 4: orchestration
    appsec-orchestrator: sequences S0-S8 and S9 reporting into run_scan; wires S10/S11 into remediate

  Tier 5: CLI / product surface
    appsec-cli: clap parsing, concrete LlmClient/ToolExecutor wiring, appsec-scan binary
    appsec-interactive: terminal finding picker used by appsec-cli's -i/--interactive flag

  Not part of the shipped product
    appsec-parity-tests: cross-checks this port's CVSS/redact/config/S11-scoring
                     output against the real vvaharness Python source
```

`appsec-stage-s5` depends directly on `appsec-stage-s7` (S5's pre-verify
semantic-dedup pass reuses S7's dedup logic rather than duplicating it), and
`appsec-stage-s11` depends on `appsec-stage-s10` (it scores an S10
`RemediationRecord`). Both are same-tier (Tier 3) edges, not violations of
the tier ordering. Nothing in Tier 3 depends on Tier 4 or above.

## Data flow: scan pipeline (S0-S9)

```
   repo  +  optional known_cves / design_controls / CMDB app-id
                              |
   S0 seed         -- LLM-free tree-sitter scan (see S0 static seed below) ------> SeedPackage
   S1 preprocess   -- agentic repo survey + deterministic call graph --> ContextPackage
   S2 threatmodel  -- single-shot LLM over gathered evidence --------> ThreatModel (or None on failure)
   S3 decompose    -- LLM risk-ranked chunks + deterministic 100%-coverage sweep --> TaskManifest
   S4 deepdive     -- N sequential LLM calls per chunk, majority-voted -----------> Finding[]
   S5 prefilter    -- deterministic confidence/evidence gates + S7 pre-dedup
   S6 verify       -- adversarial agentic session tries to disprove each finding --> TRUE/FALSE_POSITIVE + CVSS
   S7 dedup        -- deterministic + optional semantic LLM dedup --------------> canonical Finding[]
   S8 chain        -- single LLM call over ALL findings: exploit chains + re-rank --> FinalReport
   S9 reporting    -- deterministic typed report rendering --------------------> Markdown + SARIF
                              |                                                  (CLI also publishes CSV + JSON)
                    optional S10 remediation + S11 review
```

Each stage crate implements the shared `PipelineStage` trait
(`appsec-pipeline-core`) and returns a `StageOutcome<T>`, either `Ok` or
`Degraded { value, reason }`. What each stage does, and its degrade policy:

| Stage | Does | Degrades to | Fatal path |
|---|---|---|---|
| **appsec-stage-s0** seed | LLM-free (in `rules` mode) tree-sitter scan producing a `SeedPackage` S1 merges: entry points, unsafe sinks, taint paths, structured taint evidence, framework entry points, and a reusable call graph. | Empty `SeedPackage` on *any* failure (disabled, no supported language, no applicable rules, nothing matched) | none |
| **appsec-stage-s1** preprocess | Agentic Read/Glob/Grep exploration builds a rough structural map (language, modules, entry points, unsafe sinks, seed call graph); validated/filled out against ground truth by `appsec-repo-analysis`'s deterministic passes. CMDB lookup and threat-model generation are explicitly *not* this stage's job. | Partial map on bad LLM response | none |
| **appsec-stage-s2** threatmodel | Single-shot, non-agentic LLM call over deterministically gathered evidence produces a `ThreatModel`. | **No internal degrade**. Errors propagate as `Err`; `appsec-orchestrator` catches and falls back to `threat_model = None`. | any parse/shape failure |
| **appsec-stage-s3** decompose | Single-shot LLM call produces a risk-ranked manifest, grounded in a `F###`/`E###`/`K###` id inventory the reply must cite (ids resolve only to inventory files; a stray path is suffix-matched or dropped); a fully deterministic pipeline (taint-path chunks, oversize splitting, catch-all sweep, eleven surface-gated specialist lenses emitted shard-major, threat fallback) then fills coverage gaps in the eligible file inventory. Assignment to a chunk is not proof of complete analysis or vulnerability coverage. | Per chunk: an off-schema chunk is dropped and the rest kept. Empty manifest + rationale only when no usable `chunks` list exists, whether the *call* failed or the *response* was malformed | none |
| **appsec-stage-s4** deepdive | N sequential LLM calls per chunk, majority-voted within the chunk then collapsed across chunks. `config.parallel` chunks in flight via `tokio::sync::Semaphore`/`JoinSet`, dispatched in risk-rank order; a shard's specialist lenses share a cached prompt prefix and wait (without a permit) for the shard's first lens to return (`appsec-stage-s4::shard_gate`). Each parsed finding passes through `appsec-stage-s4::reanchor` before the vote (see "Temporal anchoring" below). | Per-chunk outcomes carried as data on `DeepdiveOutput.outcomes`, not a stage degrade | guardrail-abort gate |
| **appsec-stage-s5** prefilter | Deterministic gates (test/mock paths; hallucinated files, though a wrong directory on a real file is repaired when it resolves to exactly one inventory path; low confidence; missing evidence, except for point-of-occurrence findings such as hardcoded credentials and missing controls, which have no flow to cite; then the language and route-guard gates below) cut obvious false positives without a model call, then S7's trivial-dup filter, then, past `pre_verify_threshold`, S7's semantic dedup. | Inherits S7's degrade transitively | none of its own |
| **appsec-stage-s6** verify | For every S4/S5 survivor, a fresh agentic session (jailed to the repo) tries to *prove the finding wrong*, emitting TRUE/FALSE_POSITIVE + CVSS 3.1; only TRUE_POSITIVE above `min_confidence` continues. Concurrency mirrors S4. | Rejections become `DroppedFinding`, not a degrade | `max(3, parallel)` guardrail-blocked sessions with zero successes |
| **appsec-stage-s7** dedup | Deterministic same-file/vuln-class/line-tolerance pre-filter (`appsec-dedup-core`), then an optional single-shot semantic LLM pass for what's left. The survivor of any cluster is chosen by content (sink-anchored end, then most severe, then the most specific/lowest CWE), never by arrival order, so back-to-back scans keep the same identity. | Deterministic-only result if the semantic call fails | none |
| **appsec-stage-s8** chain | Final analysis stage: one LLM call over all verified findings finds multi-step exploit chains, re-ranks severity by exploitability + design controls, checks combination with known unpatched CVEs. | Unranked `FinalReport` (`.degraded`/`.degraded_reason` fields) on call/parse/hydration failure | none; it always produces a valid report |
| **S9 reporting** (orchestrator and CLI) | Deterministically renders the typed report into Markdown and SARIF; the CLI publishes those artifacts plus CSV and JSON. No model call or Markdown reparsing. | Carries forward the report's existing analysis limitations | CLI publication errors propagate |

S9 is an explicit reporting boundary without a separate stage crate. It
wraps the existing `appsec-report-md` and `appsec-sarif` formatters and the
CLI's report publication path, building SARIF (`appsec-sarif::build_sarif`)
directly from the typed `FinalReport`, without reparsing Markdown or asking
a model to translate formats.

`appsec-orchestrator::run_scan` (`crates/appsec-orchestrator/src/lib.rs`) sequences
S0-S9 in this fixed order and accepts an `Option<StopAfter>` (`S1`..`S9`)
so a caller can halt the pipeline early. `--stop-after s8` stops with the
ranked typed report, before rendered report files are produced.
`--stop-after s9` produces the scan reports and stops before S10/S11, even
if `--remediate` is also set. S9 does not require a separate model
configuration. There is no `s0` stop
point: S0 spends no tokens in `rules` mode and produces no report of its
own. `run_scan` takes
the concrete `Arc<dyn LlmClient>`/`Arc<dyn ToolExecutor>`, a `ScanInput`
(repo root/name, known CVEs, design controls, optional CMDB app id), and a
`ScanConfig` bundling every stage's typed config plus the tool-version
string stamped into SARIF. `ScanConfig` also carries the scan's
checkpointing: `checkpoint: Option<Arc<dyn CheckpointStore>>` and
`resume: bool`. Whenever a store is present each of S1-S7 writes its own
checkpoint (keys `s1`..`s7`) as it completes; `resume: true` additionally
makes each stage consult its cached checkpoint first and skip re-running
(and re-spending tokens on) a stage that already finished. Writing is
unconditional and reading is opt-in, exactly like `RemediateConfig`'s own
`resume` contract for S10's per-finding checkpoints.

## S0 static seed

`appsec-stage-s0` runs before S1 and hands it a `SeedPackage`. Everything it
does is deterministic and token-free in `rules` mode; the domain logic
lives in `appsec-callgraph`, and the stage crate is just the repo walk,
language filtering, rules-vs-LLM dispatch, and model conversion. It never
fails: every abort condition degrades to an empty `SeedPackage`.

**S0 is ON by default** (`step0.enabled: true`). It is
what feeds framework routes, auth guards and seed taint paths to every
later stage (S5's route gate and S6's guarded-route language fact both
read facts only S0 produces), so a run without it carries none of that.

**It walks exactly S1's scope.** The orchestrator overwrites the
`Step0Config::walk` field with `config.step1.walk` before running the
stage, because S1 reuses the seed's file inventory whenever one is
present: a step-0 walk that ignored `step1.exclude_dirs` would silently
widen the entire scan. There is correspondingly no `step0.exclude_dirs`
(or any other `step0` walk key) in a config file; configure exclusions
once, under `step1`.

**Per-file scan** (`appsec-callgraph::scan`). One tree-sitter parse per file
drives five walks:

| Walk | Produces | Languages |
|---|---|---|
| language plugin | imports, function defs, call sites, call edges, assign/return/call-arg facts | python, javascript, typescript, go, java, csharp, php, ruby, kotlin, rust, c-cpp (assign/return/call-arg facts: python, java, csharp only; php/ruby/kotlin/rust/c-cpp also carry no import table; see `scan/lite.rs`). `c-cpp` is one key for both C and C++: `ext_to_lang` maps `.c`/`.h`/`.cpp`/`.cc`/`.cxx`/`.hpp` onto it, and C++'s tree-sitter grammar parses both. |
| `appsec-callgraph::facts` | field writes/reads, container writes | python, java, csharp |
| `appsec-callgraph::reflection` | reflective/dynamic-dispatch call sites (`getattr`, `Class.forName`, `Type.GetMethod`, and so on) | python, java, csharp |
| `appsec-callgraph::framework` | framework markers + route facts + auth guards | Django/Flask/FastAPI (python), Spring/JAX-RS (java), ASP.NET (csharp), Express/Koa/Fastify/hapi/NestJS/Next.js file routes (javascript, typescript), net/http + gin/echo/chi/gorilla mux/fiber (go), Laravel/Symfony + `$_GET`/`$_POST` scripts (php), Rails/Sinatra (ruby), Ktor/Spring (kotlin), axum/actix-web/rocket (rust) |
| `appsec-callgraph::framework` | response dataflow (`JsonResponse`, `ResponseEntity`, `Ok`, and so on) | python, java, csharp |

Every route the framework walk recognizes carries its HTTP method, its
path concatenated with any enclosing group/controller prefix, its
handler, its file and its line, and feeds
`EntryPoint::reachable_from_unauth` from whatever guard evidence sits
over it: a decorator, annotation, attribute, route middleware, a Rails
`before_action` (minus any `skip_before_action`), a Ktor `authenticate`
block, an axum `route_layer`, or an auth extractor in a Rust handler's
signature. The guard name may be one a framework ships or one the
application coined: a demand verb over a credential noun
(`require_operator_token`, `require_admin!`) counts, since projects
name their own middleware far more often than they reuse a framework's.
Guards are joined per file, with one exception: a controller-qualified
handler id (Rails' `users#show`) joins across files, because Rails puts
the route table and the `before_action` in different files by
construction.

Two shapes get special handling, because a route table written in them
is invisible to a walk that only reads the textbook spelling. Rails binds
most of its routes with the path as a hash key (`get '/p' => 'c#a'`) rather
than a `to:` option, and axum apps build their guarded section in a
local (a router assigned to `admin` with `route_layer`, then
merged into another router with `merge(admin)`), so a `let` binding is resolved at the
`merge`/`nest` that consumes it and walked there with that site's
prefix and guards.

**Graph and evidence** (`appsec-callgraph::graph`, `appsec-callgraph::evidence`).
The scan output feeds a call graph, intra-procedural pairing, and a
bounded inter-procedural BFS (3 hops, 5 for high-risk CWEs), then a
confidence-weighted path budget. Every candidate pair is put through the
symbolic transfer closure in `appsec-callgraph::evidence`, which walks the
path function by function applying sanitizers, field writes/reads,
container writes, local aliases and return-to-local transfers to a
fixpoint, and emits a `TaintEvidencePath` naming each hop's transfer
kind and symbol.

That evidence gates `taint_paths` **softly**. A pair whose value the walk
shows reaching the sink already sanitized is recorded as evidence with
`sanitized: true` and kept out of `taint_paths`. That is a positive
finding. A pair the walk simply cannot ground is *kept*, carrying the
same bare fallback evidence (`edges: []`, unsanitized) that JavaScript,
TypeScript and Go always get, since their extractors emit no facts at
all.

Grounded evidence is a confidence signal, not an admission criterion: an
extractor gap must not erase a path the call graph proves reachable.
Consumers wanting the stronger signal filter on
`TaintEvidencePath::edges` being non-empty.

Two decoration passes finish the package: reflection facts whose target
symbol is already tainted add speculative `reflect` edges, and response
dataflow widens an evidence path's CWE set with the injection class of
the response body it writes (`html` -> CWE-79, `xml` -> CWE-611, and so on).

**What S1 does with it** (`appsec-stage-s1::pure::merge_seed_into_data`).
Entry points, framework entry points, unsafe sinks, taint paths and
taint evidence are each re-resolved against S1's ground-truth file
inventory (config dedup can drop files after S0 ran) and merged into the
`ContextPackage`. From there `ContextPackage::seed_taint_evidence` is
read by S4's `STRUCTURED TAINT EVIDENCE` prompt block, by
`appsec-repo-analysis`'s seed-path promotion, and by S5's evidence backfill;
`seed_taint_paths` additionally keeps a seeded file out of reach of
S3's `catchall_mode: reachable_only` pruning.

## S3 taint traversal and its sanitizer rule

S0's seeds and S1's call graph give S3 a set of entry points, a set of
sinks and a graph between them. `appsec_repo_analysis::add_taint_chunks` walks
it (`bfs_to_sinks`, `crates/appsec-repo-analysis/src/taint.rs`) and turns each
entry-to-sink path it keeps into a deep-dive chunk.

Its sanitizer rule is a different thing from the seed plane's symbolic
transfer closure. That one asks whether a value provably
arrives at the sink already sanitized, from tracked facts. This one asks
only whether the path crosses a function whose *bare name* (the part after
the last `::`, matched case-insensitively) is a known neutralizer. It is a
name heuristic, so what it covers is deliberately narrow.

**Universal sanitizers are decided per hop.** `escape`, `quote`,
`strip_tags`, `html_escape`, `xml_escape`, `quote_plus`, `urlencode`,
`bleach_clean`, `prepared_statement` and `parameterized` are the escaping
and parameterization primitives whose whole job is to make a string safe
whatever consumes it. They neutralize every weakness class, so a hit can
gate expansion the moment it is seen.

**Class sanitizers cannot be decided per hop.** `int`, `float`, `bool` and
`to_int` neutralize CWE-89 and CWE-90; `encode` and `html_escape`
neutralize CWE-79. A numeric coercion stops a SQL-injection payload built
from that value and does nothing for a command-injection payload built
from the same string reaching a different sink, so the decision needs the
arriving sink's CWEs, which are not known while the path is still being
walked. The path therefore carries the *set* of class-sanitizer names it
has crossed, and the decision is made at sink arrival against the union of
CWEs tagged on the sinks resolving to that node. Every class tagged at the
sink must be neutralized, not just one: a single call site can carry
several CWEs, and suppressing on the first match would discard the
unsanitized aspect. That errs toward reporting, which is the right
direction here, because S4 re-checks what is emitted and nothing re-checks
a path that was never emitted. A sink with no CWEs can only ever be
universally sanitized.

**`sanitize`, `clean` and `validate` are in neither set.** There is no
weakness class for which a function merely *named* `clean` is proof of
anything, and a repository function named `validate` anywhere on a path
would otherwise kill that path for every weakness beyond it.

**A sanitized arrival does not suppress a later clean path.** Sink
visited-tracking is kept separate from non-sink nodes. A sink first
reached by a sanitized path is not recorded as reached at all, so a
clean path can still discover it and report it. That is the
validation-bypass shape: one sink reachable both through and around a
guard.

Traversal state is `(node, universal_hit, class_hits)`, drawn from a
finite space, and every set in the walk only grows, so the frontier empties
even before `max_hops` applies. A clean arrival is reported once per sink;
a sanitized arrival is expanded past at most once per state. A clean sink
arrival is also expanded past, so a sink reachable only *through* another
sink is still found.

## Language knowledge in the prompts

Two separate prompt surfaces carry per-language knowledge, and they are
deliberately different in kind.

**S4 research lens** (`appsec-stage-s4::hints` holds the hint bodies;
`appsec-stage-s4::prompts::build_research_lens` assembles them). Every chunk's
prompt gets a "where to look first" block for up to three of its
languages, keyed on `appsec_repo_analysis::ext_to_lang` (Python's
`EXT_TO_LANG`). These are *seeds, not checklists*; the researcher is told
to reason past them, 44 keys in all.

| Key | Extensions | Emphasis |
|---|---|---|
| `c` | `.c`, `.h` | Memory safety first (UAF/double free, heap/stack overflow, format string, integer overflow feeding an allocation, `strncpy` non-termination, uninitialized reads, signed/unsigned bounds checks), then TOCTOU (`access` then `open`), `system`/`popen`/`exec*`, and path traversal. Sources: `argv`, `getenv`, `recv`/`read`, `fgets`/`scanf`, file/wire parsers. |
| `cpp` | `.cc`, `.cpp`, `.cxx`, `.hpp` | All of `c`, plus iterator/reference invalidation, dangling `c_str()`/`string_view`, `reinterpret_cast`/union punning (type confusion), `shared_ptr`/`unique_ptr` ownership, exception safety, unchecked `operator[]`. |
| `c-cpp` | *(the coarse key itself)* | Same body as `cpp`, since a mixed chunk may hold either flavor. |
| `swift` | `.swift` | Force unwraps/`try!`/`as!` on external data, URL-scheme and universal-link handlers, `WKWebView` `evaluateJavaScript` and message-handler bridges, ATS exceptions and trust-all `URLSessionDelegate`s, secrets in `UserDefaults` vs Keychain accessibility, raw `sqlite3_exec`, external `String(format:)`, `Unsafe*Pointer`, `NSCoding` without `NSSecureCoding`. |
| `scala` | `.scala`, `.sc` | Play/Akka-HTTP/http4s routes as sources, Slick/Doobie/Anorm bound interpolators vs the `#$` raw splice, Twirl `@Html`, JVM deserialization and XXE, `sys.process`/`Runtime.exec`, `Option.get` and other partial operations, real JVM-thread races around `Future`s and actor state, Play session/CSRF configuration. |

`ext_to_lang` groups the whole C family under one `c-cpp` key, which is the
right granularity for a language-mix vote but not for a research lens.
`appsec-stage-s4::hints::hint_key_for_path` splits it per file (`.c`/`.h` to
`c`, everything else to `cpp`, the same split `appsec-repo-analysis::ts_graph`
makes when it picks a tree-sitter grammar), and `build_research_lens`
applies that split when *every* C-family file in a chunk falls on one
side. A mixed chunk keeps `c-cpp`.

**S6 LANGUAGE FACTS** (`appsec-stage-s6::prompts`). A much smaller block, held
to a much higher bar: a fact belongs here only if it decides a verdict on
its own and holds without exception, so the verifier can stop at it. Each
entry states its FALSE_POSITIVE / TRUE_POSITIVE consequence explicitly.

| Fact | Decides |
|---|---|
| JS/TS event loop | A race needs an `await`/`.then`/callback/timer between check and act *and* cross-request shared state. |
| Template auto-escaping | Which constructs are escaped by default and which are raw, plus the non-HTML contexts escaping does not cover. |
| Parameterized SQL | The binding spelling per language (JDBC `?`+`setX`, `SqlParameter`/EF LINQ/`FromSqlInterpolated`, DB-API `execute(q, params)`, Go variadic arguments, PDO `prepare`, ActiveRecord hash/array, `mysql2`/`pg` placeholders, `sqlx::query!`) vs the concatenating one, and that an identifier (table/column/ORDER BY) can never be a placeholder. |
| Rust memory safety | Safe Rust cannot produce UAF/double-free/data race; FALSE_POSITIVE unless `unsafe`, `unsafe impl Send`/`Sync` or FFI is in the flow. |
| Go concurrency | Goroutines are real parallelism. The JS rule does *not* travel; a race needs shared state *and* no mutex/channel/`atomic`/`Once` ordering. |
| Java atomicity | One `synchronized`/`ReentrantLock` region, or one `ConcurrentHashMap` `compute*`/`merge`/`putIfAbsent` call, is atomic; two calls in a row are not. |
| C/C++ copy bounds | `snprintf`/`strlcpy`/`fgets` with a correct size are bounded; `strcpy`/`strcat`/`sprintf`/`gets` are not. |
| Python/Ruby GIL | The GIL never refutes a check-then-act across I/O, a DB row or a cache. |
| Framework-guarded routes | A route the framework gates HAS an authorization check on every request; "this handler lacks authorization" on it is FALSE_POSITIVE without a bypass. The reverse marker is evidence *for* a missing-auth finding. |

The first two also have a deterministic half in
`appsec-stage-s5::lang_gates`, which settles the unambiguous cases before a
verification session is paid for.

### Route guards

The last fact has a deterministic half too: `appsec-stage-s5::route_gates`,
the third pre-verify gate. It is the one place where an S0 fact decides
an S5 verdict directly. S0's framework plane records
`reachable_from_unauth` per route from the guard markers
`appsec-callgraph::framework` extracts (Laravel `->middleware('auth')`, Ktor
`authenticate { }`, Rails `before_action`, axum `route_layer`,
Spring `@PreAuthorize`, ASP.NET `[Authorize]`), and S1 merges those into
`ContextPackage.entry_points`. A guard on the ROUTE satisfies the check a
"missing authorization" finding demands, so:

- **S4** (`QUALITY_BAR` plus the `access-control` specialist hint) is told
  to open the file that registers the route before reporting one at all.
- **S5** (`route_gates`) drops such a finding when every framework entry
  point that can reach it is guarded, matching entry points to findings by
  handler name (`export_report`, `OpsConsoleController@runMaintenance`,
  `reports#index`, and Ktor's `restoreConsoleSnapshot`, since the Kotlin
  section names a route after the function its lambda delegates to), by
  route-table line (`main.rs:47`), or, where the entry point id is still
  synthesized from the path and names no handler (a Ktor lambda with a
  body of its own, or one whose delegate another route in the file shares),
  by unanimity across a route file. A finding that claims the guard
  is bypassable or mis-registered is never dropped, and one open route
  among the matches vetoes the drop.
- **S6** explicitly marks guarded framework entry points as requiring
  authentication, rather than only omitting `[UNAUTH-REACHABLE]`. Only `EntryPointKind::Framework` earns
  either marker; `reachable_from_unauth` is `#[serde(default)]`, so on any
  other kind `false` means "unknown", not "guarded".

### Temporal anchoring

S4's reply schema (`appsec-stage-s4::prompts`' `OUTPUT_SCHEMA`, spliced into
`SYSTEM` and therefore sent on every request) tells the model to anchor a
use-after-free, double-free or TOCTOU finding at the LATER unsafe use,
spanning the release site when both are visible, and the `c` research hint
repeats it in C's own terms. That instruction is enforced, not trusted:
`appsec-stage-s4::reanchor` runs on every `Finding` parsed out of a reply,
before the in-chunk vote, and for a temporal finding in a C/C++ file whose
reported `line_start` really does sit on a `free(p)`/`delete p` it parses
the enclosing function with tree-sitter, finds the first genuine later use
of that pointer, and rewrites `line_start`/`line_end` to span
release-to-use. It has to run before the vote because
`appsec-stage-s4::vote`, S7's dedup, `appsec-sarif`'s v2 fingerprint and
`appsec-github`'s review-comment placement all key on the line.

Every ambiguity declines rather than guesses, because a false re-anchor
moves a correct finding onto a wrong line: an unreadable file, a release
call taking anything but a bare identifier, two release sites covering one
line, a reassignment or an address-taken between release and next mention,
or a mention the release provably cannot reach. It never invents an anchor
for a finding reported somewhere with no release site, and it never
touches `sink_ref`, which S5's backfill owns. What it did rewrite is
recorded on `Finding::reanchored` and surfaces in `findings.json`. The
prompt rule still carries everything the pass deliberately cannot: every
non-C/C++ language, a release through a project's own wrapper such as
`g_free`, and TOCTOU, which has no release site to key on at all.

## S10 remediation flow

`appsec-orchestrator::remediate` (a separate entry point from `run_scan`, since
remediation needs a write-capable `ToolExecutor`, `SandboxTools::
new_with_write`, rather than the read-only one `run_scan` uses) drives
**appsec-stage-s10**, gated throughout by **appsec-policy-gate**:

1. `stale_refusal` checks the report isn't stale relative to the working
   tree (unless `--force`); findings are then selected by CVSS-descending
   order, capped by `--top`/`top_default` (`select_top_by_cvss`).
2. Each selected finding is processed sequentially, never concurrently
   (concurrent agents editing one working tree would race on file
   contents/git state/diff capture). **Pre-gate**: `appsec-policy-gate`'s
   `RemediationGate` evaluates the finding's CWE/file against a
   deny-list-wins policy; a `deny` short-circuits before any model call is
   spent, recording a `denied` verdict (`policy_action: "guidance_only"`).
3. If allowed, **appsec-diffcapture** snapshots the target file (plus, under
   enforcement, every worktree file matching a forbidden/sensitive glob)
   via `snapshot_files` *before* the agentic loop runs.
4. The agentic edit loop (`appsec-llm-agentic::run_agentic`, `Edit`/`Write`
   enabled via `appsec-sandbox-tools`) produces a `RemediationVerdict`
   (fixed/partially-fixed/not-fixed/needs-review + per-file changes),
   parsed via `appsec-json-repair`.
5. **Post-gate**: changed files are diffed (`capture_git_diff`, falling
   back to `synth_unified_diff`), scanned by `inspect_diff`, and checked
   against the deny/forbid-path lists (`gate.forbidden_files`). Any file
   touching a forbidden/sensitive path is individually rolled back via
   `appsec_diffcapture::revert` (from the pre-edit snapshot), dropped from the
   verdict, noted in `remaining_risks`, and a `Fixed`/`PartiallyFixed`
   verdict is downgraded to `NeedsReview`.
6. `appsec_policy_gate::cap_verdict` caps the final verdict by the policy
   decision's action and whether the verdict's own gates all passed.
7. `--resume`: `remediate_one_checkpointed` consults an optional
   `appsec-checkpoint::CheckpointStore`, skipping a finding only when a stored
   checkpoint's finding-identity hash matches the *current* finding at that
   position (a stale/reordered checkpoint can never skip the wrong one).

Every path referenced by an LLM-controlled `verdict.changes[].file` is
confined through `appsec_pathjail::confine` before touching disk: a direct
CWE-22 defense, including against a Windows UNC-path NTLM-hash-leak
scenario.

## S11 validation flow

Chained inside `remediate` itself, not a separate CLI command:
`appsec-orchestrator` calls `appsec_stage_s11::validate_finding` for each
`RemediationRecord` with a non-`None` `diff`. The batch (`--top`) path
remediates every selected finding first and validates them in a second
pass; the `-i` picker validates each pick immediately. Either way it
drives **appsec-stage-s11**:

- A **2-or-3 persona LLM panel**: `security-architect` and
  `penetration-tester` always on, plus an opt-in `cross-repo-analyzer`.
  Each independently reviews the fix (through
  `appsec-llm-agentic::run_agentic` with a **read-only** `ToolExecutor`:
  `Read`/`Grep`/`Glob` plus the five deterministic fact tools
  `DiffTouched`/`ChangedLines`/`DiffImpactMap`/`PatternScan`/
  `TestInventory`, on by default via `step_validate.fact_tools`, never the
  write-capable executor S10 uses, so validation is structurally
  incapable of mutating source) and scores it against the same 4 gates.
- There is no multi-repo signal to trigger the `cross-repo-analyzer` on
  (`appsec-scan --repo <path>` is always exactly one repo), so it is an
  explicit operator opt-in, `step_validate.cross_repo_analyzer: true`,
  which runs it on **every** finding.
- The personas' independent gate opinions are synthesized per gate by
  `synthesize_n`/`synthesize_one_gate`: a `skip` is an abstention and is
  excluded from the vote, two or more agreeing non-skip votes win
  outright, and a tie or a lone vote resolves to the most conservative
  non-skip status. One persona listing the same gate twice is folded to
  its own most conservative vote first, so it still votes once. Each
  merged gate also carries a `SynthesisConfidence`: `High` when 2 or more
  personas agreed, `Flagged` for a contradiction, a lone vote, or a gate
  the whole panel skipped.
- A single `Flagged` gate makes the whole fix `Unverifiable`, before any
  arithmetic runs. The gate's own status and evidence are still reported;
  what is withheld is the aggregate verdict, because a status only one
  persona voted for is not a panel result. The ordering is fail-closed
  (shape check, then consensus, then critical gates): a fix is graded
  conclusively only when at least two personas evaluated every gate and
  agreed.
- The synthesized gate set is handed to **appsec-validation-scoring**'s
  `score_fix`, which grades it against 4 weighted gates: `RootCause`,
  `InstanceCoverage`, `NoNewVulnerabilities`, and `SecurityBestPractices`.
  `RootCause` and `NoNewVulnerabilities` are critical: either one
  unevaluated is `Unverifiable` outright, which no aggregate weight can
  outvote. From those it derives a
  Fixed/PartiallyFixed/NotFixed/Unverifiable verdict. `appsec-validation-scoring`
  itself is pure logic with no I/O; `appsec-stage-s11` is the only crate that
  calls it.
- No on-disk DTO staging or ephemeral repo copy: validation runs
  in-process against the real, already-fixed working tree immediately after
  S10 applies its fix.

## Cross-cutting concerns

- **Config loading** (`appsec-config`): YAML parse (via the project's own
  `appsec-yaml`, chosen because the `serde_yaml` ecosystem is unmaintained;
  see `docs/supply-chain.md`), built-in step-defaults merge,
  `config.local.yaml` deep-merge overlay, and `${VAR}` env expansion.
  Environment lookups are threaded through as a `&dyn Fn(&str) ->
  Option<String>` parameter rather than calling `std::env::var` directly.
  Also owns the
  `is_network_path`/in-target-config trust-gate checks (via `appsec-pathjail`)
  and `apply_step1_overlay`, an append-merge step1 overlay reserved for a
  future `--step1-config` flag (no such flag exists today; the shipped
  overlay path is `--auto-step1`/`step1.auto_exclude`, applied in
  `appsec-cli::autoexclude`).
  Deliberately does not log anything itself; it reports what happened via
  `LoadedConfig` so a higher-tier caller decides how to surface it.
- **Untrusted XML** (`appsec-xml`): SOAP/WSDL, XSD and OData CSDL files in a
  target repository, and Checkmarx `--checkmarx-xml` reports, are read
  with the project's own XML 1.0 reader rather than a third-party engine,
  for the same supply-chain reasons as `appsec-yaml`. It fails closed: any
  DOCTYPE is refused (so no external entities and no entity expansion),
  only the five predefined entities exist, and input size, nesting depth,
  attributes per element, node count and namespace bindings are all
  bounded by a caller-supplied `Limits`.
  Parsed elements and attributes keep their byte spans, so a repair is
  applied as a minimal text edit instead of a re-serialized file.
- **Redaction** (`appsec-redact`): applied **once**, on the assembled
  `FinalReport` in `appsec-orchestrator` (`redact_tree`, a JSON round-trip
  in S9, or for the typed S8 early-stop result), so downstream scan formats (Markdown, SARIF, CSV,
  `findings.json`, `remediation.json`) inherits it without needing its
  own pass; plus at the tool-output boundary in `appsec-sandbox-tools`, and
  again on the post-remediation augmented Markdown. Neither
  `appsec-report-md` nor `appsec-sarif` depends on `appsec-redact` at all, by design.
  These checks reduce exposure of recognized card data, PII and credential
  patterns in reports and tool output. They do not prove that every secret
  has been removed from arbitrary source or model responses. Card
  numbers are Luhn+IIN gated, SSNs are area/group/serial gated, generic
  secrets are keyword-gated, all tuned for precision over recall. Pure and
  stateless (string-in/string-out, no shared mutable counter state), so
  it's safe to call concurrently from parallel S4 chunks or S6 sessions.
- **Path jailing** (`appsec-pathjail`): every path originating from an LLM, a
  config file, or any other untrusted source is confined to a known root
  via `confine`/`is_within` before it is read, globbed, or used to build a
  `git` pathspec (CWE-22). Also rejects UNC/network paths
  (`is_network_path`) *before* any filesystem access, since merely
  touching a `\\host\share\file` path on Windows triggers an SMB handshake
  leaking the caller's NTLMv2 hash. The check is evaluated identically
  regardless of host OS. Consumed directly by 15 crates across every tier:
  the config/I/O boundaries (`appsec-config`, `appsec-diffcapture`, `appsec-sandbox-tools`,
  `appsec-gateway-http`), the stages (S2-S5, S10), and the orchestrator and
  report layer (`appsec-orchestrator`, `appsec-sarif`, `appsec-enrich`,
  `appsec-policy-gate`, `appsec-compliance`, `appsec-thirdparty`).
- **Token/usage tracking**: `appsec-orchestrator` wraps the caller's
  `Arc<dyn LlmClient>` in an internal `UsageTrackingClient`
  (`crates/appsec-orchestrator/src/lib.rs`), once, at the top of `run_scan`, so
  every stage's `chat()` calls are metered through one interception
  point. Usage is
  snapshotted and reset (`.take()`) between stages to attribute spend to
  the phase that produced it, populating `ScanMetrics.tokens_by_phase`.
  The headline `prompt_tokens` is **billable input** (fresh plus
  cache-write), and cache-reads are reported in their own per-phase
  `cache_read` bucket rather than folded in.
  All four fields report `None` ("unavailable") rather than a misleading
  `0` when no backend ever reported usage. `errors_by_stage` **is**
  populated (one entry per stage that degraded to a fallback, plus S4's
  `chunks_failed` count when nonzero) and renders as
  `- Recoverable errors logged by stage:`; only `errors_log_path`, a
  file-backed JSONL error log, has no implementation and stays empty.
- **Token pricing** (`appsec-pricing`): turns `(provider, model, one call's
  token counts)` into an exact dollar figure, and does nothing else. It
  is pure: no I/O, no network, no file read at run time, and no
  intra-workspace dependency. Costs are exact integers rather than
  floats, and a lookup is keyed on provider *and* model, never falling
  back to another provider's price for the same model id. Prices come
  from `crates/appsec-pricing/data/models-dev-prices.json`, a trimmed capture
  of [models.dev](https://models.dev)'s public catalog (MIT licensed
  open data) pulled into the binary with `include_str!`. It is committed
  rather than fetched, so a price change arrives as a reviewable diff;
  `crates/appsec-pricing/scripts/refresh_prices.py` regenerates it. An
  operator on negotiated gateway rates can layer a second table over the
  vendored one.
- **LLM transport** (`appsec-llm-client` + `appsec-llm-anthropic`/`appsec-llm-openai`):
  one dialect-agnostic `LlmClient` trait, implemented once per wire dialect
  (Anthropic Messages API; OpenAI Chat Completions or the Responses API),
  either able to point at a direct provider endpoint or an
  OpenAI/Anthropic-compatible AI gateway (Bifrost, Portkey, etc). The
  agentic multi-turn tool-use loop (`appsec-llm-agentic::run_agentic`) is
  written once against this trait so it runs identically regardless of
  dialect. Provider-specific reasoning state (OpenAI reasoning items,
  Anthropic thinking blocks) rides through that loop as opaque content
  blocks each dialect replays verbatim. `appsec_llm_client::capabilities`
  decides per model which parameters are sent, a per-model quirk memory
  learns what the table gets wrong, and `appsec_llm_client::CachePolicy`
  governs prompt caching on both providers. See
  [`llm-transport.md`](llm-transport.md).
- **Sandboxed tool execution** (`appsec-sandbox-tools`): `Read`/`Glob`/`Grep`
  are available to read-only sessions; `Edit`/`Write` require
  `SandboxTools::new_with_write`, used by S10 and the controlled application
  of reviewed target tests. Generation and review model sessions remain
  read-only. Dispatch enforces each session's advertised tool set. Writes
  reject Git control paths and capture their canonical baseline before
  mutation; unreadable baselines refuse the write. `Bash` is never offered either way, since a
  host shell would defeat the path jail on untrusted scan targets.
- **CVSS/CWE** (`appsec-cvss`, `appsec-cwe`): shared, dependency-free scoring and
  naming. `appsec-cvss` is consumed by `appsec-stage-s6` (verify-time CVSS) and
  `appsec-enrich` (environmental/VSVS scoring); `appsec-cwe` additionally by
  `appsec-report-md`, `appsec-sarif` and `appsec-csv`. That is one source of truth, so
  Markdown, SARIF and CSV never disagree on a CWE name or a score.

## Compiled policies

Security-framework policies are embedded by `appsec-compliance/src/presets.rs`
from `crates/appsec-compliance/presets/*.yaml`. The CLI resolves named
`--scan-framework` selections (`--compliance-preset` is an alias) before scanning; it does not load runtime
compliance-policy files. Orchestration passes their guidance through the
context package and applies their requirement crosswalks before S8. S9
renders the resulting report. These mappings do not constitute framework
certification or an additional static-analysis engine.

Target-testing profiles use embedded content selected with
`--target-tests [LEVEL]` (alias `--testing-level`) during full-scan isolated
remediation. `discover`, `unit`, `integration` and `comprehensive` select the
requested scope; a bare flag, `e2e` and `generate` select comprehensive scope.
These levels do not authorize execution. The opt-in `discovered-offline`
profile resolves discovered commands against build-owned ecosystem images
and exact argv allowlists, and pairs each ecosystem with a build-owned,
lockfile-respecting install command. Custom images or commands require a
rebuild.

`appsec-target-tests` performs bounded static discovery. The CLI's
`target_testing` module prepares baseline evidence, invokes read-only
generation and review sessions, applies accepted tests, protects bound test
bytes through S10, and records validation status. Its `api_spec` submodule
creates, repairs or relocates the target's API specification through the
same generation and review discipline, with the deterministic rules in
`appsec-api-spec`. `target_executor` runs
only approved commands in restricted Linux containers, with a network in
the provisioning phase alone and a state that keeps an unprepared
environment distinguishable from a failing test. This remains
separate from S11's model assessment and from the harness's own Rust tests.

The CLI's `delivery` module chooses default combined-patch export, explicit
branch publication (`delivery_branch`), or a Git-independent source snapshot
and ZIP (`delivery_archive`). Full-scan branch and ZIP delivery include all
accepted source and test changes. They enforce the relevant completion and
validation gates and record delivery receipts; CI artifact upload remains
the caller's responsibility. Default patch export preserves the worktree on
export failure so accepted changes can be recovered.

See [built-in policies](built-in-policies.md), [target testing](target-testing.md)
and [remediation delivery](remediation-delivery.md).
