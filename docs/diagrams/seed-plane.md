# The seed plane: step 0

S0 is the deterministic half of the scanner. It reads the repository with
tree-sitter, matches a bundled source/sink corpus, builds a call graph, walks
taint through it, and discovers framework routes and their auth guards. No
model is involved in any of that. The one optional LLM call in S0 chooses
*which* source/sink specs to match; the walk itself is LLM-free.

Turn it on or off with `step0.enabled`, which is on by default. Mode is
`step0.callgraph_detection`: `rules` (zero tokens) or `llm`.

It is worth what it costs. On the OWASP Juice Shop backend, seed plane off
versus on, same commit family: **1313 s down to 428 s**, **6.40M down to
4.56M tokens**, verification precision **69.8% up to 76.6%**, the cap
tripped before S7 in the first run and not in the second, and both hit the
same 14 of 15 canonical challenge files. It is not a detection aid so much
as a *targeting* aid: it spends static analysis to avoid spending model
calls.

## Inside S0

```mermaid
flowchart TD
    W["walk the repo<br/>using STEP 1's exclude config, not its own"]
    DL["detect languages"]
    EX["tree-sitter extractors<br/>11 language keys: python, javascript, typescript, go,<br/>java, csharp, php, ruby, kotlin, rust, c-cpp"]
    F["facts, in memory per file<br/>functions and params, calls, assigns, returns, call args,<br/>field reads and writes, container writes, reflection"]
    CORP["source and sink corpus<br/>21 source rules, 87 sink rules, embedded in the binary.<br/>Operator YAML or an LLM spec-detection pass can replace it"]
    MATCH["match calls against specs<br/>4 call shapes: qualified, module attr, bare call, receiver method<br/>plus argument predicates, ANDed: requires_dynamic_arg, requires_any_arg,<br/>requires_arithmetic_arg, requires_unit_arg"]
    SYN["synthetic source planes<br/>framework parameter bindings and Rust extractors<br/>become sources even with no rule match"]
    CG["call graph<br/>per-file module scope caller, receiver and import hints,<br/>capped fan-out per call site"]
    TW["taint walk<br/>intra-procedural, then BFS: 3 hops, 5 for high-risk classes.<br/>Kind-compatibility gate on source-to-sink pairs"]
    EV["symbolic transfer, to a fixpoint, SANITIZERS FIRST<br/>edges: source, assign, arg_to_param, return_to_local,<br/>field, container, sanitize, reflect, local_to_sink"]
    BUD["path budget<br/>score by hops, CWE severity and confidence.<br/>5 per source; a protected sink family is never dropped"]
    FW["framework routes and guards<br/>routes per framework; a guard is a decorator, annotation,<br/>attribute, middleware, before_action, authenticate block<br/>or an auth extractor in the handler signature"]
    OUT["SeedPackage<br/>entry_points, framework_entry_points with reachable_from_unauth,<br/>unsafe_sinks, taint_paths, taint_evidence,<br/>call_graph, def_spans, all_files"]

    W --> DL
    DL --> EX
    EX --> F
    CORP --> MATCH
    F --> MATCH
    F --> SYN
    MATCH --> CG
    SYN --> CG
    CG --> TW
    TW --> EV
    EV --> BUD
    F --> FW
    BUD --> OUT
    FW --> OUT
```

### The parts that are easy to get wrong

**"Correct scope" is a real bug that was fixed.** S0 has no exclusion config
of its own. The orchestrator overwrites its walk config with step 1's at
scan time. It has to, because S1 *reuses the seed's file inventory* when one
is present. A step-0 walk that ignored `step1.exclude_dirs` therefore
silently widened the entire scan: one Juice Shop run went from 199 files to
744 that way and spent its whole budget before verification. Configure
exclusions once, under `step1`.

**The soft gate.** A call-graph-reachable, kind-compatible source/sink pair
is emitted as a taint path *unless* the walk positively proves it reaches the
sink sanitized. An *ungrounded* walk keeps its path with fallback evidence.
This inverts the Python original's hard `if evidence is None: continue`,
which had the perverse effect of giving the best-understood languages the
fewest seed paths.

**Two extractor tiers.** Python, JavaScript, TypeScript, Go, Java and C#
get full extractors with assignment, return and call-argument facts, so
they have an interprocedural taint plane. PHP, Ruby, Kotlin, Rust and C/C++
use "lite" extractors: function definitions, call edges, params, indexed
request reads, and per-argument shapes. That last part is not a lesser
answer: all five judge which arguments are static string literals (for
`requires_dynamic_arg`), and C/C++ additionally judges which are
arithmetic and which are the literal `1`, which is what the allocation
rules need. Those shapes are read straight off the argument node kinds, so
a rule carrying a predicate is as precise here as under the full visitor.
What a lite extractor does not have is assignment, return and
call-argument facts, so no interprocedural taint evidence. That difference
is visible in the polyglot results.

**`entry_points` and `framework_entry_points` are separate fields on
purpose.** Plain entry points are *source call sites*, and they always carry
`reachable_from_unauth: false`, because a source call site says nothing
about how a request reaches it. Only the framework plane computes that flag
from evidence. Keeping them apart lets S1 merge once; the Python original
appends the framework set twice and double-counts every route.

**Absence of a guard is what makes a route unauthenticated.** Nothing is
emitted when nothing is known. A method-level opt-out beats a method-level
guard, and any method-level verdict beats the enclosing class's.

## How the rest of the pipeline consumes it

`SeedPackage` crosses exactly one crate boundary, orchestrator to S1.
Every later stage reads the seed *through* the `ContextPackage` that S1
writes.

```mermaid
flowchart TD
    S0["S0 SeedPackage"]
    S1["S1<br/>reuses the seed's file inventory instead of walking again.<br/>Merges framework entry points FIRST so guard truth wins the dedup.<br/>Demotes a survey-model 'framework' entry point once real routes exist.<br/>Adopts the call graph and def spans outright"]
    GF["step1.mode gap_fill<br/>a strong enough seed SKIPS S1's agentic exploration entirely"]
    CTX["ContextPackage<br/>entry_points, unsafe_sinks, seed_taint_paths,<br/>seed_taint_evidence, call_graph, def_spans"]
    S3["S3<br/>seed hops seed the AST frontier and survive the trim.<br/>Seed paths become S4 WORK ITEMS with first claim on the chunk budget.<br/>Any file on a seed hop is always considered reachable"]
    S4["S4<br/>a chunk with path_funcs switches to the confirm/refute taint prompt.<br/>Structured taint evidence block: origin symbol, edge histogram,<br/>sink-consuming symbol.<br/>def_spans give the function slices to load"]
    S5["S5<br/>the ROUTE GATE indexes framework entry points.<br/>Backfill indexes seed paths by file"]
    S6["S6<br/>renders GUARDED or UNAUTH-REACHABLE markers per entry point.<br/>Call-graph context, with a warning not to refute on a missing edge"]

    S0 --> S1
    S0 --> GF
    GF --> S1
    S1 --> CTX
    CTX --> S3
    CTX --> S4
    CTX --> S5
    CTX --> S6
```

With the seed plane **off**, `seed_taint_paths` and `seed_taint_evidence`
are empty, so S3's taint promotion, S4's structured evidence block, S5's
route gate and S6's guard markers all go dark at once, and the entry-point
and sink lists come only from what the survey model happened to say. That is
the configuration the 1313-second Juice Shop run was in.
