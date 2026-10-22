# Coverage-gate exceptions

`.github/workflows/ci.yml`'s `test` job runs `cargo llvm-cov` once for the
whole workspace at a strict `--fail-under-lines 100 --fail-under-functions
100`, excluding the crates documented below. Each excluded crate then gets
its own `cargo llvm-cov -p <crate>` step at a specific, narrower threshold.

Every exception here is one of two things:

- a `cargo-llvm-cov` reporting artifact: the code executes, and the tool's
  own summary miscounts it; or
- an unreachable defensive branch, kept as real code rather than deleted
  just because today's inputs cannot reach it. These guard against a
  future dependency-version change, and a guard that panics or silently
  mis-attributes is worse than one that returns nothing.

None of them are "give up and raise the ceiling". Every threshold leaves
headroom below the real figure, so a genuine regression still trips the
gate.

A shortfall in an excluded crate is not automatically one of these two
categories. Verify before accepting one: confirm through a standalone test
run whether the code path actually executes.

## `appsec-interactive/src/blocking_io.rs` (file-level exclusion, not a crate)

The only *file-level* coverage exclusion in this workspace
(`--ignore-filename-regex 'appsec-interactive/src/blocking_io\.rs'`, applied
on both the workspace-wide and the `appsec-cli` `cargo llvm-cov` steps), and
a deliberate, documented one (see that file's own module doc comment): its
two blocking real-terminal-I/O calls (`crossterm::event::read()`,
`stdin().read_line()`) cannot be safely exercised by an automated test
without a live TTY. Doing so risks hanging the whole suite, not just
flaking one test, if the test process's stdin is not already at EOF.

`Terminal`'s other methods (`is_tty`/`draw`/`write_line`, in `terminal.rs`)
and every actual decision this crate makes (key mapping, cursor movement,
selection parsing) live elsewhere and stay fully covered against a scripted
fake.

## `appsec-cli`

Gate: `--fail-under-lines 99.37 --fail-under-functions 99.5`.

`appsec-cli` is the only crate in this workspace with a `[lib]` *and* a
`[[bin]]` *and* its own `tests/*.rs`, which produces five separately
compiled instances of its library code: the `--lib` unit-test binary, the
`tests/cli.rs` integration binary linking it as a normal dependency, the
real `appsec-scan` executable, and two harness-mode duplicates of the
`[[bin]]` target. `cargo llvm-cov`'s summary reports lines short of 100%
that every other diagnostic (`--show-instantiations`, the HTML report, the
JSON region export merged across all compiled instances, and `llvm-cov
show` invoked directly against the relevant objects) agrees have executed.
This is a known category of `cargo-llvm-cov` summary/instantiation-merge
disagreement for heavily monomorphized multi-binary crates, not an
untested code path. This crate is the only one in the workspace where it
surfaces, matching its unique compile shape.

`run_command` and `clone::run_bounded_clone` take the program name and the
deadline as parameters, which makes the spawn-failure arm reachable with a
program name that does not exist and the timeout arm reachable with
`Duration::ZERO`. As a side effect, this crate's coverage does not depend
on whether the machine running it has Docker installed: exit-status
classification is driven through the same seam by tiny scripts that exit 0,
1, 125 and 127.

What is excepted:

**A. Container process arms no test can drive.** `run_command` branches
four ways after spawning the Docker CLI. Three are tested: an unavailable
digest-pinned image through `execute`, a client that cannot be started, and
a run that outlives its deadline. The fourth, `child.wait()` itself
returning an error (`target_executor.rs` 558-568), cannot be induced from a
test at all. Lines 682 and 690 are the Windows halves of
`docker_program`/`safe_host_path`, compiled but not taken on a Unix runner,
and 724 is `ContainerCleanup`'s drop outside a Tokio runtime, which the
summary keeps reporting as missed even though two tests execute it.

**B. Uncovered functions.** `batch.rs` 500 and `clone.rs` 211 are the
instantiation artifact described above. `builtin_profiles.rs` 54 is the
embedded profile JSON failing to parse; it is `include_str!`-ed at build
time and every entry is parsed by
`all_compiled_profiles_have_unique_names_and_valid_policies`, and its
message interpolates the profile name, so it cannot share a closure
without changing what it says. `delivery_archive.rs` 309 is the archive
re-reading more than 256 MiB after the inventory measured less, i.e. the
source growing mid-run. `lib.rs` 1867 is
`serde_json::to_string(&report.findings)` failing, which `serde_json` has
no failing case for on that shape.

**C. Arms no input can reach.** `builtin_profiles.rs` 56 validates a
profile's `execution` policy, and no shipped profile authorizes execution;
`target_testing.rs` 318 rejects a test path that escaped the root, which
`safe_relative` has already made impossible; `target_testing.rs` 580 needs
a rollback whose `remove_file` fails for a reason other than the file being
absent; `delivery.rs` 129 is the no-parent branch of a path that always has
one; `delivery_branch.rs` 264, 277, 288, 414, 460 and 485 are `text()`
rejecting non-UTF-8 output from `git rev-parse`, `git remote get-url`,
`git hash-object` and `git write-tree`, none of which can emit it; 384 is
unreachable because the component walk immediately above it already returns
for the same error; 395 needs a changed file to grow between its `metadata`
call and its `read`; 176-178 is the 120-second Git timeout.

**D. Platform-conditional lines.** `delivery_archive.rs` 138-140 and its
test at 457 are the case-insensitive filename collision check, which cannot
be provoked on a case-insensitive filesystem (macOS APFS) and is covered on
Linux; 346 is the write-error propagation of a `u16` header field. The
remaining `lib.rs`, `environment.rs`, `autoexclude.rs`, `worktree.rs`,
`batch.rs`, `clone.rs` and `estimate.rs` lines are the artifact and
defensive-branch categories already described.

`llvm-cov show`, merged across all compiled instances, finds substantially
fewer zero-count lines in this crate than the summary reports. The
difference is the same instantiation-merge disagreement, and it grows with
the crate: the newer modules add production code that only the `--lib` test
binary executes, and the summary counts a good deal of it as missed anyway.
The threshold is set against the summary, because that is what the gate
reads.

## `appsec-checkpoint`

Gate: `--fail-under-lines 99.5 --fail-under-functions 100`.

A different artifact from `appsec-cli`'s: this crate has only a `[lib]`, so
none of that multi-binary shape. `cargo llvm-cov`'s summary reports one
line short of 100% in `crates/appsec-checkpoint/src/sqlite_store.rs`, but
`llvm-cov show` invoked directly against the exact same single compiled
test binary and profdata (bypassing the `cargo-llvm-cov` wrapper entirely)
finds zero lines with a zero execution count, and the HTML and text detail
views built from that same data agree. `llvm-cov report`'s aggregate
disagreeing with `llvm-cov show`'s line-by-line render of the same
instrumentation data is an internal tool inconsistency, not an untested
code path.

## `appsec-callgraph`

Gate: `--fail-under-lines 98.5 --fail-under-functions 98.5`.

Not a report-versus-show tool disagreement: `llvm-cov show` on the same
profdata agrees with the summary here, so these are real zero-execution
lines. They are defensive fallbacks in the S0 tree-sitter scanner
(`src/scan.rs`) that are unreachable via any real parse tree the pinned
grammar versions produce, plus a recurring LLVM region/instantiation
counting artifact.

Grammar-guaranteed unreachable field guards:

- `py_leftmost_identifier`'s two "malformed node" guards (missing
  `object`/`function` field, or a childless token hit while walking a
  wrapper node's first child). `js_leftmost_identifier`'s and
  `go_leftmost_identifier`'s equivalent guards
  (`member_expression`/`selector_expression` and `call_expression` each
  requiring their `object`/`operand`/`function` field) are the same
  category: every real node of each kind the grammar produces, including
  nested-call and parenthesized-expression cases that do reach each
  function's success path and its wildcard arm, had the expected field
  populated.
- `import_from_statement`'s "module name is empty" branches (Python):
  `module_name` is always non-empty whenever this node kind appears at all.
  The JS/TS equivalents are a `named_imports` specifier missing its `name`
  field, a CommonJS `require(...)` call missing its `arguments` field, and
  a `class_declaration` missing its `name` field. An anonymous
  `export default class {}` parses to a bare `class` node, never
  `class_declaration`, so a nameless `class_declaration` cannot occur, and
  every `call_expression` the grammar produces, `require()` included,
  always carries an `arguments` node even when empty.
- Go's `go_import_spec` missing a `path` field: no construction, including
  an empty `import ()` block, produces an `import_spec` node without one.
- Java: a `local_variable_declaration`/`variable_declarator` missing its
  `type`/`name` field, and an `assignment_expression` missing either
  operand. A deliberately malformed `x =;` parses to an `ERROR` node rather
  than a real `assignment_expression`, so that branch cannot be reached
  that way either.
- C#: `cs_leftmost_identifier`'s two "missing field, empty child"
  fallbacks (a `member_access_expression` always carries an `expression`
  field; an `invocation_expression`/`element_access_expression` always has
  at least one child to fall back to), `cs_assignment_parts`'s
  missing-`left`-or-`right`-operand guard (both fields are
  grammar-mandatory for
  `assignment_expression`/`simple_assignment_expression`), and
  `cs_visit_variable_declarator`'s `name_node.kind() != "identifier"`
  guard. The one real case where a declarator's name is not a plain
  identifier, tuple deconstruction with `var (a, b) = ...`, produces no
  `name` field at all and is caught by the earlier `Some(name_node)` check,
  so this narrower guard never fires.
- The PHP/Ruby/Kotlin/Rust entry-point plane
  (`src/framework/{php,ruby,kotlin,rust}.rs`, `src/scan/lite.rs`): a
  `function_definition`/`method_declaration`/`function_declaration`/`function_item`
  missing its `parameters` node, a `call_expression` missing its `function`
  field or carrying no named child at all, a `navigation_expression` with
  fewer than two named children, and `leftmost`'s dead-end arm for a
  receiver expression that bottoms out on a node with neither a named child
  nor any of the fields it follows.
- The fact-extraction modules (`src/facts.rs`, `src/framework.rs`,
  `src/reflection.rs`): each walks the tree looking for a specific node
  shape, and the guards that would fire when a matched node is missing a
  structurally mandatory field never do. Where a guard was cheap to
  eliminate outright it was: `framework.rs`'s per-language
  `*_method`/`*_parameter`/`py_decorated` helpers return `Option<()>`, so
  those lookups are `?` expressions on an executed line rather than dead
  early-return arms.

These are kept rather than asserted away, because they are verified
empirically against the grammar versions pinned today, not proven. A future
tree-sitter bump could start producing a shape that reaches them.

Phantom zero-counts on closing braces: a handful of closing braces
immediately following an unconditional `return` or an empty `_ => {}` match
arm, with nothing else in that scope, show a permanent 0-count in
`py_visit`'s "assignment" arm, `js_visit`/`go_visit`'s call-expression
handling, `match_call`'s module_attr resolved-path branch, `java_visit`'s
`class_declaration`/`object_creation_expression` handling, and
`cs_invocation_parts`'s `_ => {}` arm, `cs_call_target`'s assignment-operand
check and `cs_visit`'s `class_declaration` handling. In every case the
statement immediately before the brace is independently confirmed executing
via `llvm-cov show`. Two C# instances of this shape
(`cs_visit_variable_declarator`'s "no `value` field" fallback and the
`object_creation_expression` arm's class-name computation) were fixed
outright instead of accepted, by flattening the nested `if`/`if-let` into a
single `.or_else(...)`/`.and_then(...)` combinator chain. `src/graph.rs`
(the call-graph/BFS/path-budget engine) reached genuine 100%/100% the same
way for every instance of this pattern it had. It was not attempted for the
remaining `scan.rs` instances, because their tree-walk visitors are a much
worse fit for that restructuring: deeply nested per-node-kind matches, not a
single linear scan. `src/annotator.rs` (LLM-free candidate collection,
prompt building, heuristic classification) adds two more accepted lines
matching these same categories.

Duplicate-instantiation regions: a `cargo-llvm-cov` "missed function" flag
on exactly one closing-brace *region* (not the function body) of each of
`py_leftmost_identifier`/`js_leftmost_identifier`/`go_leftmost_identifier`,
confirmed via a direct JSON coverage export to be a duplicate-instantiation
region, where one of several compiled instances of the same function shows
0 while another shows real hits. Each has direct, passing success-path
tests.

Grammar divergences from the Python original's assumptions: tree-sitter-c-sharp
0.23.5, the pinned version, diverges from what Python's `_cs_extract` assumes
in three ways, verified against the exact grammar and replicated faithfully
rather than "fixed" to read the tree differently, which would diverge from
what the Python original itself produces against this same grammar.
`argument` nodes (children of `argument_list`) never populate an
`"expression"` field, so `cs_identifier_args`'s "argument" branch can never
capture anything, and its "any other kind" wildcard arm is dead too, since
every `argument_list` child is always `argument`-wrapped. An
`equals_value_clause` node never appears in this grammar's parse tree at
all, so `cs_call_target`'s block for it is dead. And `variable_declarator`
never exposes a `"value"` field, only `"name"`, so `cs_call_target`'s
`variable_declarator`-with-`"value"`-field check is dead too; see the
`.or_else(...)` workaround in `cs_visit_variable_declarator`.

## `appsec-repo-analysis`

Gate: `--fail-under-lines 99.5 --fail-under-functions 100`.

`ts_graph.rs`, the Query/QueryCursor-based `step1.call_graph: tree_sitter`
backend, has a handful of defensive branches that are unreachable given the
current, committed `QUERIES` table. A live probe compiling and running all
14 languages' `defs`/`calls` queries against the exact grammar crate
versions this workspace pins confirmed every one of them succeeds, so:

- `compile_all`'s `Query::new(...)` failure arm, where a query fails to
  compile against the linked grammar, never fires for any of the 14
  entries.
- `parse_file`'s `parser.parse(text, None)` returning `None`
  (tree-sitter's own documented reasons: no language set, or an explicit
  cancellation flag or timeout, and this backend sets neither) cannot
  happen for a language that just successfully compiled a `Query`.
- Two match-arm wildcards, the `defs` query's capture-name match and the
  `calls` query's capture-name check, are unreachable because every one of
  the 14 `defs` queries declares exactly the two capture names
  `name`/`def`, and every one of the 14 `calls` queries declares exactly
  the one capture name `callee`. There is no third capture name for either
  wildcard to see.
- The `let (Some(nn), Some(dn)) = (name_node, def_node) else { continue }`
  guard in the defs-match loop is unreachable given the same fact: each
  `defs` query match pairs exactly one `@name` with one `@def`, verified
  even for multi-alternative-pattern queries such as Java's
  `method_declaration`/`constructor_declaration`, so one without the other
  never occurs for any of the 14.

Like `appsec-callgraph`'s guards, these are verified empirically against the
pinned grammar versions rather than mathematically proven, so a future
grammar-crate bump could change this. `--fail-under-functions 100` stays
exact: that metric is unaffected, because every function has at least one
covered region.

## `appsec-validation-scoring`

Gate: `--fail-under-lines 99.5 --fail-under-functions 100`.

An unreachable defensive branch, not a tool artifact. `score_fix`'s
`Err(result) => return result` arm on `renormalized_score`'s call is
provably unreachable through the public API: `shape_error` requires all 4
gate names present with no duplicates, and `critical_gate_error` already
short-circuits if either critical gate (`root_cause`,
`no_new_vulnerabilities`) is Skip or Invalid. So by the time
`renormalized_score` runs, both critical gates are always Pass, Partial or
Fail and contribute their full weight (0.43 + 0.1867 = 0.6167) to
`active_weight`, which can never be `<= 0.0`.

The guard itself *is* covered directly, by
`renormalized_score_guards_a_zero_weight_input_directly` in `src/tests.rs`,
which calls the private function on its own. Only `score_fix`'s own dead
calling arm is excepted here.

## `appsec-stage-s0`

Gate: `--fail-under-lines 99.5 --fail-under-functions 100`.

Two defensive branches in `engine.rs` that cannot be reached with a
correctly built binary:

- The `Err` arm of the bundled starter corpus load
  (`load_rules_mode_specs`, the `no source/sink rule YAML configured`
  path). Its input is `include_str!`-ed at compile time from
  `crates/appsec-stage-s0/corpus/{sources,sinks}.yaml`, and a corpus that
  did not parse would fail
  `load_rules_mode_specs_falls_back_to_the_bundled_corpus_when_unconfigured`
  and two `run_callgraph_engine` tests beside it long before this arm ran.
  Kept as real code rather than an `expect`, because the alternative to a
  warning here is a panic in a scan.
- `run_callgraph_engine`'s `used_llm_specs` branch inside the "0 files
  matched" arm. Every spec `appsec_callgraph::annotator::append_spec`
  builds is derived directly from a call site this same second scan
  re-parses, so it always matches at least that one site; see that branch's
  own code comment. This is probed empirically, not formally proven, so it
  is kept as real code rather than deleted.

Note for anyone reading a `tracing` line as uncovered: `tracing`'s macros
only evaluate their arguments when a subscriber has the callsite enabled,
and no test installs one. `run_callgraph_engine`'s two `tracing::info!`
summaries therefore format eagerly into a `String` first, which is the same
fix used for the eagerly formatted summary lines elsewhere in this
workspace.

## `appsec-stage-s1`

Gate: `--fail-under-lines 99.5 --fail-under-functions 98`.

The same report-versus-show tool inconsistency as `appsec-checkpoint`:
`cargo llvm-cov`'s summary reports 2 lines and 2 functions short of 100% in
`src/pure.rs`, the S0-seed merge and gap-fill logic, but `llvm-cov show`
against the same compiled test binary and profdata, bypassing the wrapper,
finds every one of those lines executed, `return;` early exits included.

## `appsec-thirdparty-api`

Gate: `--fail-under-lines 99.5 --fail-under-functions 99.0`.

Two independent, verified tool artifacts, not real gaps:

- `src/oauth2.rs`'s `TokenCache::get_or_refresh<F, Fut, E>` is a generic
  `async fn` monomorphized 7 times: once per its own crate-internal unit
  tests' `String`-typed closures, once for `AikidoClient::access_token`'s
  `AikidoError`-typed closure, and once for
  `CheckmarxClient::access_token`'s `CheckmarxError`-typed closure. The
  "already valid, return the cached token without re-fetching" branch
  (`if tok.is_valid() { return Ok(...); }`) executes on the vendor-crate
  instantiations too: `AikidoClient` and `CheckmarxClient` both call
  `access_token()` more than once per `fetch_findings()`, once per
  paginated page or once per scans-then-results call, and the two-call
  tests (`aikido::tests::fetch_findings_reuses_the_cached_token_across_pages`,
  `checkmarx::tests::fetch_findings_paginates_results_until_total_count_is_reached`)
  would not pass if a second real token fetch were needed. But
  `cargo-llvm-cov`'s region merge for this doubly monomorphized function,
  generic plus async state machine, attributes the runtime hit to a
  different region copy than the one its line-level summary checks, so the
  vendor-crate instantiations show 0 even though the branch runs.
- `semgrep.rs` and `snyk.rs`'s `severity_mapping` test uses `#[rstest]`
  with 6 `#[case]` attributes. Every generated `case_1`..`case_6` variant
  runs and passes, but the un-expanded template function signature itself
  is counted as one additional, never-directly-called "function" by
  `cargo-llvm-cov`'s function-count metric. That is an inherent
  `rstest`-macro-expansion artifact, not a behavioral gap.

## `appsec-diffcapture`

Gate: `--fail-under-lines 99.7 --fail-under-functions 99.0`.

Two unreachable defensive branches rather than a tool artifact (`llvm-cov
show` agrees with the summary here; these really are zero-execution
regions), both in `src/lib.rs`:

- `canonical_repo_path`'s non-`Normal` component arm
  (`Component::CurDir | ParentDir | RootDir | Prefix(_) => None`).
  `relative` is whatever is left after stripping one
  `appsec_pathjail::confine` result from another, and `confine` returns a
  fully resolved path: its `resolve_best_effort` pops every `..`, drops
  every `.`, and canonicalizes whatever exists, so the remainder of a
  `strip_prefix` between two such paths can only be `Normal` components, or
  nothing at all. The "nothing at all" case, where the candidate is the
  root, is reachable, but it is the following `!components.is_empty()`
  guard, not this arm. Kept rather than deleted: the alternative to an arm
  that returns `None` is a repo-relative identity assembled from a
  component this code never checked, which is the exact mistake the
  function exists to prevent.
- The `map_err` closure on tier 2's `git checkout` `.output()` call. That
  `Result` is `Err` only when `git` itself cannot be spawned, and this
  crate hard-codes the program name, so the only way to induce it is to
  empty `PATH` for the whole test process, which races every other test in
  the same binary. Closing it properly needs the injectable-program-name
  shape `appsec_cli::clone::run_bounded_clone` uses, which is a production
  change rather than a test.

Two guards here that look similar do have a reachable input and are covered
by real tests:

- `a_repo_file_named_like_a_unc_path_is_skipped_and_refused_by_revert`. A
  repository file whose own name begins with two backslashes, an ordinary
  file name on Unix, is the one input that reaches the "re-confining the
  canonical identity failed" guards in `snapshot_files` and `revert`. The
  absolute spelling a caller supplies is not a UNC path, so the identity
  resolves; the repo-relative identity it yields is one, and
  `appsec_pathjail::confine` refuses it before touching the filesystem.
- `a_failing_git_checkout_is_reported_instead_of_being_swallowed`. Emptying
  the object store of an otherwise valid work tree leaves `is_git_worktree`
  and `is_tracked` answering truthfully while `git checkout` cannot read
  the blob, which is what the error return exists for: a revert that
  silently did nothing used to be indistinguishable from one that worked.

## `appsec-sandbox-tools`

Gate: `--fail-under-lines 99.8 --fail-under-functions 100`.

One line, and it is the same exception as `appsec-diffcapture`'s first item
rather than a new one: `control_path.rs`'s `canonical_relative_path` has the
identical non-`Normal` component arm, for the identical reason. Both
functions strip one `appsec_pathjail::confine` result from another and map
what is left. See that section for the full argument.

The rest of `control_path.rs` is covered directly: the leading and trailing
whitespace refusal, the colon and whitespace checks on each component, the
empty-identity case, and the symlink resolution `is_git_control_path`
depends on. So is the `prepare_write` gate in `executor.rs` that consumes
it, on both the `Write` and the `Edit` path, including the two refusals a
caller actually sees, an outside-root path and a Git control path.

`--fail-under-functions 100` stays exact: every function in this crate has
at least one covered region.

## `appsec-orchestrator`

Gate: `--fail-under-lines 99.9 --fail-under-functions 99.4`.

Two `map_err` closures in `src/reporting.rs` (S9), over serialization calls
that cannot fail for the types they are handed:

- `redact_report`'s `serde_json::to_value(report)`. `FinalReport` and every
  type it contains derive `Serialize`, hold no map with a non-string key,
  and have no hand-written `Serialize` impl, so both error shapes
  `serde_json`'s `Value` serializer can produce, a key that is not a string
  and an error a custom impl raised itself, are unconstructible here. A
  non-finite `f64` is deliberately *not* one of them: `to_value` writes
  `null` for it and returns `Ok`.
- `Stage9::run`'s `serde_json::to_string_pretty` over the built
  `SarifDocument`, for the same reason about the same kind of derived
  types.

The third closure in this file is not an exception and has a real test.
`redact_report`'s return leg, `serde_json::from_value` back into a
`FinalReport`, does fail for a reachable input, and
`a_report_that_cannot_survive_the_redaction_round_trip_is_a_stage_error`
feeds it one: `ScanMetrics { duration_sec: f64::NAN, .. }`. JSON has no
spelling for a non-finite float, so the outbound `to_value` writes `null`,
and `duration_sec: f64` refuses `null` on the way back, because
`#[serde(default)]` fills in a field that is *missing*, never one that is
explicitly null. That case is worth having: the code this replaced used
`.expect("redact_tree preserves JSON shape, so FinalReport deserializes
back")` and would have panicked at the very last step of a scan that had
already done all of its work.

## `appsec-parity-tests` (excluded, no separate step)

Cross-checks this port against the real Python source and needs a Python
venv that is not set up on this runner. See
[`parity-harness.md`](parity-harness.md).
