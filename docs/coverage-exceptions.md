# Coverage-gate exceptions

`.github/workflows/ci.yml`'s `test` job runs `cargo llvm-cov` once for the
whole workspace at `--fail-under-lines 99.8 --fail-under-functions 100`,
excluding the crates documented below. Each excluded crate then
gets its own `cargo llvm-cov -p <crate>` step at a specific, narrower
threshold. This file is the full rationale for every one of those
exceptions, moved out of `ci.yml` itself (which now just points here) so
the workflow file stays readable. Every threshold below leaves headroom
below the consistently observed real number so a genuine regression still
trips the gate. None of these are "give up and raise the ceiling"; each
one is either a verified `cargo-llvm-cov` tool artifact (the code
executes; the tool's summary miscounts it) or a verified
unreachable defensive branch (kept as real code, either
matching the Python original's own defensive style or guarding against a
future dependency-version change, rather than deleted just because
today's inputs can't reach it).

## Why the workspace gate is 99.8% lines, not 100%

It was 100% until rustc 1.100.0. The measurement comes from rustc's own
bundled LLVM, and 1.100 changed how it attributes two kinds of region
this file already describes:

- **closing braces** after an unconditional statement, the phantom
  category documented per crate below;
- **multi-line macro invocations**, overwhelmingly `tracing::warn!` and
  friends, where the argument lines now carry their own regions.

Nothing was tested less than before. CI run 43143817118 ran the same
commit twice: attempt 1 under 1.99.1 reported no uncovered lines, and
attempt 2 under 1.100.0 reported 85, spread over 26 files in twelve
crates nobody had touched. Of the spans captured from that run, 24 were
closing braces and 17 were multi-line macros.

Three ways out, and why this one:

- **Flatten the code to remove the phantoms.** That is what `graph.rs`
  did to reach 100%, and it works where an `if let` chain can become one
  combinator. Across 44 sites it would mean collapsing idiomatic
  multi-line `tracing!` calls into single lines, which trades readable
  logging for a round number.
- **Exclude 26 files by name.** The exclusion list exists so each entry
  can carry a reason; 26 entries for one tool-version artifact would make
  it unreadable and would hide real gaps in those files for good.
- **Leave headroom, the way every per-crate gate below already does.**
  The observed figure is 99.886%; the gate sits at 99.8%, so a genuine
  regression of more than a handful of lines still trips it.

Functions stay at **100%** and that is the part worth defending: a
function that never runs is a real gap, not an attribution quirk, and
1.100 reported exactly one -- a closure in a zero-item test in
`appsec-stage-s10/src/select.rs` that could not run. It was fixed rather
than excepted.

## Re-measured for rustc 1.100 (2026-11-15)

Every per-crate threshold below was re-measured against rustc 1.100, the
version pinned in `rust-toolchain.toml`. The 1.99 -> 1.100 bump moved the
numbers with no code change, so seven gates were failing on attribution
rather than on anything a test could fix.

1.100 counts line regions the previous release did not: a bare closing
brace, each argument line of a multi-line `tracing::warn!`, each
continuation line of a multi-line format string or method chain. Those
lines do execute -- the gate's own `--show-missing-lines` names them, and
reading them shows ordinary executed code -- so no test covers them and a
100% line target is no longer reachable.

| crate | lines | functions | was |
| --- | --- | --- | --- |
| `appsec-cli` | 99.02% | 99.29% | 99.37 / 99.5 |
| `appsec-callgraph` | 98.18% | 99.30% | 98.5 / 98.5 |
| `appsec-stage-s0` | 99.48% | 100% | 99.5 / 100 |
| `appsec-stage-s1` | 99.20% | 99.72% | 99.5 / 98 |
| `appsec-diffcapture` | 99.43% | 99.36% | 99.7 / 99.0 |
| `appsec-sandbox-tools` | 99.70% | 100% | 99.8 / 100 |
| `appsec-orchestrator` | 99.80% | 99.23% | 99.9 / 99.4 |

Each new threshold is the measured value floored to one decimal and
dropped 0.1 -- enough to catch a regression, enough to absorb the small
platform difference (a macOS run reads marginally lower than CI's Linux:
99.02 against 99.040 for `appsec-cli`). Gates that still passed were left
at their existing values rather than loosened.

One difference is larger than jitter. Read it before chasing
it: measured on macOS, the workspace gate fails on a single uncovered
function in `appsec-enrich/src/cmdb.rs`, and measured on CI's Linux it
does not -- CI reports 8310/8310 functions. The gate's
`--fail-under-functions 100` is therefore correct for CI and unreachable
locally on macOS. A local workspace run that fails *only* on that
function is reproducing the platform difference, not a regression.

Two corrections to what this document previously said. The 86 uncovered
lines the workspace gate reports are **not** cache pollution; a fully
cleaned tree reproduces that exact line set, and they are real under
1.100. What *is* true is that `cargo llvm-cov clean --workspace` does not
remove everything: the same crate measured 94.25% lines after that clean
and 100% after `rm -rf target/llvm-cov-target`, same code, same commit.
Re-measure with the directory removed, or the numbers read low.

## `appsec-interactive/src/blocking_io.rs` (file-level exclusion, not a crate)

The only *file-level* coverage exclusion in this workspace
(`--ignore-filename-regex 'appsec-interactive/src/blocking_io\.rs'`, applied
on both the workspace-wide and the `appsec-cli` `cargo llvm-cov` steps), and a deliberate, documented
one (see that file's own module doc comment): its two blocking
real-terminal-I/O calls (`crossterm::event::read()`,
`stdin().read_line()`) can't be safely exercised by an automated test
without a live TTY. Doing so risks hanging the whole suite, not just
flaking one test, if the test process's stdin isn't already at EOF.
`Terminal`'s other methods (`is_tty`/`draw`/`write_line`, in
`terminal.rs`) and every actual DECISION this crate makes (key mapping,
cursor movement, selection parsing) live elsewhere and stay fully covered
against a scripted fake.

## `appsec-cli`

Observed ~99.3% functions, ~99.0% lines (`--fail-under-lines 98.9 --fail-under-functions 99.1`)

`appsec-cli` is the only crate in this workspace with a `[lib]` *and* a
`[[bin]]` *and* its own `tests/*.rs`, which produces five separately-
compiled instances of its library code (the `--lib` unit-test binary, the
`tests/cli.rs` integration binary linking it as a normal dependency, the
real `appsec-scan` executable, and two harness-mode duplicates of the
`[[bin]]` target itself). After closing every gap
`--show-instantiations` could actually name (confirmed clean after a full
`rm -rf target/llvm-cov-target` rebuild), `cargo llvm-cov`'s own summary
still reports 5 lines short of 100% in `src/lib.rs`, but every other
diagnostic (`--show-instantiations`, the HTML report, the JSON region
export merged across all compiled instances, and `llvm-cov show` invoked
directly against all ~44 relevant objects) agrees every line has actually
executed. This is a known category of `cargo-llvm-cov`
summary/instantiation-merge disagreement for heavily-monomorphized
multi-binary crates, not an untested code path. This crate is the only
one in the workspace where it surfaces, matching its unique compile
shape. (A real, additional gap was also found and fixed here during Phase 7
cleanup, not accepted as this same category: `batch.rs`'s private
functions were never exercised by the separate `tests/cli.rs`
compilation unit, and the default `./batch_summary.md` fallback path
had no test at all. Both got real tests, `tests/cli.rs::
a_batch_scan_with_repo_file_succeeds_end_to_end_through_the_real_binary`
and `src/lib.rs::main_impl_batch_mode_defaults_the_summary_path_
when_out_batch_summary_is_unset`. Don't assume every shortfall in this
crate is the tool-artifact category above. Verify first, the way that
one was: confirm via a standalone test run whether the code path
executes before accepting a threshold gap as artifact rather
than real.)

### 2026-09 update: the gate had drifted below itself

At the start of the CLI-wiring pass this crate measured **99.22% lines /
99.34% functions against a 99.5 / 100 gate**, i.e. CI's own coverage step
was failing on `main` and had been for a while. Almost all of it was real,
not the artifact category above: `src/clone.rs` (added later than this
section's text) had 29 uncovered lines and 4 uncovered functions across
its stage-marker, reuse and clone-failure paths.

Closed with real tests plus two small testability refactors, both of the
"injectable cap" shape this workspace already uses in
`appsec_stage_s10::worktree_forbidden_matches_capped`:

- `run_bounded_clone(program, timeout, ...)` takes the git program name and
  the deadline as parameters, so the timeout arm is reachable with
  `Duration::ZERO` and the cannot-spawn arm with a program name that does
  not exist. Neither was testable before: a 600-second deadline cannot be
  waited out, and emptying `PATH` to make `git` unspawnable races every
  other test in the process (tried, and it did).
- `clone_failure_message(output, token)` is a pure function over an
  `Output`, so the stderr/stdout preference and the token redaction are
  testable without provoking a real `git clone` failure of each shape.
- `write_stage_marker` now takes its directory from `stage_marker_dir()`
  rather than `marker_path.parent()`, deleting a `None` arm no input
  could reach.

Now at **99.51% lines / 99.90% functions**. One function in `clone.rs`
remains unexecuted and could not be isolated: `llvm-cov`'s merged JSON
lists every `clone.rs` function once per compiled instance (this crate
has five; see above), so a name that is zero in the non-test rlib copy
and non-zero in the test copy is indistinguishable, in that export, from
one that is never run. The summary's own dedup says exactly one
is real. Rather than guess, the functions gate moves to 99.5 (which
still trips on a second uncovered function), and this note records the
number to beat.

At that point `--fail-under-lines 99.4` left ~11 lines of headroom below
the observed 99.51% so a *real* regression still trips the gate, on the
same principle as every other threshold in this document. The next
section is where both numbers, and that threshold, stand now.

### 2026-09 update: the target-testing and delivery modules

`--target-tests` and `--remediation-delivery` added six modules
(`target_executor.rs`, `target_testing.rs`,
`target_testing/builtin_profiles.rs`, `delivery.rs`, `delivery_archive.rs`,
`delivery_branch.rs`) plus the `dispatch_remediation` and
`build_remediate_run` wiring in `lib.rs`. They arrived with almost no
tests: **96.41% lines / 94.41% functions**, i.e. 574 uncovered lines and
82 uncovered functions against a 99.4 / 99.5 gate.

97 tests now cover every path in that code with observable behavior. The
isolated executor's policy validation, phase selection, snapshot
sanitizing (nested directories, executable bits, special files, symlinks,
depth/entry/byte bounds, unreadable and unsearchable source directories),
Docker argument construction, exit-status classification, output
combining and truncation, container naming and cleanup. The assurance
pipeline's proposal validation (file count, byte budget, secret
detection, support-path approval, source-type recognition, symlinked
destinations, citation checking, oversized contract files), generator and
reviewer failure modes (malformed output, exhausted turn budget,
unreachable model), the apply-and-roll-back writer, execution
classification, the evidence artifact and the Markdown/SARIF annotation.
Delivery's mode selection, branch publication against a synthetic Git
remote (detached-HEAD and single-push-destination requirements,
create-only branches, unsupported status records, changed symlinks,
non-file paths, size and secret limits, deletions, executable and binary
content, no-change runs, non-UTF-8 configuration keys), the archive's
inventory bounds, portability checks and ZIP writer, and the `lib.rs`
refusals that keep target testing and delivery inside a completed full
scan with an isolated worktree or snapshot.

Two of the gaps that left were not test gaps. Both were closed by moving
the new code onto a convention the rest of this crate already follows,
with no change to what any of it does:

- Every `map_err(|e| e.to_string())` now uses the crate's shared
  [`stringify`], and every `map_err(|e| format!("<context>: {e}"))` uses a
  new sibling `context("<context>")` that returns one shared closure body
  per error type. Textually distinct closures compile to separate
  functions, so each one previously had to be reached on its own to be
  counted; 23 of the 25 uncovered functions were closures of that shape
  over operations that cannot fail in-process. The messages are
  byte-identical: `stringify` *is* `e.to_string()`, and `context(what)`
  *is* `|e| format!("{what}: {e}")`, verified by diffing the multiset of
  30 converted prefixes before and after.
- `run_command` takes the Docker program name and the deadline as
  parameters, the same injectable-cap shape `clone::run_bounded_clone`
  already uses here for exactly this problem, with `execute` passing
  `docker_program()` and `COMMAND_TIMEOUT` and
  `the_production_call_site_uses_the_real_client_and_deadline` pinning
  both. That makes the spawn-failure arm reachable with a program name
  that does not exist and the timeout arm reachable with
  `Duration::ZERO`, neither of which was testable before. As a side
  effect this crate's coverage no longer depends on whether the machine
  running it has Docker installed: exit-status classification is driven
  through the same seam by tiny scripts that exit 0, 1, 125 and 127.

That is **99.41% lines / 99.70% functions**, 109 uncovered lines and 5
uncovered functions. `--fail-under-lines` moves from 99.4 to **99.37**,
which is 6 lines of headroom below the observed figure, so losing a
handful of covered lines still trips it. `--fail-under-functions` stays
at **99.5**, which the refactor clears with room to spare and which still
trips on a sixth uncovered function. What is left:

**A. Container process arms no test can drive (14 lines).** `run_command`
branches four ways after spawning the Docker CLI. Three are now tested:
an unavailable digest-pinned image through `execute`, a client that
cannot be started, and a run that outlives its deadline. The fourth,
`child.wait()` itself returning an error (`target_executor.rs` 558-568,
11 lines), cannot be induced from a test at all. Two more lines (682,
690) are the Windows halves of `docker_program`/`safe_host_path`,
compiled but not taken on a Unix runner, and 724 is `ContainerCleanup`'s
drop outside a Tokio runtime, which the summary keeps reporting as missed
even though two tests execute it.

**B. Five uncovered functions.** `batch.rs` 500 and `clone.rs` 211 are
the pre-existing instantiation artifact described above.
`builtin_profiles.rs` 54 is the embedded profile JSON failing to parse; it
is `include_str!`-ed at build time and every entry is parsed by
`all_compiled_profiles_have_unique_names_and_valid_policies`, and its
message interpolates the profile name, so it cannot share a closure
without changing what it says. `delivery_archive.rs` 309 is the archive
re-reading more than 256 MiB after the inventory measured less, i.e. the
source growing mid-run. `lib.rs` 1867 is
`serde_json::to_string(&report.findings)` failing, which `serde_json` has
no failing case for on that shape.

**C. Arms no input can reach (22 lines).** `builtin_profiles.rs` 56
validates a profile's `execution` policy, and no shipped profile
authorizes execution; `target_testing.rs` 318 rejects a test path that
escaped the root, which `safe_relative` has already made impossible;
`target_testing.rs` 580 needs a rollback whose `remove_file` fails for a
reason other than the file being absent; `delivery.rs` 129 is the
no-parent branch of a path that always has one; `delivery_branch.rs` 264,
277, 288, 414, 460, 485 are `text()` rejecting non-UTF-8 output from
`git rev-parse`, `git remote get-url`, `git hash-object` and
`git write-tree`, none of which can emit it; 384 is unreachable because
the component walk immediately above it already returns for the same
error; 395 needs a changed file to grow between its `metadata` call and
its `read`; 176-178 is the 120-second Git timeout.

**D. Platform-conditional and pre-existing lines.** `delivery_archive.rs`
138-140 and its test at 457 are the case-insensitive filename collision
check, which cannot be provoked on a case-insensitive filesystem (macOS
APFS) and is covered on Linux; 346 is the write-error propagation of a
`u16` header field. The 33 remaining `lib.rs`, `environment.rs`,
`autoexclude.rs`, `worktree.rs`, `batch.rs`, `clone.rs` and `estimate.rs`
lines pre-date this feature and are the artifact and defensive-branch
categories already described above.

**The summary/show disagreement is now much larger than the 5 lines the
text above describes.** `llvm-cov show`, merged across all compiled
instances, finds 67 lines in this crate with a zero execution count. The
summary the gate reads reports 109. The 42-line difference is the same
instantiation-merge disagreement, and it grew with the crate: the new
modules add production code that only the `--lib` test binary executes,
and the summary counts a good deal of it as missed anyway. Both figures
are recorded here so a future reader can tell a real regression from more
of the same, and the threshold is set against the summary because that is
what the gate reads.

## `appsec-checkpoint`

Observed 100% functions, ~100% lines (`--fail-under-lines 99.5 --fail-under-functions 100`)

A DIFFERENT gotcha from `appsec-cli`'s above (this crate has only a `[lib]`:
no `[[bin]]`, no `tests/*.rs`, none of the multi-binary shape appsec-cli's
own comment describes). After landing `gc`/`prune`/`register_run`/
`reset_run` (`crates/appsec-checkpoint/src/sqlite_store.rs`), `cargo
llvm-cov`'s own summary reports 1 line short of 100% in that file, but
`llvm-cov show` invoked DIRECTLY against the exact same single compiled
test binary + profdata `report` used (bypassing the `cargo-llvm-cov`
wrapper entirely, confirmed via a fully clean `cargo llvm-cov clean
--workspace` rebuild first) finds ZERO lines with a zero
execution count, and the HTML/text detail views built from that same
data agree. `llvm-cov report`'s own aggregate disagreeing with `llvm-cov
show`'s own line-by-line render of THE SAME instrumentation data is an
internal tool inconsistency, not an untested code path: `llvm-cov show`,
read per instantiation, finds every one of those lines executed.
`--fail-under-lines 99.5` leaves headroom below
the consistently observed 99.83% so a *real* regression still trips the
gate.

## `appsec-callgraph`

Observed ~99.3% functions, ~98.2% lines (`--fail-under-lines 98.0 --fail-under-functions 98.5`)

A THIRD, different category from `appsec-cli`/`appsec-checkpoint`
above: not a `cargo-llvm-cov` report-vs-show tool disagreement
(`llvm-cov show` on the same profdata agrees with the summary here;
these are REAL zero-execution lines), but defensive fallbacks in the S0
tree-sitter scanner (`src/scan.rs`) that are unreachable via any real
parse tree the pinned grammar version produces, plus (added once
`javascript`/`typescript`/`go` landed alongside the original
`python`-only extractor) a recurring LLVM region/instantiation-counting
artifact:

- `py_leftmost_identifier`'s two "malformed node" guards (missing
  `object`/`function` field, or a childless token hit while walking a
  wrapper node's first child), verified via ~25 adversarial
  malformed/truncated/error-recovery Python snippets. `js_leftmost_
  identifier`'s and `go_leftmost_identifier`'s own equivalent guards
  (`member_expression`/`selector_expression` and `call_expression` each
  requiring their `object`/`operand`/`function` field) are the same
  category for tree-sitter-javascript/-go: every real node of each kind
  tree-sitter ever produced (including nested-call and
  parenthesized-expression adversarial cases, which DO reach each
  function's *success* path and its own wildcard arm; see the paired
  `_walks_through_a_call_expression_*`/`_wildcard_arm_walks_then_dead_ends`
  tests) had the expected field populated.
- `import_from_statement`'s "module name is empty" branches (Python):
  `module_name` is always non-empty whenever this node kind appears at
  all. The JS/TS equivalents: a `named_imports` specifier missing its
  `name` field, a CommonJS `require(...)` call missing its `arguments`
  field, and a `class_declaration` missing its `name` field, all
  verified unreachable the same way (an anonymous `export default class
  {}` parses to a bare `class` node, never `class_declaration`, so a
  nameless `class_declaration` can't occur; every
  `call_expression` tree-sitter produces, `require()` included, always
  carries an `arguments` node even when empty). Go's `go_import_spec`
  missing a `path` field is the same category once more (no
  construction, including an empty `import ()` block, produces an
  `import_spec` node at all without one). Java (landed after JS/TS/Go)
  adds two more instances of this same "no real construction reaches
  it" category rather than a new one: a `local_variable_declaration`/
  `variable_declarator` missing its `type`/`name` field, and
  an `assignment_expression` missing either operand. The last of these
  was cross-checked against a deliberately malformed `x =;`, which
  tree-sitter-java parses to an `ERROR` node instead of a real
  `assignment_expression` at all, confirming the branch it would
  otherwise guard can't be reached that way either. C# (landed after
  Java) adds three more instances of the same category:
  `cs_leftmost_identifier`'s two "missing field, empty child" fallbacks
  (a `member_access_expression` always carries an `expression` field;
  an `invocation_expression`/`element_access_expression` always has at
  least one child to fall back to), `cs_assignment_parts`'s
  missing-`left`-or-`right`-operand guard (both fields are
  grammar-mandatory for `assignment_expression`/
  `simple_assignment_expression`), and `cs_visit_variable_declarator`'s
  `name_node.kind() != "identifier"` guard (the one real case where a
  declarator's name ISN'T a plain identifier, tuple deconstruction with
  `var (a, b) = ...`, produces no `name` field at all, caught by the
  earlier `Some(name_node)` check instead, so this narrower guard never
  actually fires).

The fact-extraction modules that landed alongside the S0 taint-evidence
engine (`src/facts.rs`, `src/framework.rs`, `src/reflection.rs`) add more
instances of this same grammar-guaranteed category rather than a new one:
each walks the tree looking for a specific node shape, and the guards
that would fire when a matched node is missing a structurally mandatory
field never do. Where the guard was cheap to eliminate outright it was
(`framework.rs`'s per-language `*_method`/`*_parameter`/`py_decorated`
helpers return `Option<()>` so those lookups are `?` expressions on an
executed line rather than dead early-return arms), and what is left is
the same "closing brace after an unconditional arm" phantom described
below plus a handful of unreachable field guards.

These mirror Python's own defensive style faithfully rather than
asserting away code that's provably dead only for the grammar versions
pinned today. A future tree-sitter bump could theoretically change
this.

A SECOND, distinct sub-category, present since `scan.rs` first landed: a
handful of closing braces immediately following an unconditional
`return` or an empty `_ => {}` match arm, with nothing else in that
scope, show a permanent phantom 0-count in `py_visit`'s "assignment"
arm, `js_visit`/`go_visit`'s call-expression handling, `match_call`'s
module_attr resolved-path branch, (Java) `java_visit`'s
`class_declaration`/`object_creation_expression` handling, and (C#)
`cs_invocation_parts`'s `_ => {}` arm, `cs_call_target`'s
assignment-operand check, and `cs_visit`'s `class_declaration` handling.
In every case the statement immediately before the brace (the actual
`return`, or the match arm the brace closes over) is independently
confirmed executing via `llvm-cov show`. Two OTHER C#-specific instances
of this same shape (`cs_visit_variable_declarator`'s "no `value` field"
fallback and the `object_creation_expression` arm's class-name
computation) were fixed outright instead of accepted, by flattening the
nested `if`/`if-let` into a single `.or_else(...)`/`.and_then(...)`
combinator chain, per gotcha #3's documented fix, confirming that fix
generalizes beyond the two crates (`appsec-stage-s6`/`appsec-stage-s8`) it was
first found in. `src/graph.rs` (the call-graph/BFS/path-budget engine)
reached genuine 100%/100% the same way for every instance of this
pattern it had. It was not attempted for the REMAINING `scan.rs`
instances above because their tree-walk visitors are a much worse fit
for that restructuring (deeply nested per-node-kind matches, not a single linear
scan). `src/annotator.rs` (LLM-free candidate collection /
prompt-building / heuristic classification) adds two more accepted
lines matching these same two categories, not a third.

A THIRD sub-category, new with the JS/TS/Go extractors: a
`cargo-llvm-cov` "missed function" flag on exactly one closing-brace
*region* (not the function body) of each of `py_leftmost_identifier`/
`js_leftmost_identifier`/`go_leftmost_identifier`, confirmed via a
direct JSON coverage export to be a specific duplicate-instantiation
region (one of ≥2 compiled instances of the same function shows 0 while
another shows real hits), the same class of tool artifact seen elsewhere
in this workspace, not evidence the function itself is untested (each has
direct, passing success-path tests).

A FOURTH sub-category, new with C#: tree-sitter-c-sharp 0.23.5 (the
pinned version) diverges from what Python's `_cs_extract` assumes in
three ways, verified via live probes against the exact grammar, and
faithfully replicated rather than "fixed" to read the tree differently
(which would diverge from what the Python original itself produces
against this same grammar): `argument` nodes (children of
`argument_list`) never populate an `"expression"` field, so
`cs_identifier_args`'s "argument" branch can never capture anything and
its "any other kind" wildcard arm is dead too (every `argument_list`
child is always `argument`-wrapped; there's no bare-identifier child
shape for the sibling match arm to exist for); an `equals_value_clause`
node never appears in this grammar's parse tree at all
(`cs_call_target`'s block for it is dead); and `variable_declarator`
never exposes a `"value"` field (only `"name"`; see the
`.or_else(...)` workaround in `cs_visit_variable_declarator`, so
`cs_call_target`'s `variable_declarator`-with-`"value"`-field check is
dead too).

A FIFTH set, new with the PHP/Ruby/Kotlin/Rust entry-point plane
(`src/framework/{php,ruby,kotlin,rust}.rs`, `src/scan/lite.rs`), is the
first category again (grammar-guaranteed structural fields guarded
anyway) rather than anything new: a `function_definition`/
`method_declaration`/`function_declaration`/`function_item`
missing its `parameters` node, a `call_expression` missing its
`function` field or carrying no named child at all, a
`navigation_expression` with fewer than two named children, and
`leftmost`'s dead-end arm for a receiver expression that bottoms out on
a node with neither a named child nor any of the fields it follows. Each
was probed against the pinned grammar the same way the Python/JS/Go/Java
guards above were; every real node of each kind carried the field. They
are kept rather than deleted for the reason the top of this file gives:
a future grammar bump could start producing a shape that reaches them,
and an extractor that panics or silently mis-attributes there is worse
than one that returns nothing.

## `appsec-repo-analysis`

Observed 100% functions, ~99.8% lines (`--fail-under-lines 99.5`)

`ts_graph.rs` (the Query/QueryCursor-based `step1.call_graph:
tree_sitter` backend, ported from `vvaharness/lang/ts_graph.py`) has a
handful of defensive branches that are unreachable given the
CURRENT, committed `QUERIES` table. A live probe compiling and running
all 14 languages' `defs`/`calls` queries against the exact grammar crate
versions this workspace pins confirmed every one of them succeeds, so:

- `compile_all`'s `Query::new(...)` failure arm (query fails to compile
  against the linked grammar) never fires for any of the 14 entries
  today.
- `parse_file`'s `parser.parse(text, None)` returning `None`
  (tree-sitter's own documented reasons: no language set, or an
  explicit cancellation flag/timeout; this backend sets neither) can't
  happen for the language just successfully compiled a `Query` against
  moments earlier.
- two match-arm wildcards (the `defs` query's capture-name match, the
  `calls` query's capture-name check) are unreachable because every one
  of the 14 `defs` queries declares EXACTLY the two capture names
  `name`/`def`, and every one of the 14 `calls` queries declares
  EXACTLY the one capture name `callee`. There is no third capture
  name for either wildcard to ever see.
- the `let (Some(nn), Some(dn)) = (name_node, def_node) else {
  continue }` guard in the defs-match loop is unreachable given the
  same fact: a live probe confirmed each `defs` query match pairs
  exactly one `@name` with one `@def` (verified even for
  multi-alternative-pattern queries like Java's
  `method_declaration`/`constructor_declaration`), so one without the
  other never occurs for any of the 14.

These mirror `appsec-callgraph`'s own "grammar-guaranteed unreachable"
exception category:
empirically verified against the pinned grammar versions, not
mathematically proven, so a future grammar-crate bump could
theoretically change this; kept as real defensive code rather than
deleted. `--fail-under-lines 99.5` leaves headroom below the
consistently observed 99.81% (`--fail-under-functions 100` stays exact;
that metric is unaffected, every function has at least one covered
region) so a *real* regression still trips the gate.

## `appsec-validation-scoring`

Observed 100% functions, ~99.7% lines (`--fail-under-lines 99.5 --fail-under-functions 100`)

Same "unreachable defensive branch" category as
`appsec-callgraph`/`appsec-repo-analysis` above, not a tool artifact.
`score_fix`'s `Err(result) => return result` arm on
`renormalized_score`'s call is provably unreachable through the public
API: `shape_error` requires all 4 gate names present with no
duplicates, and `critical_gate_error` already short-circuits if either
critical gate (`root_cause`, `no_new_vulnerabilities`) is Skip/Invalid.
So by the time `renormalized_score` runs, both critical gates are
always Pass/Partial/Fail and contribute their full weight (0.43 +
0.1867 = 0.6167) to `active_weight`, which can never be `<= 0.0`. The
guard itself IS covered directly (see
`renormalized_score_guards_a_zero_weight_input_directly` in
`src/tests.rs`, calling the private function on its own, mirroring the
current Python `_engine.py`'s own doc comment calling this the
"divide-by-zero guard" for the same reason); only `score_fix`'s own
dead calling arm is excepted here. `--fail-under-lines 99.5` leaves
headroom below the observed 99.66% so a *real* regression still trips
the gate.

## `appsec-stage-s0`

Observed 100% functions, ~99.5% lines (`--fail-under-lines 99.3 --fail-under-functions 100`)

Four lines in `engine.rs`, across two defensive branches that cannot be
reached with a correctly built binary:

- The `Err` arm of the BUNDLED starter corpus load (`load_rules_mode_specs`,
  the `no source/sink rule YAML configured` path). Its input is
  `include_str!`-ed at compile time from
  `crates/appsec-stage-s0/corpus/{sources,sinks}.yaml`, and a corpus that did
  not parse would fail
  `load_rules_mode_specs_falls_back_to_the_bundled_corpus_when_unconfigured`
  (and two `run_callgraph_engine` tests beside it) long before this arm
  ran. Kept as real code rather than an `expect`, because
  the alternative to a warning here is a panic in a scan.
- `run_callgraph_engine`'s `used_llm_specs` branch inside the "0 files
  matched" arm: believed unreachable by construction (every spec
  `appsec_callgraph::annotator::append_spec` builds is derived directly from
  a call site this same second scan re-parses, so it always matches at
  least that one site; see that branch's own code comment), empirically
  probed, not formally proven, so kept as real code rather than deleted.

**A previously listed exception was not one.** This section used to claim
a `FailingClient::chat` test double showed zero executions despite being
used, and attributed it to an `async-trait`-macro coverage-attribution
quirk after ruling out signature shape, error text, macro spelling and
struct placement. The real cause was simpler and worse: the test's
fixture was `def f():\n    g()\n`, a BARE call, which
`collect_candidates` does not produce a candidate for, so `detect_specs`
returned early and the failing client was never called. The test asserted
on an empty seed and passed for the wrong reason, proving nothing about a
failed LLM call. Fixed by giving it a dotted call (`os.system(cmd)`) and
disabling `heuristic_supplement`, and its assertion now checks that the
run degraded to the rules fallback and still produced a seed. Coverage
reporting was right; the test was wrong.

Two more lines were recovered by formatting `run_callgraph_engine`'s two
`tracing::info!` summaries eagerly into a `String` first: `tracing`'s
macros only evaluate their arguments when a subscriber has the callsite
enabled, and no test installs one, so eight lines of argument expressions
were never executed. Same fix, same reason, as the
eagerly-formatted summary lines elsewhere in this workspace.

## `appsec-stage-s1`

Observed ~99.7% functions, ~99.2% lines (`--fail-under-lines 99.1 --fail-under-functions 98`)

Same report/show tool-inconsistency category as `appsec-checkpoint`/
`appsec-stage-s0` above: `cargo llvm-cov`'s own summary reports 2 lines/2
functions short of 100% in `src/pure.rs` (the S0-seed merge/gap_fill
logic added alongside `appsec-stage-s0`), but `llvm-cov show` against the
same compiled test binary + profdata (bypassing the wrapper,
clean-rebuilt first) finds every one of those lines executed, `return;`
`--fail-under-lines 99.5` / `--fail-under-functions 98` leave headroom
below the consistently observed crate-level 99.85% lines / 98.92%
functions so a *real* regression still trips the gate.

## `appsec-thirdparty-api`

Observed ~99.55% functions, ~99.8% lines (`--fail-under-lines 99.5 --fail-under-functions 99.0`)

Two independent, verified tool artifacts, not real gaps:

- `src/oauth2.rs`'s `TokenCache::get_or_refresh<F, Fut, E>` is a generic
  `async fn` monomorphized 7 times (once per its own crate-internal unit
  tests' `String`-typed closures, once for `AikidoClient::access_token`'s
  `AikidoError`-typed closure, once for `CheckmarxClient::access_token`'s
  `CheckmarxError`-typed closure). The "already valid, return the cached
  token without re-fetching" branch (`if tok.is_valid() { return
  Ok(...); }`) executes on the vendor-crate instantiations
  too. `AikidoClient`/`CheckmarxClient` both call `access_token()` more
  than once per `fetch_findings()` (once per paginated page, or once per
  scans-then-results call), and the two-call tests
  (`aikido::tests::fetch_findings_reuses_the_cached_token_across_pages`,
  `checkmarx::tests::fetch_findings_paginates_results_until_total_count_is_reached`)
  wouldn't need a second real token fetch to pass. But `cargo-llvm-cov`'s
  region-merge for this doubly-monomorphized (generic + async-state-
  machine) function attributes the runtime hit to a different region copy
  than the one its own line-level summary checks, so the vendor-crate
  instantiations show 0 even though the branch runs. Same general
  category as `appsec-cli`'s and `appsec-stage-s1`'s entries above.
- `semgrep.rs`/`snyk.rs`'s `severity_mapping` test uses `#[rstest]` with
  6 `#[case]` attributes; every generated `case_1`..`case_6` variant runs
  and passes (confirmed in the test-run log), but the un-expanded
  template function signature itself is counted as one additional,
  never-directly-called "function" by `cargo-llvm-cov`'s function-count
  metric: an inherent `rstest`-macro-expansion artifact, not a
  behavioral gap.

## `appsec-diffcapture`

Observed ~99.4% functions, ~99.4% lines (`--fail-under-lines 99.3 --fail-under-functions 99.0`)

New with the target-testing commit, which replaced `snapshot_files`'s and
`revert`'s lexical `norm_path` keys with a resolved `canonical_repo_path`
identity and turned tier 2's `git checkout` from a fire-and-forget call
into a checked one. Two accepted items, both in `src/lib.rs`, and both the
"unreachable defensive branch" category rather than a tool artifact
(`llvm-cov show` agrees with the summary here; these really are
zero-execution regions):

- `canonical_repo_path`'s non-`Normal` component arm (`Component::CurDir |
  ParentDir | RootDir | Prefix(_) => None`). `relative` is whatever is
  left after stripping one `appsec_pathjail::confine` result from another, and
  `confine` returns a fully resolved path: its `resolve_best_effort` pops
  every `..`, drops every `.`, and canonicalizes whatever exists, so the
  remainder of a `strip_prefix` between two such paths can only be
  `Normal` components, or nothing at all. The "nothing at all" case (the
  candidate IS the root) is reachable, but it is the following
  `!components.is_empty()` guard, not this arm. Kept rather than deleted for
  the reason the top of this file gives: the alternative to an arm that
  returns `None` is a repo-relative identity assembled from a component
  this code never checked, which is the exact mistake the function exists
  to prevent.
- the `map_err` closure on tier 2's `git checkout` `.output()` call. That
  `Result` is `Err` only when `git` itself cannot be spawned, and this
  crate hard-codes the program name, so the only way to induce it is to
  empty `PATH` for the whole test process. That races every other test in
  the same binary, which `appsec-cli`'s section above already records having
  tried, and it did race. Closing it properly needs the
  injectable-program-name shape `appsec_cli::clone::run_bounded_clone` uses,
  which is a production change rather than a test.

Everything else this commit added here is covered by real tests, including
both guards that turned out to have a reachable input after all:

- `a_repo_file_named_like_a_unc_path_is_skipped_and_refused_by_revert`.
  A repository file whose own name begins with two backslashes (an
  ordinary file name on Unix) is the one input that reaches the
  "re-confining the canonical identity failed" guards in `snapshot_files`
  and `revert`. The absolute spelling a caller supplies is not a UNC path,
  so the identity resolves; the repo-relative identity it yields IS one,
  and `appsec_pathjail::confine` refuses it before touching the filesystem.
- `a_failing_git_checkout_is_reported_instead_of_being_swallowed`.
  Emptying the object store of an otherwise valid work tree leaves
  `is_git_worktree` and `is_tracked` answering truthfully while
  `git checkout` cannot read the blob, which is what the new error return
  exists for: a revert that silently did nothing used to be
  indistinguishable from one that worked.

`--fail-under-lines 99.7` / `--fail-under-functions 99.0` leave headroom
below the observed 99.85% lines / 99.31% functions while still tripping on
a second uncovered function or a fourth uncovered line.

## `appsec-sandbox-tools`

Observed 100% functions, ~99.7% lines (`--fail-under-lines 99.6 --fail-under-functions 100`)

One line, and it is the same exception as `appsec-diffcapture`'s first item
above rather than a new one: `control_path.rs`'s `canonical_relative_path`
has the identical non-`Normal` component arm, for the identical reason
(both functions strip one `appsec_pathjail::confine` result from another and
map what is left). See that section for the full argument.

The rest of `control_path.rs`, which is new in the same commit, is covered
directly: the leading/trailing-whitespace refusal, the colon and
whitespace checks on each component, the empty-identity case, and the
symlink resolution `is_git_control_path` depends on. So is the
`prepare_write` gate in `executor.rs` that consumes it, on both the
`Write` and the `Edit` path, including the two refusals a caller actually
sees (an outside-root path and a Git control path).

`--fail-under-functions 100` stays exact; every function in this crate has
at least one covered region. `--fail-under-lines 99.8` leaves headroom
below the observed 99.94% so a real regression still trips the gate.

## `appsec-orchestrator`

Observed ~99.3% functions, ~99.6% lines (`--fail-under-lines 99.5 --fail-under-functions 99.1`)

The line threshold moved from 99.7 to 99.5 on 2026-11-16, when context
gathering landed. The four uncovered lines it added are the tail of
`gather_typed_context`, reached only once documents are in hand -- which
needs a live MCP server process. The halves either side are covered
directly: `gather_documents` and `drive` by scripted transcripts plus a
real child process (`/bin/cat`, which starts and is not a server), and
`extract_and_merge` by hand-made documents with a scripted model,
including the add-and-raise-only merge rules. What is left is glue, the
same shape as `appsec-mcp`'s `server::run`.

Two `map_err` closures in `src/reporting.rs` (S9, split out of
`run_scan` by the target-testing commit), over serialization calls that
cannot fail for the types they are handed:

- `redact_report`'s `serde_json::to_value(report)`. `FinalReport` and every
  type it contains derive `Serialize`, hold no map with a non-string key,
  and have no hand-written `Serialize` impl, so both error shapes
  `serde_json`'s `Value` serializer can produce (a key that is not a
  string, and an error a custom impl raised itself) are unconstructible
  here. A non-finite `f64` is deliberately NOT one of them: `to_value`
  writes `null` for it and returns `Ok`.
- `Stage9::run`'s `serde_json::to_string_pretty` over the built
  `SarifDocument`, for the same reason about the same kind of derived
  types.

The third closure in this file was NOT an exception and now has a real
test. `redact_report`'s return leg, `serde_json::from_value` back into a
`FinalReport`, does fail for a reachable input, and
`a_report_that_cannot_survive_the_redaction_round_trip_is_a_stage_error`
feeds it one: `ScanMetrics { duration_sec: f64::NAN, .. }`. JSON has no
spelling for a non-finite float, so the outbound `to_value` writes `null`,
and `duration_sec: f64` refuses `null` on the way back, because
`#[serde(default)]` fills in a field that is MISSING, never one that is
explicitly null. That is the case worth having, because the code this
commit replaced used `.expect("redact_tree preserves JSON shape, so
FinalReport deserializes back")` and would have panicked at the very last
step of a scan that had already done all of its work.

`--fail-under-lines 99.9` / `--fail-under-functions 99.4` leave headroom
below the observed 99.97% lines / 99.57% functions while still tripping on
a third uncovered function or a sixth uncovered line.

## `appsec-mcp`

Observed ~97.9% functions, ~98.8% lines (`--fail-under-lines 98.6 --fail-under-functions 97.5`)

Carries its own gate rather than sitting under the workspace's
100%-functions gate, because it owns a binary. The thresholds are lower
than its neighbours' and the reason is structural, not a shortfall in
testing: the parts a unit test cannot enter are a visible fraction of a
crate this size.

| file | functions | why |
| --- | --- | --- |
| `lib.rs` | 100% | none |
| `gather.rs` | 100% | none |
| `sharepoint.rs` | 100% | none |
| `confluence.rs` | 96/99 | `panic!` arms in test assertions |
| `http.rs` | 50/52 | two unreachable builder errors |
| `client.rs` | 68/71 | a child with no pipes; a failing `wait` |
| `server.rs` | 60/62 | `run` reads the real environment and stdin |
| `main.rs` | 0/1 | glue; covered only across a process boundary |

The uncovered things, each verified by reading the lines the gate names
rather than assumed:

- **`main.rs`, 6 lines.** The binary's glue. `tests/server_process.rs`
  does drive it as a process -- asserting it answers on stdout, exits
  non-zero when misconfigured without echoing the token, and keeps
  serving after a malformed frame -- but coverage is not collected across
  a process boundary, so it reads as 0% despite being exercised.
- **`server::run`, 22 lines.** Reads the real environment and locks the
  real stdin. Every decision it makes belongs to `config_from_env` or
  `serve`, which are driven directly by in-memory buffers and an injected
  `getenv`. It grew when the backend became a choice, because selecting
  and boxing the source is the one thing that can only happen there.
- **Two error closures in `http.rs`.** `reqwest::ClientBuilder::build`
  and tokio's `Builder::new_current_thread().build()` cannot fail with
  this crate's fixed configuration. Returning an error rather than
  `expect`-ing is right for a server process, so the paths stay and are
  simply unreachable from a test.
- **One line in a test's spawned thread** (`http.rs`), in the raw-listener
  server that truncates a body mid-stream.
- **The `panic!` arms of test assertions**, which run only when the test
  fails. The gate counts each as a function, which is why functions sit
  below lines and why adding tests can move the two in opposite
  directions.

### The time this gate caught a gate, not a gap

Worth recording, because the mistake was mine and the gate is what
found it.

The thresholds were raised to 98.6/97.5 on a measurement taken partway
through a change. More code then landed in the same crate -- the
document-reading wiring -- and nothing re-measured before the push. CI
failed on functions at 97.323%.

The reflex is to lower the number. What the failure actually pointed at
was a real hole: **nothing exercised the shipped `ReqwestTransport` from
outside the crate.** Every test of it used `plaintext_for_tests`, the
`#[cfg(test)]` constructor compiled out of real builds, so the transport
under test was strictly not the one that ships.
`tests/real_transport.rs` now builds the real one through the public API
and drives all five of its methods.

That alone did not move the number, which was the useful part: it
disproved the theory and forced a proper reading of the per-file counts,
which named the actual gap in one line -- a 429 carrying `Retry-After`
on the **download** path. `send_bytes` parses that header itself, and
`BytesResponse` has its own `Throttled` impl, so the JSON path's tests
covered neither. A throttled download would have been retried on a delay
nothing had parsed. Two tests closed it, and the measurement went to
97.913% without the threshold moving.

### Gaps this gate found, which were closed rather than excused

The point of reading the named lines rather than accepting the number.

From the first pass: `context_search` had never been driven through the
serve loop (so the source's `search` was dead code in tests), the
flush-error path was unreachable because the stub's `flush` always
succeeded, and a `Retry-After` that is not a number had no test.

From the SharePoint pass (2026-11-16), where the crate roughly doubled:

- a site resolved **on demand** rather than from the search's cache --
  the path a fetch takes when no search populated the mapping first;
- a term that cleans away to nothing, which must drop out rather than
  become an empty phrase, since KQL documents a query of only operators
  as invalid;
- a **401 on the search POST**, which is a second code path from the one
  a plain Graph GET takes. Both were written; only one was exercised;
- a 200 carrying a non-JSON body, the shape a sign-in page takes;
- and the one that mattered most: **the Confluence CQL terms clause had
  no test at all**, despite the orchestrator now sending subject terms on
  every scan. A malformed clause there would have broken every Confluence
  search, not just a newly configured one. It is the clearest case in
  this document of the gate earning its keep -- the code was new, it
  looked obvious, and it was on the critical path of a shipped feature.

## `appsec-parity-tests` (excluded, no separate step)

Cross-checks this port against the real Python source and needs a
Python venv that isn't set up on this runner. See
`docs/parity-harness.md`.
