# Module size: what is measured, and what is being split

The CI `size` job runs `scripts/loc_audit.py --check`. This is the
rationale beside it, the same way `docs/coverage-exceptions.md` sits
beside the coverage gates.

## Why raw line counts are not the measure

`wc -l` is badly misleading in this repository, and acting on it would
send a refactor at the wrong files. Two things inflate the count,
neither of which means a file is monolithic:

- **Inline tests.** House style puts `#[cfg(test)] mod tests` beside the
  code it covers, and the block is routinely several times larger than
  the code.
- **Dense documentation.** Doc comments here carry the reasoning behind
  a decision. That is the style working as intended, not something to
  break up.

So the audit reports code, test, comment and blank lines separately and
thresholds on **code**, which is what a refactor actually has to move.
By raw lines, 15 files exceed 2000. By code lines, three do.

The clearest case for measuring properly is
`crates/appsec-stage-s0/src/engine.rs`: 3711 raw lines, fifth-largest
file in the repository, and **244 lines of code**. It is a small module
with a 3250-line table-driven test suite. A raw count would have put it
near the top of a split list for no reason at all.

## Functions, not just files

A file gate cannot see a large function inside a reasonable file.
`appsec-stage-s4/src/hints.rs` is 1311 code lines, which the file audit
reports as unremarkable, and it held a single **833-line** function.
Nothing flagged it; it was found by running `--outline` on a hunch.

So `--functions` reports every function over `--fn-threshold` (default
250) across the repository, and the gate ratchets those too. Two
decisions make that list worth reading:

- **Functions only.** An `impl` block or a derive struct is a
  *container*: a 520-line `impl Validator` is thirty small methods, and
  a 1170-line `pub struct Cli` is clap's surface with a doc comment per
  flag. Neither is a thing to decompose, and listing them buries the
  functions that are.
- **Methods included.** A long method inside an `impl` is not a
  top-level item, so a top-level-only scan cannot see it at all.
  `Stage1::run` is 256 lines and was invisible until this looked one
  level in.

A large `#[cfg(test)] mod tests` is skipped: that is the house style
working, and the file audit counts test lines separately.

## The gate

Baseline: `scripts/loc_baseline.json`, regenerated with
`--update-baseline`. It records both halves -- files over the code-line
limit and functions over the line limit -- and ratchets each the same
way.

It fails on exactly two things:

1. a baselined file whose code count **grew** -- a module already past
   the limit must not get worse;
2. a file not in the baseline that **crossed** the limit -- a new
   monolith.

It deliberately does **not** fail when a file shrinks, or when a
baselined file drops under the limit. Those are the outcome the gate
exists to encourage, and failing a build on an improvement during
exactly the refactor it supports is how a gate gets switched off. Both
are reported, with the command to lock the progress in.

Only `rust` files are gated. A generated price table is not a module and
splitting it would mean nothing; the audit still reports it.

Only the current offenders are baselined, not every file near the limit.
Tracking the near misses would mean re-baselining on most pull requests,
and a gate that demands a chore on every change is a gate people route
around. A file under the limit may grow freely until it crosses, which
is the point at which somebody should be thinking about it anyway.

## The three files, and how each one divides

`--outline FILE` lists a file's top-level items with their line spans,
which is what finding a seam actually needs. The three have different
shapes, and only one of them divides by size.

### `appsec-callgraph/src/scan.rs` -- 2962 code

Per-language visitors behind a dispatch: `cs_visit` (202 lines),
`js_visit` (172), `java_visit` (167), `py_visit` (157), `go_visit`
(124), with `scan_file` (213) choosing between them and
`RawCall`/`match_call` shared.

One module per language plus a shared `common.rs`. The pieces are
independent, the seams are obvious, and this crate's own `lib.rs` is
already down to 33 lines across 16 files, so the pattern is established
here. **Start with this one.**

### `appsec-orchestrator/src/lib.rs` -- 2117 code

One large item (`build_metrics`, 213 lines) and many small ones, so it
divides by concern rather than by size. Candidate homes: the config
types (`ScanInput` 101, `ScanConfig` 98), `build_metrics` beside the
existing `coverage.rs`, `UsageTrackingClient`, and the remediation
helpers. The crate already has `coverage.rs`, `diagnostics.rs`,
`cancellation.rs`, `manifest.rs`, `reporting.rs` and `telemetry.rs`, so
`lib.rs` is the leftover rather than the design.

### `appsec-cli/src/lib.rs` -- 2866 code

Also many small items: the `build_*` family (`build_scan_config`,
`build_scan_input`, `build_llm_stack`, `build_remediate_settings`), and
`ScanSummary`/`GcSummary` with their `Display` impls (111 and 51 lines
of pure formatting). The crate already has 49 source files.

**Read this before starting on it.** Its test module is `pub(crate)`
because `s6_progress.rs` and `autoexclude.rs` reach into
`crate::tests::{ENV_LOCK, restore_env, fast_config}`. Those 8353 lines
of tests cannot simply move with the code they cover; the shared
fixtures need extracting into a test-support module first. That
`ENV_LOCK` also explains why this suite is the slow one: those tests
serialize on environment mutation.

## Running any of this on a memory-constrained machine

The audit itself is free: 0.8 s and 23 MB peak RSS over 613 files. It
streams one file at a time and never parallelises, because it is I/O
bound and the memory is better spent elsewhere.

The rebuild loop is where the cost is. On a 16 GB laptop with 10 cores,
`cargo` will start up to 10 `rustc` processes, each over a gigabyte on
the larger crates, and the machine starts swapping.

- `cargo check -p <crate>` for the edit loop. No codegen, no linking.
- `-j 4` or `-j 6` to cap the concurrent compilers.
- `CARGO_PROFILE_DEV_DEBUG=line-tables-only`, which CI already sets for
  disk and which helps here for memory.
- `cargo llvm-cov -p <crate>`, never `--workspace` locally. The
  workspace run builds everything instrumented and is by far the
  heaviest thing in this repository.
- `cargo llvm-cov clean --workspace` after any branch switch that
  changes which crates exist. Otherwise it merges instrumented binaries
  left by the other branch and reports a collapse that is not real.

There is deliberately no `-j` cap in a committed `.cargo/config.toml`:
that file is shared, and slowing CI to suit one laptop is the wrong
trade.

## The functions over 250 lines, one verdict each

`--functions` found eleven. Four are done. The rest each have a reason
recorded here, because "no gaps" means every item has a decision, not
that every item got split.

Two patterns account for every one that was worth doing, and neither was
about logic:

- **Data inside a function.** `lang_hint` (833) and `specialist_hint`
  (273) were a `match` over multi-line raw strings; the text moved to
  consts. `main_impl_with_cancel` (297) was 19-field `ScanSummary`
  literals writing `None` eighteen times; `..Default::default()` already
  existed.
- **A sequence with narrow joints.** `publish` (303 -> 36) handed one
  value from each phase to the next. `Stage1::run` (256 -> 166) was
  linear derivation with no early return and one `mut`.

### Left as they are, with reasons

**`run_scan`'s S4-S7 block** (712 total). The block declares
`let raw_findings_count: i64;` and `let chunk_outcomes: ...;` unassigned
and relies on rustc proving S4 sets them before any `break 'pipeline`.
Returning that state through a struct means fields with defaults, and
the compiler stops proving nothing reads an unset one. That trades a
real guarantee for a smaller function, so it should be its own change
where the trade is the subject.

**`dispatch_remediation`** (302: five exits, three mutable locals),
**`remediate_observed`** (314: three exits, four), and
**`remediate_finding_with_baseline`** (543: seven exits, twelve). These
are orchestration over shared mutable state where most phases can abort
the whole operation. Each phase lifted out would take five to seven
`&mut` parameters and signal "the caller should return now" through an
`Option`. That moves the shared state and the exit points out of one
scope, where they are visible, into several, where only review keeps
them consistent. Longer is clearer here.

**`build_taint_paths`** (382: nineteen mutable locals, twenty-nine
loops). Dense graph traversal that accumulates into many structures at
once. Splitting it means threading a dozen accumulators through helpers,
which is the same objection as above with more parameters.

### Done, and why it was the one left worth doing

**`add_taint_chunks`** (423 -> 152). A pure algorithm of distinct passes,
which is the shape that decomposes: the two chunk-emission blocks -- one
for S0-proven seed paths, one for BFS-derived ones -- came out as
`emit_seed_chunks` (145) and `emit_bfs_chunks` (147).

Both mutate the same six accumulators, which is the objection that got
the orchestration functions above left alone. The difference is that
these six accumulate **one thing**: `chunks` and `merges` are pushed
together and never independently, so index `i` of one always describes
index `i` of the other, and the two dedup guards decide whether a push
happens at all. So they became one `TaintAccum` struct rather than six
`&mut` parameters, and the parallel-index invariant is now a doc on the
struct that owns both fields instead of a comment on one local.

The two blocks were deliberately **not** unified, though they are
similar enough to tempt it. The comments explain why: the seed branch's
`source_ref` is a `file:line` while the BFS branch's is a
`file::function` qnode, so `chunk_by_work` can never match across the
two and `seen_paths` has to stay as the cross-branch guard. Merging them
would be a behavior change dressed as a refactor.

Verified by normalizing the mechanical differences (indent, the `acc.`
rename, by-value to by-reference arguments) and diffing against `main`:
**zero lines** from either block went missing in the move.

One trap. The rename masked comments and string
literals, so the extensive prose naming these fields came through
untouched -- but Rust's inline format capture means a literal *can*
reference a variable, and `format!("taint-{added:02}")` broke because
masking correctly hid it. The compiler caught both occurrences. Masking
protects prose; it does not protect captures.
