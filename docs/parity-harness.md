# Parity harness

`crates/bc-parity-tests` cross-checks this Rust port against the real
Python `vvaharness` source for the pieces where behavioral equivalence can
be verified mechanically, instead of relying on hand-derived reference
values in each crate's own unit tests. Setup and usage: `parity/README.md`.

## Scope: why these four, not more

A research pass surveyed `vvaharness` for pieces worth cross-checking
automatically. Most of the codebase needs live LLM credentials to exercise
meaningfully (the scan/remediate/validate agent loops) or is UI/
orchestration with no single pure function to compare. Neither is a fit
for a mechanical oracle. Four pieces are:

- **CVSS scoring** (`vvaharness/report/cvss.py`): stdlib only, a fixed
  small metric alphabet, so the harness enumerates all 2592 valid CVSS 3.1
  base vectors exhaustively rather than sampling.
- **Redaction** (`vvaharness/report/redact.py`): stdlib only; the pattern
  space isn't enumerable, so the harness uses a curated table with at least
  one case per pattern and per false-positive guard.
- **Config merge / env-expansion** (`vvaharness/config/__init__.py`):
  needs `pyyaml` to import the module at all (even though the merge/expand
  functions under test don't touch YAML themselves); a curated table.
- **S11 fix-validation scoring** (`vvaharness/validation/scoring/`): needs
  `pydantic`+`typing_extensions`; the harness calls the real, shipped
  `vvaharness.validation.scoring.score_fix` through
  `parity/oracles/validation_scoring_oracle.py` (the package's own
  `__main__.py` CLI entry point this used to shell out to no longer
  exists) and enumerates all 5^4 = 625 gate-status combinations
  exhaustively, plus the missing-gate and duplicate-gate shape-error
  cases.

None of the four need network access or API keys, only a real Python
3.10+ (`vvaharness/pyproject.toml`'s own `requires-python`) and the three
packages `parity/setup.sh` installs (`pyyaml`, `pydantic`,
`typing_extensions`).

The harness never edits anything under the `vvaharness` checkout. It only
imports a handful of pure, already-unit-tested functions (the same
underscore-prefixed helpers `vvaharness`'s own `tests/test_config.py`
imports directly) from small oracle scripts in `parity/oracles/`, each run
as a subprocess.

## Why it isn't part of the standard coverage gate

Most crates in this workspace are held to 100%/100% line/function
coverage; eight have narrower, individually documented gates (see
[`coverage-exceptions.md`](coverage-exceptions.md)).
`bc-parity-tests` is deliberately excluded from that gate entirely: whether
its tests exercise anything depends on a Python venv that may not exist on
a given machine, which a coverage percentage can't express. A coverage
number here would either be meaningless (if measured with the venv absent,
every real assertion shows 0 hits) or misleadingly reassuring (if only ever
measured on the one machine that has the venv set up).

Instead, each test resolves the venv + `vvaharness` checkout at the top
(`tests/support/mod.rs::resolve`) and returns early (printing a `SKIPPED:`
note to stderr) when either is missing, so `cargo test --workspace` stays
green (fast, no real assertions run) on a machine that hasn't run
`parity/setup.sh`. Run `cargo test -p bc-parity-tests` explicitly (or grep
its output for `SKIPPED`) to confirm the checks actually ran rather than
silently passed.

CI does run it, in its own `parity` job: `.github/workflows/ci.yml` checks
out `visa/visa-vulnerability-agentic-harness` pinned to a specific commit
(not `main`: an upstream push must not fail this repo's CI for reasons
unrelated to any change here), builds the venv with `./parity/setup.sh`,
and greps the test output for `SKIPPED:`, failing the job if it finds one.
So the harness is excluded from the *coverage* gate, not from CI. Bump the
pinned commit deliberately: re-running against a newer `vvaharness` is
itself how real parity drift gets caught.

## Two real bugs this caught

Building this harness immediately paid for itself: the exhaustive S11
scoring sweep and a manual code-reading pass surfaced two genuine parity
bugs in `bc-validation-scoring`, both fixed in the same change:

1. **`MergeReadiness::as_str()` wire strings didn't match Python's.** The
   Rust port emitted `"ReadyWithConditions"` / `"NotReady"` (PascalCase, no
   spaces); the Python original's actual wire vocabulary
   (`vvaharness/validation/enums/readiness.py`) is `"Ready with
   Conditions"` / `"Not Ready"` (spaced). This value flows into
   `bc-sarif`'s `ResultProperties.merge_readiness` field. Any downstream
   consumer of the emitted SARIF expecting the Python original's exact
   strings would have seen different values from the Rust port.
2. **`round_to`'s rounding didn't match Python's `round()`.** The original
   implementation, `(x * 10^decimals).round() / 10^decimals`, introduces
   its own floating-point error in the multiply step. For example, the
   true value of a renormalized score can be `0.8766499999999999...`,
   which correctly rounds to `0.8766`, but multiplying by `10000.0`
   first rounds the *intermediate* product up to exactly `8766.5`, which
   then rounds away from zero to `8767`. Reimplemented via
   `format!("{x:.4}")` (a correctly-rounded decimal conversion using
   ties-to-even, the same rule Python's `round()` uses), which matches
   exactly. This affected roughly 3.7% of the 625 enumerated gate-status
   combinations (23 of 625). That was small enough that the crate's own
   hand-picked unit tests, using a `1e-4` tolerance exactly the size of
   the error, happened to pass anyway. The exhaustive, exact-comparison
   sweep in this harness is what surfaced it.

## Environment note (macOS, this session)

Setting this up on this machine hit an unrelated, pre-existing Homebrew
issue: `python@3.14`'s bottled `pyexpat` failed to import
(`Symbol not found: _XML_SetAllocTrackerActivationThreshold`). This is a
known macOS 26.1 libexpat/Python incompatibility
([Homebrew/homebrew-core#277330](https://github.com/Homebrew/homebrew-core/issues/277330)),
unrelated to this project. Fixed via the issue's documented workaround
(`install_name_tool` to repoint `pyexpat.so` at Homebrew's own `expat`
instead of the system one, then `codesign --sign -` to re-sign it). No
uninstall/reinstall of `python@3.14`, `llvm`, or `rust` was needed.
