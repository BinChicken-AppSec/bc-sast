# Parity harness

`crates/appsec-parity-tests` cross-checks this Rust port against the real
Python `vvaharness` source for the pieces where behavioral equivalence can
be verified mechanically, instead of relying on hand-derived reference
values in each crate's own unit tests. Setup and usage: `parity/README.md`.

## Scope: why these four, not more

Most of `vvaharness` needs live LLM credentials to exercise meaningfully
(the scan/remediate/validate agent loops), or is UI and orchestration with
no single pure function to compare. Neither is a fit for a mechanical
oracle. Four pieces are:

- **CVSS scoring** (`vvaharness/report/cvss.py`): stdlib only, a fixed
  small metric alphabet, so the harness enumerates all 2592 valid CVSS 3.1
  base vectors exhaustively rather than sampling.
- **Redaction** (`vvaharness/report/redact.py`): stdlib only; the pattern
  space is not enumerable, so the harness uses a curated table with at
  least one case per pattern and per false-positive guard.
- **Config merge / env-expansion** (`vvaharness/config/__init__.py`):
  needs `pyyaml` to import the module at all, even though the merge and
  expand functions under test do not touch YAML themselves; a curated
  table.
- **S11 fix-validation scoring** (`vvaharness/validation/scoring/`): needs
  `pydantic` and `typing_extensions`; the harness calls the real, shipped
  `vvaharness.validation.scoring.score_fix` through
  `parity/oracles/validation_scoring_oracle.py` and enumerates all
  5^4 = 625 gate-status combinations exhaustively, plus the missing-gate
  and duplicate-gate shape-error cases.

None of the four need network access or API keys, only a real Python
3.10+ (`vvaharness/pyproject.toml`'s own `requires-python`) and the three
packages `parity/setup.sh` installs (`pyyaml`, `pydantic`,
`typing_extensions`).

The harness never edits anything under the `vvaharness` checkout. It only
imports a handful of pure, already-unit-tested functions (the same
underscore-prefixed helpers `vvaharness`'s own `tests/test_config.py`
imports directly) from small oracle scripts in `parity/oracles/`, each run
as a subprocess.

## What the harness pins

Two behaviors in `appsec-validation-scoring` that the port can only get
right by matching Python exactly, and that the exhaustive sweeps above
hold in place:

- `MergeReadiness::as_str()`'s wire vocabulary is `"Ready with
  Conditions"` and `"Not Ready"`, spaced, matching
  `vvaharness/validation/enums/readiness.py`. This value flows into
  `appsec-sarif`'s `ResultProperties.merge_readiness` field, so a
  downstream consumer of the emitted SARIF sees the Python original's
  exact strings.
- `round_to` goes through `format!("{x:.4}")`, a correctly rounded decimal
  conversion using ties-to-even, the same rule Python's `round()` uses.
  Scaling by a power of ten and calling `.round()` instead introduces its
  own floating-point error in the multiply step: the true value of a
  renormalized score can be `0.8766499999999999...`, which correctly
  rounds to `0.8766`, but multiplying by `10000.0` first rounds the
  *intermediate* product up to exactly `8766.5`, which then rounds away
  from zero to `8767`.

## Why it isn't part of the standard coverage gate

Most crates in this workspace are held to 100%/100% line/function
coverage; eleven have narrower, individually documented gates (see
[`coverage-exceptions.md`](coverage-exceptions.md)).
`appsec-parity-tests` is deliberately excluded from that gate entirely:
whether its tests exercise anything depends on a Python venv that may not
exist on a given machine, which a coverage percentage cannot express. A
coverage number here would either be meaningless, if measured with the venv
absent, because every real assertion shows 0 hits, or misleadingly
reassuring, if only ever measured on the one machine that has the venv set
up.

Instead, each test resolves the venv and `vvaharness` checkout at the top
(`tests/support/mod.rs::resolve`) and returns early, printing a `SKIPPED:`
note to stderr, when either is missing, so `cargo test --workspace` stays
green on a machine that has not run `parity/setup.sh`. Run
`cargo test -p appsec-parity-tests` explicitly, or grep its output for
`SKIPPED`, to confirm the checks actually ran rather than silently passed.

CI does run it, in its own `parity` job: `.github/workflows/ci.yml` checks
out `visa/visa-vulnerability-agentic-harness` pinned to a specific commit
rather than `main`, so an upstream push cannot fail this repo's CI for
reasons unrelated to any change here. The job builds the venv with
`./parity/setup.sh` and greps the test output for `SKIPPED:`, failing if it
finds one. So the harness is excluded from the *coverage* gate, not from
CI. Bump the pinned commit deliberately: re-running against a newer
`vvaharness` is itself how real parity drift gets caught.

## Troubleshooting: `pyexpat` fails to import on macOS

Building the venv on macOS can hit a Homebrew issue unrelated to this
project: `python@3.14`'s bottled `pyexpat` fails to import with
`Symbol not found: _XML_SetAllocTrackerActivationThreshold`. It is a known
macOS 26.1 libexpat/Python incompatibility, tracked as
[Homebrew/homebrew-core#277330](https://github.com/Homebrew/homebrew-core/issues/277330).

Apply that issue's documented workaround: `install_name_tool` to repoint
`pyexpat.so` at Homebrew's own `expat` rather than the system one, then
`codesign --sign -` to re-sign it. Reinstalling `python@3.14` does not help,
so reach for the workaround rather than the toolchain.
