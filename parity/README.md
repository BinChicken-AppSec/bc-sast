# Parity harness

Cross-checks this Rust port against the real Python `vvaharness` source for
the pieces where behavioral equivalence can be verified mechanically: CVSS
scoring, PII/secret redaction, config merge/env-expansion, and S11
fix-validation scoring.

This never edits anything under the `visa-vulnerability-agentic-harness`
checkout. It only *imports* a handful of its pure, already-unit-tested
functions (the same underscore-prefixed helpers `vvaharness`'s own
`tests/test_config.py` imports directly, plus
`vvaharness.validation.scoring`'s public `score_fix`/`derive_merge_readiness`)
from small oracle scripts that live entirely in this directory and are each
run as a subprocess. There is no CLI shell-out: the
`python3 -m vvaharness.validation.scoring` entry point this used to invoke
no longer exists upstream, so `oracles/validation_scoring_oracle.py` calls
the same functions that CLI called.

## Setup

Needs a real Python 3.10+ (`vvaharness/pyproject.toml`'s own
`requires-python`). Then:

```sh
./setup.sh                # uses `python3` on PATH
./setup.sh /path/to/python3.12   # or point at a specific interpreter
```

This creates `.venv` here with `pyyaml`/`pydantic`/`typing_extensions`
installed, the same three packages a prior research pass identified as the
minimum needed to import `vvaharness.config` and
`vvaharness.validation.scoring` without running a real scan (no network, no
API keys, no `pip install -e .` of vvaharness itself).

## Running

```sh
cargo test -p bc-parity-tests
```

That is usually all you need: the venv and the harness checkout are both
located from defaults that assume the common layout (this repo's own
`parity/.venv`, built by `./setup.sh`, and a sibling
`visa-vulnerability-agentic-harness` checkout next to this repository). See
`crates/bc-parity-tests/tests/support/mod.rs` for exactly where it looks.

To point either somewhere else, set `BC_PARITY_PYTHON` or `BC_PARITY_REPO`
to an **absolute** path:

```sh
BC_PARITY_PYTHON=/abs/path/to/.venv/bin/python3 \
BC_PARITY_REPO=/abs/path/to/visa-vulnerability-agentic-harness \
  cargo test -p bc-parity-tests
```

A relative value is resolved against the test process's own working
directory, which cargo sets to `crates/bc-parity-tests` rather than to
wherever you typed the command. That is easy to get wrong, and it fails as
a silent skip rather than an error, so use absolute paths. (CI does the
same thing with `${{ github.workspace }}`.)

If either the venv or the harness checkout isn't where expected, the tests
print a note to stderr and skip (pass without asserting anything) rather
than failing, so `cargo test --workspace` stays green on a machine that
hasn't run `setup.sh`. Run the command above explicitly, and check stderr
for "SKIPPED", to confirm the checks actually ran.

## Why these four, not more

See the research notes folded into `docs/parity-harness.md` for the full
scope discussion. In short: CVSS scoring and redaction are stdlib-only pure
functions; config merge and S11 validation scoring need `pyyaml` /
`pydantic`+`typing_extensions` respectively but no network or API keys.
Everything else in `vvaharness` either needs live LLM credentials to
exercise meaningfully (the actual scan/remediate/validate agent loops) or is
a UI/orchestration concern with no single pure function to compare against.
