# Contributing

Thanks for looking. This is a security tool, so the bar for merging is
deliberately high and most of it is automated.

## Reporting a vulnerability

Do not open a public issue. Follow [`SECURITY.md`](SECURITY.md), which
routes reports through a private GitHub Security Advisory.

## Building and testing

```sh
cargo build --release -p bc-cli
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo deny check advisories bans licenses sources
```

`bc-parity-tests` cross-checks this port against the original Python
harness and needs a Python virtual environment. See
[`docs/parity-harness.md`](docs/parity-harness.md). Exclude it when you do
not have one: `cargo test --workspace --exclude bc-parity-tests`.

## What a change has to clear

- **Coverage.** The workspace is held to 100% line and function coverage.
  Eleven crates plus one file carry their own lower thresholds, each with a
  written rationale in
  [`docs/coverage-exceptions.md`](docs/coverage-exceptions.md). Adding a
  new exception means adding its rationale too, with the evidence.
- **No new third-party dependencies without vetting.** The policy is in
  [`docs/supply-chain.md`](docs/supply-chain.md): a crate must be at least
  30 days old, have real adoption, and be justified in a comment next to
  the pin. Workspace-internal crates are exempt.
- **Tests that fail before the fix.** For a bug fix, say in the pull
  request which test fails on the old code and passes on the new one.
- **Documentation that matches the code.** A behavior change updates the
  documents that describe it. Flags must exist in the CLI arguments,
  configuration keys must exist in the defaults.

## Style

- **Australian English**, and no em-dashes or en-dashes in prose. Restructure the
  sentence instead: a colon for a label, commas or parentheses for an
  aside, or two sentences.
- Prose in Markdown wraps at about 76 to 80 columns.
- Prompt strings and report text are user-facing. Changing one usually
  means updating a test that asserts it.

## Pull requests

Keep them scoped to one thing. Explain what changed and why, and say what
you could not verify. Honest uncertainty is more useful than confident
hand-waving, particularly in a tool whose output people act on.
