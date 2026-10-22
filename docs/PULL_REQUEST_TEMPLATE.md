## What this changes

<!-- One or two sentences. What behavior is different after this merges? -->

## Why

<!-- The problem, not the patch. If it fixes a bug, describe the bug. -->

## How it was verified

<!-- For a bug fix, name the test that fails on the old code and passes on
     the new one. For a behavior change, say what you ran. -->

- [ ] `cargo test --workspace --exclude appsec-parity-tests` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo fmt --all --check` is clean
- [ ] Coverage holds, or a new exception is documented in
      `docs/coverage-exceptions.md` with its rationale
- [ ] Documentation updated if behavior, a flag, or a config key changed

## Anything you could not verify

<!-- Say what you did not test. -->
