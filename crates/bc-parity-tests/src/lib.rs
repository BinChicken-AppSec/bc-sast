//! Not part of the shipped product — a cross-check harness that runs the
//! real Python `vvaharness` source (never modified, only imported) and
//! compares its output against this workspace's own crates for the pieces
//! where behavioral equivalence can be verified mechanically: CVSS scoring
//! (`bc-cvss`), redaction (`bc-redact`), config merge/env-expansion
//! (`bc-config`), and S11 fix-validation scoring (`bc-validation-scoring`).
//!
//! See `../../parity/README.md` for setup. All logic lives under `tests/` —
//! this crate has no public API of its own. Deliberately excluded from the
//! workspace's 100%-coverage gate (see `docs/parity-harness.md`): whether
//! these tests exercise anything at all depends on a Python venv that may
//! not exist on a given machine, which coverage percentage can't express.
