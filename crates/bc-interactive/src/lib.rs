//! Phase 2's `-i`/`--interactive` finding picker: an arrow-key terminal
//! menu (numbered-prompt fallback on a non-TTY stream) for choosing
//! which findings to remediate one at a time, ported from
//! `remediation_agent/interactive/{keys,render,loop}.py`.
//!
//! **Deliberate divergence from the Python original**: "done" status
//! comes from [`bc_stage_s10::checkpoint_done`] (a checkpoint whose
//! stored finding-identity still matches), not a `<!--
//! remediation-agent:done -->` marker written into a rendered Markdown
//! report file. Python's standalone `vvaharness remediate` command
//! re-parses a prior scan's report from disk on every invocation, so it
//! needs an in-file marker to remember state across separate process
//! runs; this port's picker runs in-process against an already-in-memory
//! `FinalReport` (see `bc-stage-s10`'s own module doc comment — there is
//! no render-then-reparse cycle here at all), and already has a real
//! persistence mechanism in the checkpoint store. Reusing it as the
//! single source of "already done" is more consistent than inventing a
//! second, parallel on-disk format for this one UI.
//!
//! Split into focused modules, each independently unit-tested:
//! - [`keys`] — crossterm key-event decoding (pure).
//! - [`render`] — row/frame rendering + numbered-prompt selection
//!   parsing (pure).
//! - [`terminal`] — the [`terminal::Terminal`] trait (`is_tty`/`draw`/
//!   `write_line`) + its real, crossterm-backed implementation.
//! - [`blocking_io`] — `Terminal`'s supertrait for its two genuinely
//!   blocking operations (`read_key`/`read_line`), split out
//!   specifically so this workspace's coverage gate can exclude just
//!   this one file (see its own module doc comment) rather than
//!   `terminal.rs`'s already-tested methods too.
//! - [`picker`] — the actual loop, driven through the `Terminal` trait so
//!   it's fully testable against a scripted fake.

mod blocking_io;
mod keys;
mod picker;
mod render;
mod terminal;

pub use blocking_io::BlockingInput;
pub use keys::{decode_crossterm_key, Key};
pub use picker::{run_interactive, PickerFinding, RemediationContext, ValidateContext};
pub use render::{parse_selection, render_frame, render_rows, Row};
pub use terminal::{RealTerminal, Terminal};
