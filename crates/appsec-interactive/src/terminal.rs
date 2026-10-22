//! The [`Terminal`] trait abstracting real interactive I/O — split out
//! specifically so [`crate::picker`]'s decision logic (cursor movement,
//! when to remediate, when to fall back to the numbered prompt) is
//! testable with a scripted fake, matching this project's established
//! `LlmClient`/`ToolExecutor`/`CheckpointStore` seam pattern. Blocking,
//! not async: unlike `ToolExecutor` (wrapped in `spawn_blocking` because
//! S4/S6 run many agent sessions concurrently), the interactive picker
//! is inherently a single foreground session — nothing else is competing
//! for the tokio runtime's worker threads while a human decides which
//! key to press, so a plain blocking call here costs nothing in practice.
//!
//! `Terminal`'s two genuinely blocking operations (`read_key`/
//! `read_line`) live on the separate [`crate::blocking_io::
//! BlockingInput`] supertrait instead of directly on `Terminal` — see
//! that module's doc comment for why (in short: it's the one file this
//! workspace excludes from its 100%-coverage gate, and splitting the
//! trait this way keeps that exclusion to only the two methods that
//! actually need it).

use std::io::IsTerminal;

use crate::blocking_io::BlockingInput;

/// Abstracts the picker's terminal I/O. `is_tty()` selects between the
/// arrow-key UI and the numbered-prompt fallback, mirroring Python's
/// `sys.stdin.isatty() and out.isatty()` check in `run_interactive`.
pub trait Terminal: BlockingInput {
    fn is_tty(&self) -> bool;

    /// Paints one full-screen arrow-key frame (already including the
    /// clear-screen sequence — see [`RealTerminal::draw`]).
    fn draw(&mut self, frame: &str) -> std::io::Result<()>;

    /// Writes one line (a trailing newline is added) to the plain,
    /// non-raw output stream — used for the numbered row list and the
    /// final session summary.
    fn write_line(&mut self, line: &str);
}

/// The real, crossterm-backed [`Terminal`] (+ [`BlockingInput`], see
/// `crate::blocking_io`). Thin by design: every decision this crate
/// makes lives in [`crate::keys`]/[`crate::render`]/[`crate::picker`],
/// all pure and unit-tested against a fake — this is just the
/// unavoidable glue.
#[derive(Debug, Default)]
pub struct RealTerminal;

impl Terminal for RealTerminal {
    fn is_tty(&self) -> bool {
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    }

    fn draw(&mut self, frame: &str) -> std::io::Result<()> {
        use std::io::Write;
        let mut out = std::io::stderr();
        write!(out, "\x1b[2J\x1b[H{frame}")?;
        out.flush()
    }

    fn write_line(&mut self, line: &str) {
        eprintln!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_terminal_is_tty_runs_both_checks_without_panicking() {
        // The actual boolean depends on the environment this test runs
        // in (CI/sandboxed processes are never TTYs; a developer's own
        // interactive terminal might be) — this only proves the check
        // itself runs cleanly, not which way it comes out.
        let _ = RealTerminal.is_tty();
    }

    #[test]
    fn real_terminal_is_debug_and_default() {
        let term = RealTerminal;
        assert_eq!(format!("{term:?}"), "RealTerminal");
        let _default: RealTerminal = Default::default();
    }

    #[test]
    fn real_terminal_draw_writes_without_error() {
        let mut term = RealTerminal;
        term.draw("a frame\n").unwrap();
    }

    #[test]
    fn real_terminal_write_line_does_not_panic() {
        let mut term = RealTerminal;
        term.write_line("a line");
    }
}
