//! [`BlockingInput`] — the genuinely untestable-without-a-live-TTY half
//! of [`crate::terminal::Terminal`], split into its own file specifically
//! so `--ignore-filename-regex` (see `.github/workflows/ci.yml`) can
//! exclude JUST this file from the 100%-coverage gate — the only such
//! exclusion in this workspace — without also losing coverage credit
//! for `Terminal`'s other, genuinely-tested methods (`is_tty`/`draw`/
//! `write_line`, which live in `terminal.rs` and stay fully counted).
//!
//! `read_key`/`read_line` block waiting for real keyboard input
//! (`crossterm::event::read()`, `stdin().read_line()`); calling either
//! from an automated test is unsafe in a way ordinary I/O isn't — if the
//! test process's stdin isn't already at EOF (true in this sandbox and
//! in CI, NOT guaranteed for a developer running `cargo test` at their
//! own interactive shell), the call blocks forever, hanging the whole
//! suite rather than just flaking one test. A pseudo-terminal-based test
//! harness could exercise this for real, but that's meaningfully heavier
//! dependency and test-infrastructure investment than this file
//! justifies. Every actual DECISION this crate makes (key mapping,
//! cursor movement, selection parsing, when to fall back to the prompt)
//! lives in `crate::keys`/`crate::render`/`crate::picker`, all fully
//! covered against a scripted fake — this file is deliberately just the
//! unavoidable glue, kept as small as possible.

use crate::keys::{decode_crossterm_key, Key};
use crate::terminal::RealTerminal;

/// The blocking half of [`crate::terminal::Terminal`] (a supertrait of
/// it) — split out so it alone can be coverage-excluded, see this
/// module's doc comment.
pub trait BlockingInput {
    /// Reads and decodes one keypress. Only ever called when `is_tty()`
    /// is true; may still error (e.g. a lost TTY mid-session), letting
    /// the caller degrade to the prompt fallback — matching the
    /// `RuntimeError` catch around Python's `_read_key()`.
    fn read_key(&mut self) -> std::io::Result<Key>;

    /// Prints `prompt` then reads one line from the numbered-prompt
    /// fallback. `None` on EOF/interrupt, matching Python's
    /// `except (EOFError, KeyboardInterrupt): return session`.
    fn read_line(&mut self, prompt: &str) -> Option<String>;
}

impl BlockingInput for RealTerminal {
    fn read_key(&mut self) -> std::io::Result<Key> {
        crossterm::terminal::enable_raw_mode()?;
        let result = loop {
            match crossterm::event::read()? {
                crossterm::event::Event::Key(k) => break Ok(decode_crossterm_key(k)),
                _ => continue,
            }
        };
        crossterm::terminal::disable_raw_mode()?;
        result
    }

    fn read_line(&mut self, prompt: &str) -> Option<String> {
        use std::io::Write;
        eprint!("{prompt}");
        std::io::stderr().flush().ok()?;
        let mut buf = String::new();
        match std::io::stdin().read_line(&mut buf) {
            Ok(0) => None,
            Ok(_) => Some(buf.trim_end_matches(['\n', '\r']).to_string()),
            Err(_) => None,
        }
    }
}
