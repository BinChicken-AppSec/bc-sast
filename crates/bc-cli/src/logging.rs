//! `--log-file`/`--log-stderr`/`--verbose`/`RUST_LOG` wiring for
//! `tracing` (task #74). Genuinely new capability, not a port: the
//! Python original's own "observability" was ad-hoc
//! `print(..., file=sys.stderr)` diagnostics with no real level scheme.
//!
//! Logs started out file-only, and the reason was real. Two pieces of UI
//! redraw in place while a scan runs, and both write to **stderr**: the
//! progress bar (`indicatif`'s `MultiProgress` draws to stderr by
//! default, see `progress.rs`) and the `--interactive` picker
//! (`bc_interactive::terminal::RealTerminal::draw`). A log line landing
//! in the middle of either one corrupts the frame, so logs went to a
//! file and nowhere else.
//!
//! The cost was that a scan running in CI showed nothing at all until it
//! finished and somebody downloaded an artifact. For a twenty-minute run
//! that is the difference between a tool an operator can watch and a
//! black box (see `bc_llm_agentic::session`'s retry warning, written
//! after a run spent eighty minutes retrying a provider error in total
//! silence).
//!
//! Both redrawing UIs already stand down when stderr is not a terminal.
//! `indicatif`'s stderr draw target hides itself outright in that case
//! (`ProgressDrawTarget::term` reports `is_hidden` for a non-terminal),
//! and the picker's own `is_tty()` (`stdin().is_terminal() &&
//! stderr().is_terminal()`) falls back to a numbered prompt that only
//! appends lines. So `stderr().is_terminal()` is the entire
//! discriminator: when it is false nothing owns the display, there is no
//! frame to corrupt, and logs can stream. That is exactly the CI case.
//! No `CI`/`GITHUB_ACTIONS` environment sniffing is involved; this is
//! the same `std::io::IsTerminal` check both of those already make,
//! applied to the stream that actually gets redrawn.
//!
//! Worth knowing when reading `progress.rs` next to this: its
//! `should_render` gates on **stdout** while `indicatif` draws to
//! stderr, so the two disagree in the one case where stdout is a
//! terminal and stderr is redirected. That is harmless, because the bar
//! hides itself on the non-terminal stderr regardless, and it is the
//! reason this module tests stderr itself rather than reusing
//! `should_render`'s answer.
//!
//! Every formatted event is passed through [`bc_redact::redact`] before
//! it reaches either destination ([`Redacting`]), as Python's
//! `util/logs.py` `_RedactingFormatter` does for every record. A log file
//! is exactly the kind of artifact that gets uploaded from CI and kept,
//! and a `tracing` field can carry anything a stage had in hand (a URL
//! with a token in it, a model reply quoting a secret from the repo).

use std::io::{IsTerminal, Write};
use std::path::Path;

use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriter, MakeWriterExt};
use tracing_subscriber::EnvFilter;

/// Maps `-v`'s repeat count to a fallback level directive, used only when
/// `RUST_LOG` isn't set in the environment. `RUST_LOG`, when present,
/// always wins (see [`build_filter`]), since it can express per-module
/// filtering (`RUST_LOG=bc_stage_s4=debug`) a single global `-v` count
/// can't.
///
/// The same table drives both destinations, so `-v` means one thing
/// everywhere. `WARN` stays the default for the stderr stream too, and
/// deliberately so: every `tracing::warn!` in this workspace marks an
/// exceptional path (a skipped third-party file, a clamped S4 vote
/// threshold, a transient LLM error being retried), so a healthy scan
/// emits none of them and a stuck one emits the line that explains
/// itself. `INFO` is where the per-stage summaries live, which is useful
/// to watch on purpose (`-v`) but is not the right thing to force on
/// every run.
fn verbosity_directive(verbose: u8) -> &'static str {
    match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    }
}

/// `true` when logs should stream to stderr. Split from [`init_logging`]
/// so the real `is_terminal()` check, which is never `true` under
/// `cargo test`'s captured output and so cannot be driven both ways any
/// other way, arrives here as a plain `bool`. Mirrors
/// `progress::should_render_impl`'s split, for the same reason.
///
/// `log_stderr` is the explicit ask and wins everywhere: it is the only
/// way to get logs onto a real terminal, and the only way to get both
/// destinations at once. Without it, streaming turns itself on exactly
/// when no `--log-file` was given and nothing owns the terminal.
/// `--log-file` suppresses the automatic case outright, so passing it
/// behaves exactly as it did before stderr streaming existed.
fn should_stream_to_stderr(has_log_file: bool, log_stderr: bool, stderr_is_terminal: bool) -> bool {
    log_stderr || (!has_log_file && !stderr_is_terminal)
}

/// The writer the subscriber should use, or `None` when there is nothing
/// to write to and no subscriber should be installed at all. Both
/// destinations at once are supported rather than refused: the file is
/// the durable artifact and stderr is the live view, and an operator who
/// wants a scan they can both watch and keep afterwards should not have
/// to choose. `MakeWriterExt::and` tees one formatted line to both.
///
/// Split out from [`install`] so all four combinations are testable
/// without racing for the process-wide subscriber slot (see
/// [`init_logging`]'s own doc comment). Whatever the destinations, the
/// result redacts ([`Redacting`]).
fn make_writer(file: Option<std::fs::File>, to_stderr: bool) -> Option<BoxMakeWriter> {
    let raw = match (file, to_stderr) {
        (None, false) => return None,
        (Some(file), false) => BoxMakeWriter::new(file),
        (None, true) => BoxMakeWriter::new(std::io::stderr),
        (Some(file), true) => BoxMakeWriter::new(file.and(std::io::stderr)),
    };
    Some(BoxMakeWriter::new(Redacting(raw)))
}

/// A [`MakeWriter`] that redacts whatever the wrapped one would have
/// received.
///
/// `tracing-subscriber`'s fmt layer formats a whole event into one buffer,
/// asks for a fresh writer, writes the buffer and drops the writer. So a
/// [`RedactingWriter`] sees exactly one event: it holds every byte back
/// until it is flushed or dropped and then redacts the event as a whole.
/// Redacting per `write` call instead could miss a secret split across
/// two calls, and per line would miss a multi-line one (a PEM key).
struct Redacting<M>(M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for Redacting<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.0.make_writer(),
            pending: Vec::new(),
        }
    }
}

struct RedactingWriter<W: Write> {
    inner: W,
    pending: Vec<u8>,
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Redacts and forwards everything held back so far. A no-op write
    /// when nothing is pending, so the flush-then-drop sequence does not
    /// emit twice.
    fn flush(&mut self) -> std::io::Result<()> {
        if !self.pending.is_empty() {
            let redacted = bc_redact::redact(&String::from_utf8_lossy(&self.pending));
            self.pending.clear();
            self.inner.write_all(redacted.as_bytes())?;
        }
        self.inner.flush()
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    /// Logging is best-effort (see [`init_logging`]), so a failed final
    /// write is dropped rather than panicking inside a `Drop`.
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// The level filter, given whatever `RUST_LOG` holds. Reproduces
/// [`EnvFilter::try_from_default_env`] with the environment read by the
/// caller instead of inside the constructor, so the precedence rule
/// itself is testable without mutating a process-wide variable that
/// every parallel test shares. A `RUST_LOG` that is set but unparseable
/// falls back to `-v` exactly as it did before.
fn build_filter(rust_log: Option<&str>, verbose: u8) -> EnvFilter {
    rust_log
        .and_then(|directives| EnvFilter::try_new(directives).ok())
        .unwrap_or_else(|| EnvFilter::new(verbosity_directive(verbose)))
}

/// Opens `log_file` if one was asked for and installs the subscriber for
/// whatever destinations that leaves. ANSI is off on both: the file has
/// never carried escape codes, and a CI console renders plain text
/// perfectly well while `grep` over a downloaded log prefers it.
///
/// Takes the already-made stream decision rather than making it, so
/// [`should_stream_to_stderr`] stays testable on its own.
fn install(log_file: Option<&Path>, verbose: u8, to_stderr: bool) -> Result<(), String> {
    let file = match log_file {
        Some(path) => {
            Some(std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?)
        }
        None => None,
    };
    let Some(writer) = make_writer(file, to_stderr) else {
        return Ok(());
    };
    let rust_log = std::env::var(EnvFilter::DEFAULT_ENV).ok();
    let filter = build_filter(rust_log.as_deref(), verbose);
    let _ = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_env_filter(filter)
        .try_init();
    Ok(())
}

/// Installs the global `tracing` subscriber for this process, writing to
/// `log_file`, to stderr, to both, or to nothing at all. See
/// [`should_stream_to_stderr`] for which of the four it picks and this
/// module's own doc comment for why stderr is gated on being a terminal.
///
/// Uses `try_init` rather than `init` (which panics on a second call
/// within the same process) so this stays safely callable from tests
/// that exercise the real file-open + filter-build path without
/// permanently wedging every other test sharing the same test binary.
/// A second (or racing) call losing the global-subscriber slot is
/// treated as a harmless no-op, matching this project's established
/// "progress/observability reporting is best-effort, never something
/// that should fail the scan" convention (see `bc_pipeline_core::emit`).
pub fn init_logging(log_file: Option<&Path>, verbose: u8, log_stderr: bool) -> Result<(), String> {
    let to_stderr = should_stream_to_stderr(
        log_file.is_some(),
        log_stderr,
        std::io::stderr().is_terminal(),
    );
    install(log_file, verbose, to_stderr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_to_write_to_installs_nothing() {
        assert_eq!(install(None, 0, false), Ok(()));
    }

    #[test]
    fn an_unwritable_path_is_an_error() {
        let err = init_logging(Some(Path::new("/nonexistent/dir/log.txt")), 0, false).unwrap_err();
        assert!(err.contains("log.txt"));
    }

    #[test]
    fn a_writable_path_succeeds_regardless_of_subscriber_install_order() {
        // Exercises the real file-create + filter-build + try_init path.
        // Whether this specific call wins the global-subscriber slot
        // depends on test execution order within the shared binary (see
        // this module's own doc comment). Either way `init_logging`
        // returns `Ok(())` once the file itself was created, so this
        // assertion is stable regardless of ordering.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.log");
        assert_eq!(init_logging(Some(&path), 2, false), Ok(()));
        assert!(path.exists());
    }

    /// Every combination that includes stderr is exercised through
    /// [`make_writer`] rather than [`install`] on purpose: reaching
    /// `try_init` with a stderr writer could win the process-wide
    /// subscriber slot and then spray every other test's warnings past
    /// `cargo test`'s output capture.
    #[test]
    fn make_writer_covers_all_four_destination_combinations() {
        let dir = tempfile::tempdir().unwrap();
        let open = || std::fs::File::create(dir.path().join("scan.log")).unwrap();
        assert!(make_writer(None, false).is_none());
        assert!(make_writer(Some(open()), false).is_some());
        assert!(make_writer(None, true).is_some());
        assert!(make_writer(Some(open()), true).is_some());
    }

    fn github_token() -> String {
        format!("ghp_{}", "a".repeat(36))
    }

    #[test]
    fn a_redacting_writer_masks_a_secret_split_across_writes_when_dropped() {
        let make = Redacting(std::sync::Mutex::new(Vec::new()));
        let token = github_token();
        {
            let mut writer = make.make_writer();
            let (head, tail) = token.split_at(10);
            write!(writer, "WARN clone failed for https://x:{head}").unwrap();
            writeln!(writer, "{tail}@github.com/o/r").unwrap();
            // Held back until the event is complete.
            assert!(!writer.pending.is_empty());
        }
        let out = String::from_utf8(make.0.into_inner().unwrap()).unwrap();
        assert!(!out.contains(&token), "{out}");
        assert!(out.starts_with("WARN clone failed"), "{out}");
    }

    #[test]
    fn flushing_emits_once_and_a_later_drop_adds_nothing() {
        let make = Redacting(std::sync::Mutex::new(Vec::new()));
        let mut writer = make.make_writer();
        writer.write_all(b"plain line\n").unwrap();
        writer.flush().unwrap();
        writer.flush().unwrap();
        drop(writer);
        assert_eq!(make.0.into_inner().unwrap(), b"plain line\n");
    }

    /// End to end through a real `fmt` subscriber (scoped to this thread,
    /// so the process-wide slot is untouched): a secret in a message field
    /// never reaches the destination.
    #[test]
    fn events_logged_through_the_subscriber_are_redacted() {
        let sink: &'static std::sync::Mutex<Vec<u8>> =
            Box::leak(Box::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Redacting(move || sink.make_writer()))
            .with_ansi(false)
            .finish();
        let token = github_token();
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("retrying with token {token}");
        });
        let out = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        assert!(out.contains("retrying with token"), "{out}");
        assert!(!out.contains(&token), "{out}");
    }

    #[rstest::rstest]
    // A log file is the pre-existing behavior, kept exactly: the file is
    // the only destination whether or not stderr is a terminal.
    #[case(true, false, true, false)]
    #[case(true, false, false, false)]
    // No log file on a real terminal stays silent, because the progress
    // bar and the `--interactive` picker redraw there.
    #[case(false, false, true, false)]
    // No log file and no terminal is the CI case: nothing can be
    // corrupted, so the scan becomes watchable.
    #[case(false, false, false, true)]
    // `--log-stderr` is the explicit ask and wins in all four.
    #[case(false, true, true, true)]
    #[case(false, true, false, true)]
    #[case(true, true, true, true)]
    #[case(true, true, false, true)]
    fn should_stream_to_stderr_cases(
        #[case] has_log_file: bool,
        #[case] log_stderr: bool,
        #[case] stderr_is_terminal: bool,
        #[case] expected: bool,
    ) {
        assert_eq!(
            should_stream_to_stderr(has_log_file, log_stderr, stderr_is_terminal),
            expected
        );
    }

    #[rstest::rstest]
    #[case(0, "warn")]
    #[case(1, "info")]
    #[case(2, "debug")]
    #[case(3, "trace")]
    #[case(255, "trace")]
    fn verbosity_directive_cases(#[case] verbose: u8, #[case] expected: &str) {
        assert_eq!(verbosity_directive(verbose), expected);
    }

    /// `RUST_LOG` keeps the precedence it has always had: a parseable
    /// value wins over any `-v` count, including `-vvv`.
    #[test]
    fn rust_log_takes_precedence_over_the_verbosity_fallback() {
        let filter = build_filter(Some("bc_stage_s4=debug,warn"), 3).to_string();
        assert!(filter.contains("bc_stage_s4=debug"), "{filter}");
        assert!(!filter.contains("trace"), "{filter}");
    }

    #[test]
    fn an_unset_rust_log_falls_back_to_the_verbosity_directive() {
        assert_eq!(build_filter(None, 1).to_string(), "info");
    }

    #[test]
    fn an_unparseable_rust_log_falls_back_to_the_verbosity_directive() {
        assert_eq!(build_filter(Some("=====,"), 2).to_string(), "debug");
    }
}
