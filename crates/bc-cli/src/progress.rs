//! `--no-progress`'s counterpart: a live terminal progress-bar renderer
//! consuming the [`bc_pipeline_core::ScanEvent`] stream (task #75). Owns
//! the terminal exclusively while a scan runs — structured logs go to
//! `--log-file` instead (see `logging.rs`'s own doc comment), never
//! interleaved with this. Not a port — the Python original has no
//! equivalent UI.

use std::io::IsTerminal;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::Duration;

use bc_pipeline_core::{ProgressSink, ScanEvent};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::estimate::with_commas;

/// `true` when a progress bar should render. Split from [`should_render`]
/// so the real `is_terminal()` check (never `true` under `cargo test`'s
/// captured output, so untestable as a literal branch outcome any other
/// way) can be injected as a plain `bool` in tests instead.
fn should_render_impl(no_progress: bool, is_tty: bool) -> bool {
    !no_progress && is_tty
}

/// `true` unless `--no-progress` was passed or stdout isn't a real
/// terminal (piped output, CI logs — auto-disabled the same way `cargo`/
/// `npm`'s own progress bars are, so ANSI control codes never leak into a
/// non-interactive log).
pub fn should_render(no_progress: bool) -> bool {
    should_render_impl(no_progress, std::io::stdout().is_terminal())
}

/// Creates the event channel and spawns the rendering thread — a real OS
/// thread, not a tokio task, since `indicatif`'s API is synchronous/
/// blocking and must never share the async runtime's worker threads.
/// Returns the [`ProgressSink`] half for `ScanConfig::progress` and a
/// [`JoinHandle`] the caller must join AFTER the scan completes (so the
/// bar has already cleared itself before the final summary line prints).
/// Joining terminates promptly because the sink is dropped along with
/// `ScanConfig` once `run_scan` returns, which disconnects the channel
/// and ends the render loop.
pub fn spawn() -> (ProgressSink, JoinHandle<()>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || render_loop(rx));
    (tx, handle)
}

/// `main_impl`'s own wiring: when `enabled`, spawns the render thread and
/// sets `config.progress` to its sink, returning the handle to join after
/// the scan completes; `None` (a full no-op) otherwise. Split out from
/// `should_render`'s own real-terminal check specifically so this half —
/// the actual channel/config wiring — stays unit-testable without a real
/// terminal, which `enabled` alone can never be under `cargo test`'s
/// captured stdout (see `should_render`'s own doc comment).
pub fn wire(config: &mut bc_orchestrator::ScanConfig, enabled: bool) -> Option<JoinHandle<()>> {
    if !enabled {
        return None;
    }
    let (tx, handle) = spawn();
    config.progress = Some(tx);
    Some(handle)
}

#[derive(Default)]
struct State {
    stage: &'static str,
    findings: usize,
    prompt_tokens: i64,
    completion_tokens: i64,
}

impl State {
    fn message(&self) -> String {
        let stage = if self.stage.is_empty() {
            "starting"
        } else {
            self.stage
        };
        format!(
            "{stage} | findings: {} | tokens: {}",
            self.findings,
            with_commas(self.prompt_tokens + self.completion_tokens),
        )
    }
}

fn render_loop(rx: Receiver<ScanEvent>) {
    let multi = MultiProgress::new();

    let stage_bar = multi.add(ProgressBar::new_spinner());
    stage_bar.set_style(
        ProgressStyle::with_template("{spinner:.cyan} [{elapsed_precise}] {msg}")
            .expect("static template is always valid"),
    );
    stage_bar.enable_steady_tick(Duration::from_millis(100));

    let chunk_bar = multi.add(ProgressBar::new(0));
    chunk_bar.set_style(
        ProgressStyle::with_template("  chunk {bar:30.blue/white} {pos}/{len}")
            .expect("static template is always valid"),
    );

    let mut state = State::default();
    stage_bar.set_message(state.message());

    while let Ok(event) = rx.recv() {
        match event {
            ScanEvent::StageStarted { stage } => {
                state.stage = stage;
                chunk_bar.set_position(0);
                chunk_bar.set_length(0);
                stage_bar.set_message(state.message());
            }
            ScanEvent::StageFinished { .. } => {}
            ScanEvent::ChunkProgress {
                completed, total, ..
            } => {
                chunk_bar.set_length(total as u64);
                chunk_bar.set_position(completed as u64);
            }
            ScanEvent::FindingsCount { count, .. } => {
                state.findings = count;
                stage_bar.set_message(state.message());
            }
            ScanEvent::UsageUpdate {
                prompt_tokens,
                completion_tokens,
                ..
            } => {
                state.prompt_tokens += prompt_tokens;
                state.completion_tokens += completion_tokens;
                stage_bar.set_message(state.message());
            }
        }
    }
    chunk_bar.finish_and_clear();
    stage_bar.finish_and_clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_progress_flag_always_wins_over_a_real_terminal() {
        assert!(!should_render_impl(true, true));
        assert!(!should_render_impl(true, false));
    }

    #[test]
    fn a_non_terminal_disables_rendering_even_without_the_flag() {
        assert!(!should_render_impl(false, false));
    }

    #[test]
    fn a_real_terminal_without_the_flag_enables_rendering() {
        assert!(should_render_impl(false, true));
    }

    #[test]
    fn should_render_reflects_the_real_stdout_under_the_captured_test_harness() {
        // `cargo test` captures stdout, so it's never a real terminal here
        // — this exercises `should_render`'s own real `is_terminal()` call
        // (not just the injectable `_impl` helper above) without being
        // able to assert a specific outcome for it, since that's
        // environment-dependent by definition.
        let _ = should_render(false);
        assert!(!should_render(true));
    }

    #[test]
    fn state_message_defaults_to_starting_before_any_stage_event() {
        let state = State::default();
        assert_eq!(state.message(), "starting | findings: 0 | tokens: 0");
    }

    #[test]
    fn state_message_reflects_stage_findings_and_combined_tokens() {
        let state = State {
            stage: "s4-deepdive",
            findings: 7,
            prompt_tokens: 1000,
            completion_tokens: 500,
        };
        assert_eq!(state.message(), "s4-deepdive | findings: 7 | tokens: 1,500");
    }

    #[test]
    fn render_loop_processes_every_event_kind_and_exits_when_the_sender_is_dropped() {
        let (tx, handle) = spawn();
        tx.send(ScanEvent::StageStarted {
            stage: "s1-preprocess",
        })
        .unwrap();
        tx.send(ScanEvent::ChunkProgress {
            stage: "s4-deepdive",
            completed: 1,
            total: 3,
        })
        .unwrap();
        tx.send(ScanEvent::FindingsCount {
            stage: "s4-deepdive",
            count: 2,
        })
        .unwrap();
        tx.send(ScanEvent::UsageUpdate {
            stage: "s4-deepdive",
            prompt_tokens: 10,
            completion_tokens: 5,
        })
        .unwrap();
        tx.send(ScanEvent::StageFinished {
            stage: "s4-deepdive",
            degraded: false,
        })
        .unwrap();
        drop(tx);
        handle.join().expect("render thread must not panic");
    }
}
