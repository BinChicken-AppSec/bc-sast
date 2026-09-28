//! The one consumer of a scan's [`bc_pipeline_core::ScanEvent`] stream
//! (task #75): a render thread that hands every event to up to three
//! observers.
//!
//! - The live terminal progress bar, `--no-progress`'s counterpart. It
//!   owns the terminal while a scan runs (structured logs go to
//!   `--log-file` instead, see `logging.rs`) and hides itself off a TTY.
//!   Not a port: the Python original has no equivalent UI.
//! - The plain-text progress lines ([`crate::progress_lines`]), for logs
//!   nothing redraws in place. When they are on, the bar is off: both
//!   write to stderr and an interleaved line corrupts the bar's frame.
//! - The run manifest's [`StageTelemetry`], always, so the manifest sees
//!   every stage whether or not anything is drawn.
//! - The S6 progress file ([`crate::s6_progress`]), when
//!   `--s6-progress-file` or `step6_verify.progress_file` asks for it.

use std::io::IsTerminal;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::Duration;

use bc_orchestrator::manifest::StageTelemetry;
use bc_pipeline_core::{ProgressSink, ScanEvent};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::estimate::with_commas;
use crate::progress_lines::{self, LineRenderer};

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

/// Which observers the render thread runs besides the telemetry
/// collector, which always runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observers {
    /// The TTY progress bar.
    pub bar: bool,
    /// Text progress lines on stderr, in this style.
    pub lines: Option<progress_lines::ProgressStyle>,
    /// Where to keep the S6 progress file, when it is on.
    pub s6_progress: Option<std::path::PathBuf>,
}

impl Observers {
    /// The bar only when line output is off (see the module doc), and
    /// only where it would render at all.
    pub fn choose(bar_renders: bool, lines: Option<progress_lines::ProgressStyle>) -> Self {
        Observers {
            bar: bar_renders && lines.is_none(),
            lines,
            s6_progress: None,
        }
    }
}

/// Creates the event channel and spawns the render thread: a real OS
/// thread, not a tokio task, since `indicatif`'s API is synchronous and
/// must never share the async runtime's worker threads. Returns the
/// [`ProgressSink`] half and a [`JoinHandle`] yielding the collected
/// [`StageTelemetry`]. The thread ends when every sink clone is dropped:
/// `ScanConfig` (and any remediation telemetry cloned from it) is
/// consumed by the scan, so joining after the scan returns is prompt.
pub fn spawn(observers: Observers) -> (ProgressSink, JoinHandle<StageTelemetry>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || render_loop(rx, observers));
    (tx, handle)
}

/// `main_impl`'s wiring: spawns the render thread and sets
/// `config.progress` to its sink. Always spawned, because the telemetry
/// collector behind the run manifest always needs the stream; the bar and
/// the lines are what `observers` switches.
pub fn wire(
    config: &mut bc_orchestrator::ScanConfig,
    observers: Observers,
) -> JoinHandle<StageTelemetry> {
    let (tx, handle) = spawn(observers);
    config.progress = Some(tx);
    handle
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

/// The indicatif bar as an event observer.
struct Bar {
    stage_bar: ProgressBar,
    chunk_bar: ProgressBar,
    state: State,
    // Held so the bars stay attached for the render's lifetime.
    _multi: MultiProgress,
}

impl Bar {
    fn new() -> Self {
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
        let state = State::default();
        stage_bar.set_message(state.message());
        Bar {
            stage_bar,
            chunk_bar,
            state,
            _multi: multi,
        }
    }

    fn on_event(&mut self, event: &ScanEvent) {
        match event {
            ScanEvent::StageStarted { stage } => {
                self.state.stage = stage;
                self.chunk_bar.set_position(0);
                self.chunk_bar.set_length(0);
            }
            ScanEvent::StageFinished { .. } => return,
            // S6's per-finding progress shares the secondary bar: it is
            // the same "k of n units of this stage" shape.
            ScanEvent::ChunkProgress {
                completed, total, ..
            }
            | ScanEvent::VerifyProgress {
                completed, total, ..
            } => {
                self.chunk_bar.set_length(*total as u64);
                self.chunk_bar.set_position(*completed as u64);
                return;
            }
            ScanEvent::FindingsCount { count, .. } => self.state.findings = *count,
            ScanEvent::UsageUpdate { usage, .. } => {
                self.state.prompt_tokens += usage.prompt_tokens;
                self.state.completion_tokens += usage.completion_tokens;
            }
        }
        self.stage_bar.set_message(self.state.message());
    }

    fn finish(self) {
        self.chunk_bar.finish_and_clear();
        self.stage_bar.finish_and_clear();
    }
}

fn render_loop(rx: Receiver<ScanEvent>, observers: Observers) -> StageTelemetry {
    let mut bar = observers.bar.then(Bar::new);
    let mut lines = observers
        .lines
        .map(|style| LineRenderer::new(std::io::stderr(), style));
    let mut s6_file = observers
        .s6_progress
        .map(crate::s6_progress::S6ProgressFile::for_path);
    let mut telemetry = StageTelemetry::default();
    while let Ok(event) = rx.recv() {
        if let Some(bar) = bar.as_mut() {
            bar.on_event(&event);
        }
        if let Some(lines) = lines.as_mut() {
            lines.on_event(&event);
        }
        if let Some(file) = s6_file.as_mut() {
            file.on_event(&event);
        }
        telemetry.record(&event);
    }
    if let Some(bar) = bar {
        bar.finish();
    }
    telemetry
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
    fn line_output_switches_the_bar_off() {
        let lines = Some(progress_lines::ProgressStyle::Compact);
        assert_eq!(
            Observers::choose(true, lines),
            Observers {
                bar: false,
                lines,
                s6_progress: None
            }
        );
        assert_eq!(
            Observers::choose(true, None),
            Observers {
                bar: true,
                lines: None,
                s6_progress: None
            }
        );
        assert!(!Observers::choose(false, None).bar);
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

    fn every_event_kind() -> Vec<ScanEvent> {
        vec![
            ScanEvent::StageStarted {
                stage: "s4-deepdive",
            },
            ScanEvent::ChunkProgress {
                stage: "s4-deepdive",
                completed: 1,
                total: 3,
            },
            ScanEvent::FindingsCount {
                stage: "s4-deepdive",
                count: 2,
            },
            ScanEvent::VerifyProgress {
                stage: "s6-verify",
                completed: 1,
                total: 2,
                outcome: Some("TRUE_POSITIVE"),
            },
            ScanEvent::UsageUpdate {
                stage: "s4-deepdive",
                usage: bc_pipeline_core::StageUsage {
                    prompt_tokens: 10,
                    completion_tokens: 5,
                    ..Default::default()
                },
            },
            ScanEvent::StageFinished {
                stage: "s4-deepdive",
                status: bc_pipeline_core::StageStatus::Completed,
                duration: Some(Duration::from_millis(5)),
                counts: vec![("findings", 2)],
                detail: None,
            },
        ]
    }

    /// Every observer on at once (which `choose` never does, so the bar
    /// and the lines can both be driven here) sees every event, and the
    /// collector comes back out of the join.
    #[test]
    fn every_observer_sees_every_event_and_the_telemetry_is_returned() {
        let state = tempfile::tempdir().unwrap();
        let s6_path = crate::s6_progress::path_under(state.path(), "run");
        let (tx, handle) = spawn(Observers {
            bar: true,
            lines: Some(progress_lines::ProgressStyle::Compact),
            s6_progress: Some(s6_path.clone()),
        });
        for event in every_event_kind() {
            tx.send(event).unwrap();
        }
        drop(tx);
        let telemetry = handle.join().expect("render thread must not panic");
        let s4 = telemetry.get("s4").unwrap();
        assert_eq!(s4.usage.unwrap().prompt_tokens, 10);
        assert_eq!(s4.status, Some(bc_pipeline_core::StageStatus::Completed));
        // The S6 progress observer saw the `VerifyProgress` event too.
        assert!(s6_path.is_file());
    }

    #[test]
    fn wire_always_installs_a_sink_for_the_telemetry_collector() {
        let mut config = crate::tests::fast_config();
        let handle = wire(&mut config, Observers::default());
        let sink = config.progress.take().expect("a sink is always wired");
        sink.send(ScanEvent::StageStarted { stage: "s1" }).unwrap();
        drop(sink);
        drop(config);
        assert!(handle.join().unwrap().get("s1").unwrap().started);
    }
}
