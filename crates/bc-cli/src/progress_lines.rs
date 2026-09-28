//! Plain-text progress lines on stderr, one line per milestone, for logs
//! that nothing redraws in place: CI jobs, `tee`, a container's captured
//! output. The TTY progress bar (`crate::progress`) hides itself there,
//! so without these a CI log shows nothing between the start banner and
//! the summary.
//!
//! Ported from the Python original's `util/scan_progress.py`
//! (`ScanProgress.stage_started`/`stage_done`/`print_summary`), fed from
//! the scan's [`ScanEvent`] stream instead of stage-side calls, with the
//! same `[progress]` prefix and the same four styles:
//!
//! - `compact` (the default): stage start/done lines, S4 chunk progress
//!   and the S4 summary block.
//! - `verbose`: compact plus running findings counts and per-stage token
//!   spend.
//! - `summary_only`: the S4 summary block alone.
//! - `stage_only`: numbered `▶`/`✓` stage lines only.
//!
//! **Deliberately not ported: `llm_debug`**, which dumps every prompt's
//! system and user text to stderr. Prompts carry source code the operator
//! may not want in a CI log, and a debug knob that does that is exactly
//! how it ends up there.
//!
//! **Divergences.** Python's per-chunk lines name the chunk and its
//! files; the event stream carries S4's progress as a count, so these
//! lines do too. Stage numbering runs to 12 (S0-S11), where Python's
//! stops at 11 and prints S11 as `?/11`. The done glyph follows the
//! outcome (`✓` completed or cached, `⚠` completed with errors, `✗`
//! error, `○` skipped or disabled), where Python's stage-only line always
//! wears `✓`: a failed stage marked with a tick is the misreading its own
//! `util/status.py` changed its glyphs to prevent.

use std::io::Write;

use bc_pipeline_core::{
    stage_id, stage_label, stage_number, ScanEvent, StageStatus, StageUsage, STAGE_IDS,
};

/// How much the text progress lines say. The CLI spellings are Python's
/// (`summary_only`, `stage_only`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ProgressStyle {
    #[default]
    Compact,
    Verbose,
    #[value(name = "summary_only")]
    SummaryOnly,
    #[value(name = "stage_only")]
    StageOnly,
}

impl ProgressStyle {
    /// A config-file style string; `None` for anything unrecognized.
    fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "compact" => ProgressStyle::Compact,
            "verbose" => ProgressStyle::Verbose,
            "summary_only" => ProgressStyle::SummaryOnly,
            "stage_only" => ProgressStyle::StageOnly,
            _ => return None,
        })
    }
}

/// The environment switch, Python's `VVAHARNESS_SCAN_PROGRESS_ENABLED`.
pub const ENABLED_ENV: &str = "BC_SCAN_PROGRESS_ENABLED";

/// Whether line output is on and in which style: `Some(style)` when
/// `--progress-style` was given, or `BC_SCAN_PROGRESS_ENABLED` is truthy
/// (`1`/`true`/`yes`, any case), or `scan_progress.enabled: true` is in
/// the config. The style is the flag's, else the config's, else
/// `compact`; an unrecognized config style falls back to `compact`
/// rather than failing the run, matching Python's `from_cfg`.
pub fn resolve(
    flag: Option<ProgressStyle>,
    env: Option<&str>,
    config_enabled: Option<bool>,
    config_style: Option<&str>,
) -> Option<ProgressStyle> {
    let env_on =
        env.is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
    let enabled = flag.is_some() || env_on || config_enabled == Some(true);
    enabled.then(|| {
        flag.or_else(|| config_style.and_then(ProgressStyle::parse))
            .unwrap_or_default()
    })
}

/// [`resolve`] for this invocation: `--progress-style`, the real
/// environment, and `--config`'s `scan_progress` section (re-read the way
/// every other consumer in this crate re-reads it; `build_scan_config`
/// has already failed the run on a config that does not load).
pub(crate) fn from_cli(cli: &crate::Cli) -> Option<ProgressStyle> {
    let data = cli
        .config
        .as_ref()
        .and_then(|path| crate::config_load::load(path).ok())
        .map(|loaded| loaded.data)
        .unwrap_or_default();
    let (enabled, style) = crate::config_overrides::scan_progress_override(&data);
    resolve(
        cli.progress_style,
        crate::getenv(ENABLED_ENV).as_deref(),
        enabled,
        style.as_deref(),
    )
}

/// Renders [`ScanEvent`]s as `[progress]` lines on `out`. Write failures
/// are ignored: progress output is observability, never something a
/// scan should fail over.
pub struct LineRenderer<W: Write> {
    out: W,
    style: ProgressStyle,
}

impl<W: Write> LineRenderer<W> {
    pub fn new(out: W, style: ProgressStyle) -> Self {
        LineRenderer { out, style }
    }

    /// The writer back, for tests to read what was rendered.
    #[cfg(test)]
    fn into_inner(self) -> W {
        self.out
    }

    fn line(&mut self, text: &str) {
        let _ = writeln!(self.out, "{text}");
    }

    fn lifecycle(&self) -> bool {
        matches!(self.style, ProgressStyle::Compact | ProgressStyle::Verbose)
    }

    pub fn on_event(&mut self, event: &ScanEvent) {
        match event {
            ScanEvent::StageStarted { stage } => self.stage_started(stage),
            ScanEvent::StageFinished {
                stage,
                status,
                duration,
                counts,
                detail,
            } => {
                let secs = duration.map_or(0.0, |d| d.as_secs_f64());
                self.stage_done(stage, *status, secs, counts, detail.as_deref());
            }
            ScanEvent::ChunkProgress {
                completed, total, ..
            } if self.lifecycle() => {
                self.line(&format!(
                    "[progress] scanned     {completed} / {total} chunks"
                ));
            }
            ScanEvent::FindingsCount { stage, count } if self.style == ProgressStyle::Verbose => {
                self.line(&format!(
                    "[progress] findings    {:<4} count={count}",
                    stage_id(stage)
                ));
            }
            ScanEvent::UsageUpdate { stage, usage } if self.style == ProgressStyle::Verbose => {
                self.line(&usage_line(stage_id(stage), usage));
            }
            _ => {}
        }
    }

    fn stage_started(&mut self, stage: &str) {
        let id = stage_id(stage);
        let label = stage_label(id).unwrap_or(id);
        match self.style {
            ProgressStyle::StageOnly => self.line(&format!(
                "[progress] \u{25b6} [{}] {} {label}",
                numbered(id),
                id.to_uppercase()
            )),
            ProgressStyle::Compact | ProgressStyle::Verbose => {
                self.line(&format!("[progress] stage-start {id:<4}  {label}"));
            }
            ProgressStyle::SummaryOnly => {}
        }
    }

    fn stage_done(
        &mut self,
        stage: &str,
        status: StageStatus,
        secs: f64,
        counts: &[(&'static str, u64)],
        detail: Option<&str>,
    ) {
        let id = stage_id(stage);
        match self.style {
            ProgressStyle::StageOnly => {
                let label = stage_label(id).unwrap_or(id);
                let timing = match (status.is_timed(), status) {
                    (true, StageStatus::Completed) => format!("{secs:.1}s"),
                    (true, _) => format!("{secs:.1}s, {}", status.as_str()),
                    (false, _) => status.as_str().to_string(),
                };
                self.line(&format!(
                    "[progress] {} [{}] {} {label} ({timing})",
                    glyph(status),
                    numbered(id),
                    id.to_uppercase()
                ));
                self.line("");
            }
            ProgressStyle::Compact | ProgressStyle::Verbose => {
                let mut msg = format!(
                    "[progress] stage-done  {id:<4} outcome={}  {secs:.1}s",
                    status.as_str()
                );
                if !counts.is_empty() {
                    msg.push_str("  ");
                    msg.push_str(&format_counts(counts));
                }
                if let Some(detail) = detail {
                    msg.push_str("  ");
                    msg.push_str(detail);
                }
                self.line(&msg);
            }
            ProgressStyle::SummaryOnly => {}
        }
        if id == "s4" && self.style != ProgressStyle::StageOnly {
            self.s4_summary(secs, counts);
        }
    }

    /// Python's `print_summary` block, printed once S4 is done: how many
    /// chunks ran, what came of them, and a warning for any the budget
    /// left unscanned.
    fn s4_summary(&mut self, secs: f64, counts: &[(&'static str, u64)]) {
        let get = |name: &str| {
            counts
                .iter()
                .find_map(|(n, v)| (*n == name).then_some(*v))
                .unwrap_or(0)
        };
        let (chunks, failed, skipped) =
            (get("chunks"), get("chunks_failed"), get("chunks_skipped"));
        let done = chunks.saturating_sub(skipped);
        self.line(&format!(
            "[progress] summary     {done} / {chunks} chunks done  |  findings={}  elapsed={secs:.1}s",
            get("findings")
        ));
        self.line(&format!(
            "           outcomes:  completed={}  failed={failed}  skipped={skipped}",
            done.saturating_sub(failed)
        ));
        if skipped > 0 {
            self.line(&format!(
                "           WARNING: {skipped} chunk(s) not scanned (budget stop)"
            ));
        }
    }
}

/// `n/N` for a stage's position in the pipeline, `?/N` for an unknown
/// one, as Python prints it.
fn numbered(id: &str) -> String {
    let total = STAGE_IDS.len();
    match stage_number(id) {
        Some(n) => format!("{n}/{total}"),
        None => format!("?/{total}"),
    }
}

fn glyph(status: StageStatus) -> char {
    match status {
        StageStatus::Completed | StageStatus::Cached => '\u{2713}',
        StageStatus::CompletedWithErrors => '\u{26a0}',
        StageStatus::Error => '\u{2717}',
        StageStatus::Skipped | StageStatus::Disabled => '\u{25cb}',
    }
}

/// `name=value` pairs, space separated, in the order the stage gave them
/// (Python's `_progress_detail`).
fn format_counts(counts: &[(&'static str, u64)]) -> String {
    counts
        .iter()
        .map(|(name, n)| format!("{name}={n}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn usage_line(id: &str, usage: &StageUsage) -> String {
    let mut line = format!(
        "[progress] tokens      {id:<4} calls={} prompt={} completion={} cache_read={} cache_write={}",
        usage.calls,
        usage.prompt_tokens,
        usage.completion_tokens,
        usage.cache_read_tokens,
        usage.cache_write_tokens
    );
    if let Some(cost) = usage.cost_usd {
        line.push_str(&format!(" cost_usd={cost:.6}"));
    }
    line
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn line_output_is_off_unless_something_turns_it_on() {
        assert_eq!(resolve(None, None, None, None), None);
        assert_eq!(resolve(None, Some("0"), Some(false), Some("verbose")), None);
    }

    #[test]
    fn the_flag_turns_it_on_and_its_style_wins() {
        assert_eq!(
            resolve(
                Some(ProgressStyle::StageOnly),
                None,
                Some(false),
                Some("verbose")
            ),
            Some(ProgressStyle::StageOnly)
        );
    }

    #[test]
    fn the_env_switch_accepts_pythons_truthy_spellings() {
        for on in ["1", "true", "YES", "True"] {
            assert_eq!(
                resolve(None, Some(on), None, None),
                Some(ProgressStyle::Compact),
                "{on}"
            );
        }
        assert_eq!(resolve(None, Some("no"), None, None), None);
    }

    #[test]
    fn the_config_turns_it_on_and_an_unknown_style_falls_back_to_compact() {
        assert_eq!(
            resolve(None, None, Some(true), Some("summary_only")),
            Some(ProgressStyle::SummaryOnly)
        );
        assert_eq!(
            resolve(None, Some("1"), None, Some("verbose")),
            Some(ProgressStyle::Verbose)
        );
        assert_eq!(
            resolve(None, None, Some(true), Some("llm_debug")),
            Some(ProgressStyle::Compact)
        );
    }

    #[test]
    fn from_cli_reads_the_flag_and_the_config_section() {
        let _guard = crate::tests::ENV_LOCK.blocking_lock();
        let prior = std::env::var(ENABLED_ENV).ok();
        unsafe { std::env::remove_var(ENABLED_ENV) };
        let dir = tempfile::tempdir().unwrap();
        let mut cli = crate::test_support::minimal_cli(dir.path());
        assert_eq!(from_cli(&cli), None);
        cli.progress_style = Some(ProgressStyle::Verbose);
        assert_eq!(from_cli(&cli), Some(ProgressStyle::Verbose));
        cli.progress_style = None;
        let cfg_dir = tempfile::tempdir().unwrap();
        let config = cfg_dir.path().join("config.yaml");
        std::fs::write(
            &config,
            "scan_progress:\n  enabled: true\n  style: stage_only\n",
        )
        .unwrap();
        cli.config = Some(config);
        assert_eq!(from_cli(&cli), Some(ProgressStyle::StageOnly));
        crate::tests::restore_env(ENABLED_ENV, prior);
    }

    fn done(
        stage: &'static str,
        status: StageStatus,
        millis: Option<u64>,
        counts: Vec<(&'static str, u64)>,
        detail: Option<&str>,
    ) -> ScanEvent {
        ScanEvent::StageFinished {
            stage,
            status,
            duration: millis.map(Duration::from_millis),
            counts,
            detail: detail.map(str::to_string),
        }
    }

    /// One scan's worth of events touching every renderer branch.
    fn script() -> Vec<ScanEvent> {
        vec![
            done(
                "s0-seed",
                StageStatus::Skipped,
                None,
                Vec::new(),
                Some("disabled in config"),
            ),
            ScanEvent::StageStarted {
                stage: "s1-preprocess",
            },
            ScanEvent::UsageUpdate {
                stage: "s1-preprocess",
                usage: StageUsage {
                    prompt_tokens: 120,
                    completion_tokens: 30,
                    cache_read_tokens: 5,
                    cache_write_tokens: 2,
                    calls: 1,
                    cost_usd: Some(0.0125),
                    unpriced_tokens: 0,
                    truncated_replies: 0,
                },
            },
            done(
                "s1-preprocess",
                StageStatus::Completed,
                Some(1250),
                vec![("files", 12)],
                None,
            ),
            ScanEvent::StageStarted {
                stage: "s4-deepdive",
            },
            ScanEvent::ChunkProgress {
                stage: "s4-deepdive",
                completed: 1,
                total: 3,
            },
            ScanEvent::UsageUpdate {
                stage: "s4-deepdive",
                usage: StageUsage {
                    calls: 2,
                    ..StageUsage::default()
                },
            },
            done(
                "s4-deepdive",
                StageStatus::CompletedWithErrors,
                Some(12_340),
                vec![
                    ("findings", 2),
                    ("chunks", 3),
                    ("chunks_failed", 1),
                    ("chunks_skipped", 1),
                ],
                Some("token budget of 10 reached"),
            ),
            ScanEvent::FindingsCount {
                stage: "s4-deepdive",
                count: 2,
            },
            ScanEvent::StageStarted { stage: "s6-verify" },
            done(
                "s6-verify",
                StageStatus::Cached,
                None,
                vec![("verified", 2), ("dropped", 0)],
                None,
            ),
            ScanEvent::StageStarted { stage: "s8-chain" },
            done("s8-chain", StageStatus::Error, Some(500), Vec::new(), None),
            done(
                "s11-validate",
                StageStatus::Disabled,
                None,
                Vec::new(),
                Some("validation disabled"),
            ),
            done("zz", StageStatus::Completed, Some(0), Vec::new(), None),
        ]
    }

    fn render(style: ProgressStyle) -> String {
        let mut renderer = LineRenderer::new(Vec::new(), style);
        for event in script() {
            renderer.on_event(&event);
        }
        String::from_utf8(renderer.into_inner()).unwrap()
    }

    #[test]
    fn compact_golden() {
        let expected = "\
[progress] stage-done  s0   outcome=skipped  0.0s  disabled in config
[progress] stage-start s1    pre-process
[progress] stage-done  s1   outcome=completed  1.2s  files=12
[progress] stage-start s4    deep-dive
[progress] scanned     1 / 3 chunks
[progress] stage-done  s4   outcome=completed_with_errors  12.3s  findings=2 chunks=3 chunks_failed=1 chunks_skipped=1  token budget of 10 reached
[progress] summary     2 / 3 chunks done  |  findings=2  elapsed=12.3s
           outcomes:  completed=1  failed=1  skipped=1
           WARNING: 1 chunk(s) not scanned (budget stop)
[progress] stage-start s6    verify
[progress] stage-done  s6   outcome=cached  0.0s  verified=2 dropped=0
[progress] stage-start s8    chain
[progress] stage-done  s8   outcome=error  0.5s
[progress] stage-done  s11  outcome=disabled  0.0s  validation disabled
[progress] stage-done  zz   outcome=completed  0.0s
";
        assert_eq!(render(ProgressStyle::Compact), expected);
    }

    #[test]
    fn verbose_golden() {
        let expected = "\
[progress] stage-done  s0   outcome=skipped  0.0s  disabled in config
[progress] stage-start s1    pre-process
[progress] tokens      s1   calls=1 prompt=120 completion=30 cache_read=5 cache_write=2 cost_usd=0.012500
[progress] stage-done  s1   outcome=completed  1.2s  files=12
[progress] stage-start s4    deep-dive
[progress] scanned     1 / 3 chunks
[progress] tokens      s4   calls=2 prompt=0 completion=0 cache_read=0 cache_write=0
[progress] stage-done  s4   outcome=completed_with_errors  12.3s  findings=2 chunks=3 chunks_failed=1 chunks_skipped=1  token budget of 10 reached
[progress] summary     2 / 3 chunks done  |  findings=2  elapsed=12.3s
           outcomes:  completed=1  failed=1  skipped=1
           WARNING: 1 chunk(s) not scanned (budget stop)
[progress] findings    s4   count=2
[progress] stage-start s6    verify
[progress] stage-done  s6   outcome=cached  0.0s  verified=2 dropped=0
[progress] stage-start s8    chain
[progress] stage-done  s8   outcome=error  0.5s
[progress] stage-done  s11  outcome=disabled  0.0s  validation disabled
[progress] stage-done  zz   outcome=completed  0.0s
";
        assert_eq!(render(ProgressStyle::Verbose), expected);
    }

    #[test]
    fn summary_only_golden() {
        let expected = "\
[progress] summary     2 / 3 chunks done  |  findings=2  elapsed=12.3s
           outcomes:  completed=1  failed=1  skipped=1
           WARNING: 1 chunk(s) not scanned (budget stop)
";
        assert_eq!(render(ProgressStyle::SummaryOnly), expected);
    }

    #[test]
    fn stage_only_golden() {
        let expected = "\
[progress] \u{25cb} [1/12] S0 static seed (skipped)

[progress] \u{25b6} [2/12] S1 pre-process
[progress] \u{2713} [2/12] S1 pre-process (1.2s)

[progress] \u{25b6} [5/12] S4 deep-dive
[progress] \u{26a0} [5/12] S4 deep-dive (12.3s, completed_with_errors)

[progress] \u{25b6} [7/12] S6 verify
[progress] \u{2713} [7/12] S6 verify (cached)

[progress] \u{25b6} [9/12] S8 chain
[progress] \u{2717} [9/12] S8 chain (0.5s, error)

[progress] \u{25cb} [12/12] S11 validate (disabled)

[progress] \u{2713} [?/12] ZZ zz (0.0s)

";
        assert_eq!(render(ProgressStyle::StageOnly), expected);
    }

    #[test]
    fn a_clean_s4_prints_no_budget_warning() {
        let mut renderer = LineRenderer::new(Vec::new(), ProgressStyle::SummaryOnly);
        renderer.on_event(&done(
            "s4-deepdive",
            StageStatus::Cached,
            None,
            vec![("findings", 0), ("chunks", 2)],
            None,
        ));
        let out = String::from_utf8(renderer.into_inner()).unwrap();
        assert_eq!(
            out,
            "[progress] summary     2 / 2 chunks done  |  findings=0  elapsed=0.0s\n           \
             outcomes:  completed=2  failed=0  skipped=0\n"
        );
    }

    /// A writer that always fails: progress must never fail the scan.
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_failing_writer_is_ignored() {
        let mut renderer = LineRenderer::new(Broken, ProgressStyle::Verbose);
        for event in script() {
            renderer.on_event(&event);
        }
        assert!(renderer.into_inner().flush().is_ok());
    }
}
