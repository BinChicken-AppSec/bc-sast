use std::io::{IsTerminal, Write};
use std::path::Path;

use tracing_subscriber::fmt::writer::{BoxMakeWriter, MakeWriter, MakeWriterExt};
use tracing_subscriber::EnvFilter;

fn verbosity_directive(verbose: u8) -> &'static str {
    match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    }
}

fn should_stream_to_stderr(has_log_file: bool, log_stderr: bool, stderr_is_terminal: bool) -> bool {
    log_stderr || (!has_log_file && !stderr_is_terminal)
}

fn make_writer(file: Option<std::fs::File>, to_stderr: bool) -> Option<BoxMakeWriter> {
    let raw = match (file, to_stderr) {
        (None, false) => return None,
        (Some(file), false) => BoxMakeWriter::new(file),
        (None, true) => BoxMakeWriter::new(std::io::stderr),
        (Some(file), true) => BoxMakeWriter::new(file.and(std::io::stderr)),
    };
    Some(BoxMakeWriter::new(Redacting(raw)))
}

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

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.pending.is_empty() {
            let redacted = appsec_redact::redact(&String::from_utf8_lossy(&self.pending));
            self.pending.clear();
            self.inner.write_all(redacted.as_bytes())?;
        }
        self.inner.flush()
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn build_filter(rust_log: Option<&str>, verbose: u8) -> EnvFilter {
    rust_log
        .and_then(|directives| EnvFilter::try_new(directives).ok())
        .unwrap_or_else(|| EnvFilter::new(verbosity_directive(verbose)))
}

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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.log");
        assert_eq!(init_logging(Some(&path), 2, false), Ok(()));
        assert!(path.exists());
    }

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
    #[case(true, false, true, false)]
    #[case(true, false, false, false)]
    #[case(false, false, true, false)]
    #[case(false, false, false, true)]
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

    #[test]
    fn rust_log_takes_precedence_over_the_verbosity_fallback() {
        let filter = build_filter(Some("appsec_stage_s4=debug,warn"), 3).to_string();
        assert!(filter.contains("appsec_stage_s4=debug"), "{filter}");
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
