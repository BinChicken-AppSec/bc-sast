//! Runs the operator's `verify_command` so that stopping it stops ALL of
//! it: the shell and everything the shell started.
//!
//! `kill_on_drop` alone only kills the direct child, which here is `sh`.
//! A `cargo build && cargo test` verify command leaves `cargo` (and its
//! compiler and test processes) running as orphans when only `sh` is
//! killed, still writing into the very files the rollback is about to
//! restore. So the shell is started as the leader of its own process group
//! and the whole group is killed on timeout, on a cancellation (Ctrl-C) and
//! whenever the run is dropped before the command finished.
//!
//! The group kill goes through the same shell's `kill` builtin rather than
//! a `libc` binding: the workspace carries no FFI of its own, and the
//! verify gate already requires that shell to exist (it fails closed
//! without one), so this adds no new requirement.

use std::future::Future;
use std::path::Path;
use std::pin::pin;
use std::process::Output;
use std::task::Poll;
use std::time::Duration;

use bc_pipeline_core::CancelTokenRef;

/// How often a running verify command checks for a cancellation. The token
/// has no async wake-up of its own (it lives in a runtime-free crate), and
/// a tenth of a second is far below anything an operator can notice.
const CANCEL_POLL: Duration = Duration::from_millis(100);

/// How one verify run ended.
#[derive(Debug)]
pub(crate) enum GroupRun {
    /// The command ran to completion (or could not be started at all).
    Finished(std::io::Result<Output>),
    /// `timeout` expired; the group was killed.
    TimedOut,
    /// The run was canceled; the group was killed. Carries the reason.
    Canceled(String),
}

/// Kills a process group through `shell`'s `kill` builtin when dropped,
/// unless the command it guards finished on its own.
struct GroupGuard<'a> {
    shell: &'a str,
    pgid: Option<u32>,
}

impl GroupGuard<'_> {
    fn disarm(&mut self) {
        self.pgid = None;
    }
}

impl Drop for GroupGuard<'_> {
    fn drop(&mut self) {
        if let Some(pgid) = self.pgid {
            kill_group(self.shell, pgid);
        }
    }
}

/// `SIGKILL` to every process in group `pgid`. Best effort: a group whose
/// members have all exited already is not an error worth reporting, and
/// there is nothing more a caller could do about one that failed.
fn kill_group(shell: &str, pgid: u32) {
    let _ = std::process::Command::new(shell)
        .arg("-c")
        .arg(format!("kill -s KILL -- -{pgid} 2>/dev/null"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Resolves with the cancellation reason once `cancel` trips; never
/// resolves without a token.
async fn canceled(cancel: Option<&CancelTokenRef>) -> String {
    let Some(token) = cancel else {
        return std::future::pending().await;
    };
    loop {
        if let Some(reason) = token.reason() {
            return reason;
        }
        tokio::time::sleep(CANCEL_POLL).await;
    }
}

/// Runs `shell -c command` in `repo` as its own process group, capped at
/// `timeout` and stopped early by `cancel`.
pub(crate) async fn run_in_group(
    repo: &Path,
    shell: &str,
    command: &str,
    timeout: Duration,
    cancel: Option<&CancelTokenRef>,
) -> GroupRun {
    // A cancellation that is already in place starts nothing.
    if let Some(reason) = bc_pipeline_core::canceled(cancel) {
        return GroupRun::Canceled(reason);
    }
    let mut cmd = tokio::process::Command::new(shell);
    cmd.arg("-c")
        .arg(command)
        .current_dir(repo)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        // Group id = the shell's own pid, so the whole tree can be
        // signaled as one.
        .process_group(0);
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return GroupRun::Finished(Err(e)),
    };
    // Declared before the output future so it is dropped after it: the
    // shell is reaped (kill_on_drop) and then the rest of its group killed.
    let mut guard = GroupGuard {
        shell,
        pgid: child.id(),
    };
    let mut output = pin!(child.wait_with_output());
    let mut stop = pin!(canceled(cancel));
    let raced = std::future::poll_fn(|cx| {
        if let Poll::Ready(out) = output.as_mut().poll(cx) {
            return Poll::Ready(Ok(out));
        }
        stop.as_mut().poll(cx).map(Err)
    });
    match tokio::time::timeout(timeout, raced).await {
        Ok(Ok(out)) => {
            guard.disarm();
            GroupRun::Finished(out)
        }
        Ok(Err(reason)) => GroupRun::Canceled(reason),
        Err(_) => GroupRun::TimedOut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_pipeline_core::CancelToken;

    /// Whether `pid` is a live, non-zombie process.
    ///
    /// Asks `ps` rather than reading `/proc/<pid>/stat`, which exists on
    /// Linux but not on macOS: there the read simply failed and every
    /// caller saw `false`, so the two tests below asserting a process had
    /// been killed passed without ever observing one alive, and the
    /// positive control in the cancellation test failed outright. `ps -o
    /// stat=` prints the state letter on both platforms and nothing at all
    /// for a pid that has gone, and `Z` still means a zombie, which is not
    /// alive for this purpose.
    fn alive(pid: &str) -> bool {
        alive_via("ps", pid)
    }

    /// `alive` with the tool to ask injected, so the "could not ask" arm is
    /// reachable from a test rather than only on a machine without `ps`.
    fn alive_via(program: &str, pid: &str) -> bool {
        let Ok(out) = std::process::Command::new(program)
            .args(["-o", "stat=", "-p", pid])
            .output()
        else {
            // No way to tell. Nothing here should report a process alive on
            // a guess, so this reads as not alive.
            return false;
        };
        let state = String::from_utf8_lossy(&out.stdout);
        let state = state.trim();
        !state.is_empty() && !state.starts_with('Z')
    }

    #[test]
    fn a_liveness_check_that_cannot_run_reports_not_alive() {
        assert!(!alive_via("bc-sast-no-such-process-tool", "1"));
    }

    #[test]
    fn a_pid_that_cannot_exist_is_not_alive() {
        // 0 is never a live process id to `ps -p`, so this exercises the
        // empty-output arm against the real tool.
        assert!(!alive("0"));
    }

    /// Waits up to two seconds for `path` to hold a pid.
    async fn read_pid(path: &Path) -> String {
        let mut pid = String::new();
        let mut tries = 0;
        while pid.is_empty() && tries < 200 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            pid = std::fs::read_to_string(path)
                .unwrap_or_default()
                .trim()
                .to_string();
            tries += 1;
        }
        assert!(!pid.is_empty(), "the grandchild never wrote its pid");
        pid
    }

    /// A shell that starts a long-lived grandchild and waits on it: the
    /// shape of `cargo build && cargo test`, where killing `sh` alone
    /// would orphan the real work.
    fn grandchild_command(pid_file: &Path) -> String {
        format!("sleep 30 & echo $! > {}; wait", pid_file.display())
    }

    #[tokio::test]
    async fn a_command_that_finishes_reports_its_output() {
        let dir = tempfile::tempdir().unwrap();
        let run = run_in_group(dir.path(), "sh", "echo hi", Duration::from_secs(10), None).await;
        assert!(
            matches!(&run, GroupRun::Finished(Ok(out)) if out.status.success() && out.stdout == b"hi\n"),
            "{run:?}"
        );
    }

    #[tokio::test]
    async fn a_missing_shell_is_a_spawn_error_not_a_pass() {
        let dir = tempfile::tempdir().unwrap();
        let run = run_in_group(
            dir.path(),
            "definitely-not-a-shell-bc-sast",
            "true",
            Duration::from_secs(10),
            None,
        )
        .await;
        assert!(matches!(run, GroupRun::Finished(Err(_))), "{run:?}");
    }

    #[tokio::test]
    async fn a_timeout_kills_the_whole_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let run = run_in_group(
            dir.path(),
            "sh",
            &grandchild_command(&pid_file),
            Duration::from_millis(500),
            None,
        )
        .await;
        assert!(matches!(run, GroupRun::TimedOut), "{run:?}");
        let pid = read_pid(&pid_file).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!alive(&pid), "grandchild {pid} survived the timeout");
    }

    #[tokio::test]
    async fn a_cancellation_mid_run_kills_the_whole_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let token = CancelToken::new_ref();
        let trip = token.clone();
        let pid_path = pid_file.clone();
        let canceller = tokio::spawn(async move {
            let pid = read_pid(&pid_path).await;
            // The positive control: without it, the check after the
            // cancellation could pass on a grandchild that never ran.
            let not_running = format!("grandchild {pid} was not running before the cancellation");
            assert!(alive(&pid), "{not_running}");
            trip.cancel(bc_pipeline_core::USER_CANCEL_REASON);
        });
        let run = run_in_group(
            dir.path(),
            "sh",
            &grandchild_command(&pid_file),
            Duration::from_secs(30),
            Some(&token),
        )
        .await;
        canceller.await.unwrap();
        assert!(
            matches!(&run, GroupRun::Canceled(r) if r == bc_pipeline_core::USER_CANCEL_REASON),
            "{run:?}"
        );
        let pid = read_pid(&pid_file).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!alive(&pid), "grandchild {pid} survived the cancellation");
    }

    #[tokio::test]
    async fn an_earlier_cancellation_starts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("ran");
        let token = CancelToken::new_ref();
        token.cancel("stop");
        let run = run_in_group(
            dir.path(),
            "sh",
            &format!("touch {}", marker.display()),
            Duration::from_secs(10),
            Some(&token),
        )
        .await;
        assert!(
            matches!(run, GroupRun::Canceled(ref r) if r == "stop"),
            "{run:?}"
        );
        assert!(!marker.exists());
    }
}
