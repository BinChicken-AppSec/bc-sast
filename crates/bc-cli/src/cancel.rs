//! Ctrl-C: the first press cancels the run cooperatively, the second one
//! exits at once.
//!
//! The first Ctrl-C trips the run's [`bc_pipeline_core::CancelToken`],
//! the same one every stage gate consults (see `bc_orchestrator`'s
//! `cancellation` module): no stage starts new work, the calls in flight finish, the remaining
//! stages are skipped, and the partial report and run manifest are still
//! written, marked as canceled, before the process exits with
//! [`CANCELED_EXIT_CODE`]. A second Ctrl-C is the escape hatch for an
//! operator who will not wait for the calls in flight: the process exits
//! with the same code immediately, writing nothing further.
//!
//! A mode that never armed the token (a utility mode such as `--doctor`,
//! batch mode, a posting mode) has nothing to wind down cooperatively, so
//! its first Ctrl-C already exits: an operator must never press Ctrl-C and
//! have nothing happen.
//!
//! The signal itself arrives on a channel ([`listen`]), fed by
//! [`forward_signals`] from `tokio::signal::ctrl_c` in `main.rs`, so tests
//! drive every decision by sending on the channel instead of raising real
//! signals.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use bc_pipeline_core::{CancelTokenRef, USER_CANCEL_REASON};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// The exit code of a canceled run, the shell convention for a process
/// ended by SIGINT (128 + 2).
pub const CANCELED_EXIT_CODE: u8 = 130;

/// What one Ctrl-C does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    /// Trip the token and let the run wind down, writing its report.
    Cancel,
    /// Exit with [`CANCELED_EXIT_CODE`] now.
    ExitNow,
}

/// The pure decision: only the first signal of an armed run cancels
/// cooperatively; every other signal exits at once.
pub fn decide(prior_signals: usize, armed: bool) -> SignalAction {
    if prior_signals == 0 && armed {
        SignalAction::Cancel
    } else {
        SignalAction::ExitNow
    }
}

/// What the listener needs besides the token: whether a cooperative run
/// is under way, and how many signals have arrived.
#[derive(Debug, Default)]
struct Signals {
    armed: AtomicBool,
    received: AtomicUsize,
}

/// The process's one cancellation: the token a run is handed plus what the
/// signal listener needs to decide between canceling and exiting.
#[derive(Debug, Clone, Default)]
pub struct Controller {
    signals: Arc<Signals>,
    token: CancelTokenRef,
}

impl Controller {
    pub fn new() -> Self {
        Controller::default()
    }

    /// Declares that a cooperative run is under way, from which point the
    /// first Ctrl-C cancels it rather than exiting, and hands back the
    /// token the run must consult.
    pub fn arm(&self) -> CancelTokenRef {
        self.signals.armed.store(true, Ordering::SeqCst);
        self.token.clone()
    }

    /// Whether the run has been canceled.
    pub fn is_canceled(&self) -> bool {
        self.token.is_canceled()
    }

    /// One Ctrl-C arrived: decide, and trip the token when canceling.
    pub fn on_signal(&self) -> SignalAction {
        let prior = self.signals.received.fetch_add(1, Ordering::SeqCst);
        let action = decide(prior, self.signals.armed.load(Ordering::SeqCst));
        if action == SignalAction::Cancel {
            self.token.cancel(USER_CANCEL_REASON);
        }
        action
    }
}

/// Consumes signals until one calls for an immediate exit, printing what
/// each one did. Returns `true` when the caller must exit now, `false`
/// when the signal source closed first (the run finished normally).
pub async fn listen(controller: Controller, mut signals: UnboundedReceiver<()>) -> bool {
    while signals.recv().await.is_some() {
        match controller.on_signal() {
            SignalAction::Cancel => eprintln!(
                "\n  [cancel] Ctrl-C: stopping after the work already in flight; the partial \
                 report and run manifest will still be written. Press Ctrl-C again to exit \
                 immediately."
            ),
            SignalAction::ExitNow => {
                eprintln!("\n  [cancel] Ctrl-C: exiting now (exit code {CANCELED_EXIT_CODE}).");
                return true;
            }
        }
    }
    false
}

/// `main.rs`'s listener task: [`listen`], then `exit` with
/// [`CANCELED_EXIT_CODE`] if a signal asked for it. `exit` is
/// `std::process::exit` in the binary and a stand-in in tests.
pub async fn exit_on_request(
    controller: Controller,
    signals: UnboundedReceiver<()>,
    exit: fn(i32) -> !,
) {
    if listen(controller, signals).await {
        exit(i32::from(CANCELED_EXIT_CODE));
    }
}

/// Feeds every signal `next_signal` yields into `tx` until either side
/// closes. `main.rs` passes `tokio::signal::ctrl_c`; a failure to listen
/// at all (no signal support) simply ends the forwarding, which leaves
/// Ctrl-C with its default, immediate behavior.
pub async fn forward_signals<F, Fut>(mut next_signal: F, tx: UnboundedSender<()>)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    while next_signal().await.is_ok() {
        if tx.send(()).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_first_signal_of_an_armed_run_cancels() {
        assert_eq!(decide(0, true), SignalAction::Cancel);
        assert_eq!(decide(1, true), SignalAction::ExitNow);
        assert_eq!(decide(5, true), SignalAction::ExitNow);
        // Nothing to wind down: exit on the first press.
        assert_eq!(decide(0, false), SignalAction::ExitNow);
    }

    #[test]
    fn the_controller_trips_its_token_once_then_asks_for_an_exit() {
        let controller = Controller::new();
        let token = controller.arm();
        assert!(!controller.is_canceled());
        assert_eq!(controller.on_signal(), SignalAction::Cancel);
        assert!(token.is_canceled());
        assert_eq!(token.reason().as_deref(), Some(USER_CANCEL_REASON));
        assert_eq!(controller.on_signal(), SignalAction::ExitNow);
        assert!(controller.is_canceled());
    }

    #[test]
    fn an_unarmed_controller_exits_on_the_first_signal_and_cancels_nothing() {
        let controller = Controller::default();
        assert_eq!(controller.on_signal(), SignalAction::ExitNow);
        assert!(!controller.is_canceled());
    }

    #[tokio::test]
    async fn listen_cancels_on_the_first_signal_and_exits_on_the_second() {
        let controller = Controller::new();
        controller.arm();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tx.send(()).unwrap();
        tx.send(()).unwrap();
        assert!(listen(controller.clone(), rx).await);
        assert!(controller.is_canceled());
    }

    #[tokio::test]
    async fn listen_returns_quietly_when_the_source_closes() {
        let controller = Controller::new();
        controller.arm();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tx.send(()).unwrap();
        drop(tx);
        assert!(!listen(controller.clone(), rx).await);
        assert!(controller.is_canceled());
    }

    fn fake_exit(code: i32) -> ! {
        panic!("exit {code}")
    }

    #[tokio::test]
    #[should_panic(expected = "exit 130")]
    async fn exit_on_request_exits_130_on_the_second_signal() {
        let controller = Controller::new();
        controller.arm();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tx.send(()).unwrap();
        tx.send(()).unwrap();
        exit_on_request(controller, rx, fake_exit).await;
    }

    #[tokio::test]
    async fn exit_on_request_returns_when_the_source_closes_without_asking() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        drop(tx);
        exit_on_request(Controller::new(), rx, fake_exit).await;
    }

    #[tokio::test]
    async fn forward_signals_relays_until_the_source_fails_or_the_listener_goes() {
        // Two signals, then the source fails: two relayed.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut left = 2;
        forward_signals(
            move || {
                let result = if left > 0 {
                    left -= 1;
                    Ok(())
                } else {
                    Err(std::io::Error::other("no more"))
                };
                std::future::ready(result)
            },
            tx,
        )
        .await;
        assert_eq!(rx.recv().await, Some(()));
        assert_eq!(rx.recv().await, Some(()));
        assert_eq!(rx.recv().await, None);

        // The listener is gone: forwarding stops at the first signal.
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        drop(rx);
        forward_signals(|| std::future::ready(Ok(())), tx).await;
    }
}
