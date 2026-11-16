use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use appsec_pipeline_core::{CancelTokenRef, USER_CANCEL_REASON};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub const CANCELED_EXIT_CODE: u8 = 130;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    Cancel,
    ExitNow,
}

pub fn decide(prior_signals: usize, armed: bool) -> SignalAction {
    if prior_signals == 0 && armed {
        SignalAction::Cancel
    } else {
        SignalAction::ExitNow
    }
}

#[derive(Debug, Default)]
struct Signals {
    armed: AtomicBool,
    received: AtomicUsize,
}

#[derive(Debug, Clone, Default)]
pub struct Controller {
    signals: Arc<Signals>,
    token: CancelTokenRef,
}

impl Controller {
    pub fn new() -> Self {
        Controller::default()
    }

    pub fn arm(&self) -> CancelTokenRef {
        self.signals.armed.store(true, Ordering::SeqCst);
        self.token.clone()
    }

    pub fn is_canceled(&self) -> bool {
        self.token.is_canceled()
    }

    pub fn on_signal(&self) -> SignalAction {
        let prior = self.signals.received.fetch_add(1, Ordering::SeqCst);
        let action = decide(prior, self.signals.armed.load(Ordering::SeqCst));
        if action == SignalAction::Cancel {
            self.token.cancel(USER_CANCEL_REASON);
        }
        action
    }
}

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

pub async fn exit_on_request(
    controller: Controller,
    signals: UnboundedReceiver<()>,
    exit: fn(i32) -> !,
) {
    if listen(controller, signals).await {
        exit(i32::from(CANCELED_EXIT_CODE));
    }
}

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

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        drop(rx);
        forward_signals(|| std::future::ready(Ok(())), tx).await;
    }
}
