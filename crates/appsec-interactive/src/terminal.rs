use std::io::IsTerminal;

use crate::blocking_io::BlockingInput;

pub trait Terminal: BlockingInput {
    fn is_tty(&self) -> bool;

    fn draw(&mut self, frame: &str) -> std::io::Result<()>;

    fn write_line(&mut self, line: &str);
}

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
