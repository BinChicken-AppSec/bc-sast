//! Key decoding, ported (in spirit) from
//! `remediation_agent/interactive/keys.py`'s `decode_key`. The Python
//! original hand-decodes raw escape-sequence bytes read off a POSIX/
//! Windows TTY (`\x1b[A`, `\x1bOA`, etc.); `crossterm` already does that
//! platform-specific decoding for us and hands back a structured
//! [`crossterm::event::KeyEvent`], so [`decode_crossterm_key`] only needs
//! to map ITS variants onto our own menu-level tokens — simpler than the
//! Python original, but the SAME decision table: arrows and `j`/`k`
//! vi-keys, Enter, and q/Esc/Ctrl-C/Ctrl-D as quit. Pure (no I/O), so
//! it's testable by constructing `KeyEvent` values directly — no real
//! terminal needed.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Decoded key tokens the picker understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    Quit,
    Other,
}

/// Maps a crossterm key event to one of [`Key`]'s tokens.
pub fn decode_crossterm_key(event: KeyEvent) -> Key {
    let ctrl = event.modifiers.contains(KeyModifiers::CONTROL);
    match event.code {
        KeyCode::Up | KeyCode::Char('k') => Key::Up,
        KeyCode::Down | KeyCode::Char('j') => Key::Down,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => Key::Quit,
        KeyCode::Char('c') if ctrl => Key::Quit,
        KeyCode::Char('d') if ctrl => Key::Quit,
        _ => Key::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventKind;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    }

    fn plain(code: KeyCode) -> KeyEvent {
        key(code, KeyModifiers::NONE)
    }

    #[test]
    fn arrow_up_and_vi_k_are_up() {
        assert_eq!(decode_crossterm_key(plain(KeyCode::Up)), Key::Up);
        assert_eq!(decode_crossterm_key(plain(KeyCode::Char('k'))), Key::Up);
    }

    #[test]
    fn arrow_down_and_vi_j_are_down() {
        assert_eq!(decode_crossterm_key(plain(KeyCode::Down)), Key::Down);
        assert_eq!(decode_crossterm_key(plain(KeyCode::Char('j'))), Key::Down);
    }

    #[test]
    fn enter_is_enter() {
        assert_eq!(decode_crossterm_key(plain(KeyCode::Enter)), Key::Enter);
    }

    #[test]
    fn q_uppercase_q_and_esc_are_quit() {
        assert_eq!(decode_crossterm_key(plain(KeyCode::Char('q'))), Key::Quit);
        assert_eq!(decode_crossterm_key(plain(KeyCode::Char('Q'))), Key::Quit);
        assert_eq!(decode_crossterm_key(plain(KeyCode::Esc)), Key::Quit);
    }

    #[test]
    fn ctrl_c_and_ctrl_d_are_quit() {
        assert_eq!(
            decode_crossterm_key(key(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Key::Quit
        );
        assert_eq!(
            decode_crossterm_key(key(KeyCode::Char('d'), KeyModifiers::CONTROL)),
            Key::Quit
        );
    }

    #[test]
    fn plain_c_and_d_without_control_are_other() {
        assert_eq!(decode_crossterm_key(plain(KeyCode::Char('c'))), Key::Other);
        assert_eq!(decode_crossterm_key(plain(KeyCode::Char('d'))), Key::Other);
    }

    #[test]
    fn an_unrelated_key_is_other() {
        assert_eq!(decode_crossterm_key(plain(KeyCode::Char('x'))), Key::Other);
        assert_eq!(decode_crossterm_key(plain(KeyCode::Tab)), Key::Other);
    }
}
