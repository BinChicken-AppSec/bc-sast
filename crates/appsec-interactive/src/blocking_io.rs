use crate::keys::{decode_crossterm_key, Key};
use crate::terminal::RealTerminal;

pub trait BlockingInput {
    fn read_key(&mut self) -> std::io::Result<Key>;

    fn read_line(&mut self, prompt: &str) -> Option<String>;
}

impl BlockingInput for RealTerminal {
    fn read_key(&mut self) -> std::io::Result<Key> {
        crossterm::terminal::enable_raw_mode()?;
        let result = loop {
            match crossterm::event::read()? {
                crossterm::event::Event::Key(k) => break Ok(decode_crossterm_key(k)),
                _ => continue,
            }
        };
        crossterm::terminal::disable_raw_mode()?;
        result
    }

    fn read_line(&mut self, prompt: &str) -> Option<String> {
        use std::io::Write;
        eprint!("{prompt}");
        std::io::stderr().flush().ok()?;
        let mut buf = String::new();
        match std::io::stdin().read_line(&mut buf) {
            Ok(0) => None,
            Ok(_) => Some(buf.trim_end_matches(['\n', '\r']).to_string()),
            Err(_) => None,
        }
    }
}
