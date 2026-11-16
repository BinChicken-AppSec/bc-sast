pub const UNDEFINED: char = '\u{FFFD}';

use super::tables::{GLYPH_NAMES, MAC_ROMAN_HIGH, WIN_ANSI_HIGH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoding {
    table: Vec<char>,
}

impl Encoding {
    pub fn base(name: Option<&str>) -> Self {
        let high = match name {
            Some("MacRomanEncoding") => MAC_ROMAN_HIGH,
            _ => WIN_ANSI_HIGH,
        };
        let mut table: Vec<char> = (0u8..0x80).map(char::from).collect();
        table.extend(high.chars());
        debug_assert_eq!(table.len(), 256);
        table.resize(256, UNDEFINED);
        Self { table }
    }

    pub fn apply_differences(&mut self, entries: &[super::object::Object]) {
        use super::object::Object;
        let mut code: usize = 0;
        for entry in entries {
            match entry {
                Object::Number(n) if *n >= 0.0 && *n < 256.0 => code = *n as usize,
                Object::Name(name) => {
                    if code < 256 {
                        self.table[code] = glyph_char(name).unwrap_or(UNDEFINED);
                    }
                    code += 1;
                }
                _ => {}
            }
        }
    }

    pub fn decode(&self, code: u8) -> char {
        self.table[usize::from(code)]
    }
}

impl Default for Encoding {
    fn default() -> Self {
        Self::base(None)
    }
}

pub fn glyph_char(name: &str) -> Option<char> {
    if let Some(hex) = name.strip_prefix("uni") {
        if hex.len() >= 4 && hex.len() % 4 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return u32::from_str_radix(&hex[..4], 16)
                .ok()
                .and_then(char::from_u32);
        }
    }
    if let Some(hex) = name.strip_prefix('u') {
        if (4..=6).contains(&hex.len()) && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return u32::from_str_radix(hex, 16).ok().and_then(char::from_u32);
        }
    }
    if let Ok(at) = GLYPH_NAMES.binary_search_by(|(n, _)| (*n).cmp(name)) {
        return Some(GLYPH_NAMES[at].1);
    }
    if let Some((base, _)) = name.split_once('.') {
        if !base.is_empty() && base != name {
            return glyph_char(base);
        }
    }
    let mut chars = name.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => Some(c),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::object::Object;

    #[test]
    fn the_generated_tables_are_the_right_shape() {
        assert_eq!(WIN_ANSI_HIGH.chars().count(), 128);
        assert_eq!(MAC_ROMAN_HIGH.chars().count(), 128);
        assert!(
            GLYPH_NAMES.windows(2).all(|w| w[0].0 < w[1].0),
            "the glyph table is not sorted"
        );
        assert!(GLYPH_NAMES.len() > 300);
    }

    #[test]
    fn the_mac_roman_table_decodes_what_a_real_producer_emitted() {
        let mac = Encoding::base(Some("MacRomanEncoding"));
        assert_eq!(mac.decode(0x8E), 'é');
        assert_eq!(mac.decode(0xD1), '—');
        assert_eq!(mac.decode(0xA5), '•');
        let win = Encoding::base(Some("WinAnsiEncoding"));
        assert_ne!(win.decode(0x8E), 'é');
        assert_ne!(win.decode(0xD1), '—');
    }

    #[test]
    fn the_win_ansi_table_has_the_two_differences_the_spec_lists() {
        let win = Encoding::base(Some("WinAnsiEncoding"));
        assert_eq!(win.decode(0xA0), ' ');
        assert_eq!(win.decode(0xAD), '-');
        assert_eq!(win.decode(0x80), '€');
        assert_eq!(win.decode(0x92), '\u{2019}');
    }

    #[test]
    fn the_lower_half_is_ascii_in_every_encoding() {
        for name in [None, Some("WinAnsiEncoding"), Some("MacRomanEncoding")] {
            let enc = Encoding::base(name);
            for b in 0u8..0x80 {
                assert_eq!(enc.decode(b), char::from(b), "{name:?} at {b}");
            }
        }
    }

    #[test]
    fn an_unknown_base_encoding_falls_back_rather_than_failing() {
        let unknown = Encoding::base(Some("SomethingElseEncoding"));
        assert_eq!(unknown.decode(b'A'), 'A');
        assert_eq!(unknown, Encoding::base(None));
        assert_eq!(Encoding::default(), Encoding::base(None));
    }

    #[test]
    fn differences_override_individual_codes_by_name() {
        let mut enc = Encoding::base(Some("WinAnsiEncoding"));
        enc.apply_differences(&[
            Object::Number(65.0),
            Object::Name("emdash".into()),
            Object::Name("bullet".into()),
            Object::Number(200.0),
            Object::Name("eacute".into()),
        ]);
        assert_eq!(enc.decode(65), '—');
        assert_eq!(enc.decode(66), '•');
        assert_eq!(enc.decode(200), 'é');
        assert_eq!(enc.decode(67), 'C');
    }

    #[test]
    fn differences_ignore_entries_that_make_no_sense() {
        let mut enc = Encoding::base(None);
        enc.apply_differences(&[
            Object::Number(-5.0),
            Object::Number(999.0),
            Object::Bool(true),
            Object::Null,
            Object::Name("A".into()),
        ]);
        assert_eq!(enc.decode(b'Z'), 'Z');
        let mut from_zero = Encoding::base(None);
        from_zero.apply_differences(&[Object::Name("bullet".into())]);
        assert_eq!(from_zero.decode(0), '•');
    }

    #[test]
    fn an_unknown_glyph_name_is_undefined_rather_than_guessed() {
        let mut enc = Encoding::base(None);
        enc.apply_differences(&[Object::Number(65.0), Object::Name("gXYZnotaglyph".into())]);
        assert_eq!(enc.decode(65), UNDEFINED);
    }

    #[test]
    fn glyph_names_resolve_by_table_escape_and_single_character() {
        assert_eq!(glyph_char("space"), Some(' '));
        assert_eq!(glyph_char("eacute"), Some('é'));
        assert_eq!(glyph_char("Aring"), Some('Å'));
        assert_eq!(glyph_char("emdash"), Some('—'));
        assert_eq!(glyph_char("fi"), Some('\u{FB01}'));
        assert_eq!(glyph_char("uni0041"), Some('A'));
        assert_eq!(glyph_char("uni20AC"), Some('€'));
        assert_eq!(glyph_char("u1F600"), Some('\u{1F600}'));
        assert_eq!(glyph_char("u0041"), Some('A'));
        assert_eq!(glyph_char("a.sc"), Some('a'));
        assert_eq!(glyph_char("one.oldstyle"), Some('1'));
        assert_eq!(glyph_char("Z"), Some('Z'));
        assert_eq!(glyph_char("notaglyphname"), None);
        assert_eq!(glyph_char(""), None);
        assert_eq!(glyph_char("uniZZZZ"), None);
        assert_eq!(glyph_char("uni00"), None);
        assert_eq!(glyph_char("u12"), None);
    }

    #[test]
    fn a_glyph_escape_naming_a_surrogate_yields_nothing() {
        assert_eq!(glyph_char("uniD800"), None);
        assert_eq!(glyph_char("uD800"), None);
    }
}
