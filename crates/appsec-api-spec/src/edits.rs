use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextEdit {
    pub old: String,
    pub new: String,
}

pub const MAX_EDITS: usize = 256;

pub fn apply_edits(original: &str, edits: &[TextEdit]) -> Result<String, String> {
    if edits.len() > MAX_EDITS {
        return Err(format!(
            "{} edits exceed the {MAX_EDITS}-edit repair limit",
            edits.len()
        ));
    }
    let mut text = original.to_string();
    for (index, edit) in edits.iter().enumerate() {
        if edit.old.is_empty() {
            return Err(format!("edit {index}: `old` is empty"));
        }
        match text.matches(edit.old.as_str()).count() {
            1 => text = text.replacen(edit.old.as_str(), &edit.new, 1),
            0 => {
                return Err(format!(
                    "edit {index}: `old` text was not found; copy it exactly from the current file"
                ))
            }
            count => {
                return Err(format!(
                    "edit {index}: `old` text occurs {count} times; include enough surrounding \
                     text to make it unique"
                ))
            }
        }
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(old: &str, new: &str) -> TextEdit {
        TextEdit {
            old: old.into(),
            new: new.into(),
        }
    }

    #[test]
    fn edits_apply_in_order_against_the_updated_text() {
        let text = "a: 1\nb: 2\n";
        let result = apply_edits(
            text,
            &[edit("a: 1", "a: 10"), edit("a: 10\n", "a: 10\nc: 3\n")],
        );
        assert_eq!(result.unwrap(), "a: 10\nc: 3\nb: 2\n");
        assert_eq!(apply_edits(text, &[]).unwrap(), text);
    }

    #[test]
    fn ambiguous_missing_empty_and_excessive_edits_are_refused() {
        let text = "x: 1\nx: 1\n";
        assert!(apply_edits(text, &[edit("x: 1", "y")])
            .unwrap_err()
            .contains("2 times"));
        assert!(apply_edits(text, &[edit("z", "y")])
            .unwrap_err()
            .contains("not found"));
        assert!(apply_edits(text, &[edit("", "y")])
            .unwrap_err()
            .contains("empty"));
        let many = vec![edit("x", "x"); MAX_EDITS + 1];
        assert!(apply_edits(text, &many).unwrap_err().contains("limit"));
    }
}
