//! Keeping credentials out of generated specification text.
//!
//! A specification should describe how a client authenticates (a bearer
//! scheme, an API key header name, OAuth2 flows) without any value that
//! could be a real secret. Proposed text is checked line by line with
//! `bc_redact`, the same redactor that guards every artifact this tool
//! writes. Any line the redactor would change is a credential-looking
//! value and the proposal is refused.
//!
//! Lines rather than the whole text, because the redactor's keyword rule
//! (`password: <value>`) spans whitespace: in block YAML a `password:`
//! property followed on the next line by its nested `description:` key
//! would otherwise read as a password whose value is `description`.
//! Private key blocks span lines by construction, so their armor marker
//! is matched on its own.

/// 1-based numbers of the lines in `text` that look like credentials.
pub fn credential_lines(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| bc_redact::redact(line) != *line || line.contains("PRIVATE KEY-----"))
        .map(|(index, _)| index + 1)
        .collect()
}

/// Why `text` must not be written, if it must not: each credential-looking
/// line, or, when only the whole text trips the redactor (a pattern that
/// spans lines), that fact. Both views matter because branch delivery
/// refuses to publish a changed file whose full text the redactor would
/// change, so a file that passes line by line can still block delivery.
pub fn problems(text: &str) -> Vec<String> {
    let lines = credential_lines(text);
    if !lines.is_empty() {
        return vec![format!(
            "line(s) {lines:?} contain values that look like credentials; use a placeholder \
             such as <api-key> and describe mechanisms, not values"
        )];
    }
    if bc_redact::redact(text) != text {
        return vec![
            "the text contains a value that looks like a credential across line breaks; \
                     reorder or rephrase it"
                .to_string(),
        ];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problems_cover_single_lines_and_multi_line_patterns() {
        assert!(problems("\"x\": \"<api-key>\"\n").is_empty());
        assert!(problems("\"example\": \"token: abcdef123456\"\n")[0].contains("line(s) [1]"));
        let spanning = "password:\n  description: The account password\n";
        assert!(credential_lines(spanning).is_empty());
        assert!(problems(spanning)[0].contains("across line breaks"));
    }

    #[test]
    fn credential_looking_values_are_found_by_line() {
        let text = "\
\"securitySchemes\":
  \"bearer\":
    \"type\": \"http\"
    \"scheme\": \"bearer\"
\"password\":
  \"description\": \"The account password\"
\"example\": \"ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\"
\"x-token\": \"token: abcdefgh12345\"
-----BEGIN RSA PRIVATE KEY-----
";
        assert_eq!(credential_lines(text), [7, 8, 9]);
    }

    #[test]
    fn placeholders_and_mechanism_descriptions_are_accepted() {
        let text = "\
\"name\": \"X-API-Key\"
\"in\": \"header\"
\"example\": \"<api-key>\"
\"bearerFormat\": \"JWT\"
";
        assert!(credential_lines(text).is_empty());
    }
}
