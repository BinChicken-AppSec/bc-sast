pub fn credential_lines(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            appsec_redact::redact(line) != *line || line.contains("PRIVATE KEY-----")
        })
        .map(|(index, _)| index + 1)
        .collect()
}

pub fn problems(text: &str) -> Vec<String> {
    let lines = credential_lines(text);
    if !lines.is_empty() {
        return vec![format!(
            "line(s) {lines:?} contain values that look like credentials; use a placeholder \
             such as <api-key> and describe mechanisms, not values"
        )];
    }
    if appsec_redact::redact(text) != text {
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
