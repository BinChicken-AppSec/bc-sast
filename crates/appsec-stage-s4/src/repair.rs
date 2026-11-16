use serde_json::Value;

use crate::findings_shape::findings_list;

pub(crate) const REPAIR_MAX_TOKENS: u32 = 12_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseFailure {
    Syntax(String),
    Shape(String),
}

impl std::fmt::Display for ParseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseFailure::Syntax(m) => write!(f, "invalid JSON: {m}"),
            ParseFailure::Shape(m) => write!(f, "wrong shape: {m}"),
        }
    }
}

pub(crate) fn parse_findings(raw: &str, truncated: bool) -> Result<Vec<Value>, ParseFailure> {
    let extracted = if truncated {
        appsec_json_repair::extract_truncated_json(raw)
    } else {
        appsec_json_repair::extract_json(raw)
    };
    let data = extracted.map_err(|e| ParseFailure::Syntax(e.to_string()))?;
    findings_list(&data).map_err(ParseFailure::Shape)
}

pub(crate) fn repair_json_prompt(raw: &str, failure: &ParseFailure) -> String {
    let task = match failure {
        ParseFailure::Shape(_) => {
            "The previous s4 response was VALID JSON but the wrong shape: it carried no usable \
             `findings` list.\nReturn ONLY a JSON object of the form {\"findings\": [...]}, \
             preserving every finding the response already describes. If it genuinely found \
             nothing, return exactly {\"findings\": []}. Do not rename the key and do not use \
             null for the list."
        }
        ParseFailure::Syntax(_) => {
            "The previous s4 response was intended to be JSON but failed to parse.\nFix the \
             JSON syntax only and return ONLY a valid JSON object that preserves the same \
             findings content as much as possible."
        }
    };
    format!("REPAIR TASK:\n{task}\n\nFAILURE:\n{failure}\n\nPREVIOUS RESPONSE:\n{raw}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_findings_distinguishes_syntax_from_shape() {
        assert!(matches!(
            parse_findings("not json", false),
            Err(ParseFailure::Syntax(_))
        ));
        assert!(matches!(
            parse_findings(r#"{"findings": null}"#, false),
            Err(ParseFailure::Shape(_))
        ));
        assert_eq!(
            parse_findings(r#"{"findings": []}"#, false).unwrap(),
            Vec::<Value>::new()
        );
    }

    #[test]
    fn the_shape_prompt_asks_for_the_key_not_a_syntax_fix() {
        let p = repair_json_prompt("{}", &ParseFailure::Shape("no list".into()));
        assert!(p.starts_with("REPAIR TASK:\nThe previous s4 response was VALID JSON"));
        assert!(p.contains("return exactly {\"findings\": []}"));
        assert!(p.contains("FAILURE:\nwrong shape: no list\n"));
        assert!(p.ends_with("PREVIOUS RESPONSE:\n{}\n"));
    }

    #[test]
    fn the_syntax_prompt_asks_for_a_syntax_fix_only() {
        let p = repair_json_prompt("{oops", &ParseFailure::Syntax("eof".into()));
        assert!(p.contains("Fix the JSON syntax only"));
        assert!(!p.contains("wrong shape"));
        assert!(p.contains("FAILURE:\ninvalid JSON: eof\n"));
    }
}
