//! Cross-checks `bc_redact::redact_counts` against the real
//! `vvaharness.report.redact.redact_counts` over one representative case
//! per pattern (and per false-positive guard) — the pattern space itself
//! isn't enumerable the way CVSS's fixed metric alphabet is, so this is a
//! curated table, not an exhaustive one.

mod support;

use std::collections::BTreeMap;

fn counts_as_btreemap(v: &serde_json::Value) -> BTreeMap<String, u32> {
    v.as_object()
        .expect("counts is a JSON object")
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                v.as_u64().expect("count is a non-negative integer") as u32,
            )
        })
        .collect()
}

#[test]
fn redact_counts_matches_the_python_original_across_every_pattern() {
    let Some(py) = support::resolve() else {
        return;
    };

    let cases: &[&str] = &[
        // PAN — Luhn + IIN gated.
        "card number 4111111111111111 on file",
        "spaced pan 4111 1111 1111 1111 here",
        "amex 378282246310005 expires soon",
        "not a card: 1234567890123456", // fails Luhn/IIN, must NOT mask
        // CVV
        "cvv: 123",
        "cvc2=4321",
        // Track data
        "track %B4111111111111111^DOE/JOHN?1234567890? end",
        // SSN separated, valid vs structurally-impossible
        "ssn on file 123-45-6789 confirmed",
        "area zero 000-12-3456 is not a real ssn",
        "group zero 123-00-6789 is not a real ssn",
        // SSN keyword-gated bare 9 digits
        "SSN: 123456789 recorded",
        "itin 987654321 on the form",
        "just a number 123456789 with no keyword", // must NOT mask
        // Cloud/SaaS credentials
        "aws key AKIAAAAAAAAAAAAAAAAA in env",
        "gh token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa leaked",
        "slack xoxb-11111111111111111111 here",
        // Split so the file never contains a contiguous Stripe-shaped
        // literal: GitHub push protection blocks one on sight, and this
        // repository should not ship a string that trips a scanner.
        // `concat!` rebuilds it at compile time, so the case is unchanged.
        concat!("stripe sk_", "test_", "aaaaaaaaaaaaaaaaaaaaaaaa in code"),
        "google key AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA set",
        "azure sig=aaaaaaaaaaaaaaaaaaaaaaaaa%2Bxyz in url",
        "twilio SK00000000000000000000000000000000 used",
        // JWT
        "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQfake token",
        // Bearer / Basic
        "Authorization: Bearer abc123XYZ.token-value here",
        "uses HTTP Basic Authentication for the demo", // all-alpha value, must NOT mask
        // URL userinfo credential
        "connect to https://user:secretpass1@db.example.com/app",
        // Private key block
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----",
        // Generic secret assignment
        "password: \"hunter2value\"",
        "apiKey: \"abc123secretvalue\"",
        "secret: management",      // plain lowercase prose word, must NOT mask
        "token = parse(x)",        // code-expression shape, must NOT mask
        "token=[REDACTED-SECRET]", // already a placeholder, idempotent
        // No match at all
        "just an ordinary sentence with no sensitive data",
        "",
    ];

    let input = serde_json::to_value(cases).unwrap();
    let oracle_out = py.run_oracle("redact_oracle.py", &input);
    let oracle_out = oracle_out.as_array().expect("oracle returns a JSON array");
    assert_eq!(oracle_out.len(), cases.len());

    let mut mismatches = Vec::new();
    for (case, entry) in cases.iter().zip(oracle_out) {
        let (rust_redacted, rust_counts) = bc_redact::redact_counts(case);
        let rust_counts: BTreeMap<String, u32> = rust_counts.into_iter().collect();

        let py_redacted = entry.get("redacted").unwrap().as_str().unwrap();
        let py_counts = counts_as_btreemap(entry.get("counts").unwrap());

        if rust_redacted != py_redacted || rust_counts != py_counts {
            mismatches.push(format!(
                "{case:?}:\n  rust=({rust_redacted:?}, {rust_counts:?})\n  python=({py_redacted:?}, {py_counts:?})"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} cases mismatched:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n")
    );
}
