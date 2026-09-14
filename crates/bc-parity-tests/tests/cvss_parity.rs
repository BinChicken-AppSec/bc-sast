//! Exhaustively cross-checks `bc_cvss::{score, rating}` against the real
//! `vvaharness.report.cvss` module over every valid CVSS 3.1 base vector
//! (4*2*3*2*2*3*3*3 = 2592 combinations) — small enough to enumerate fully
//! rather than sample.

mod support;

#[test]
fn score_and_rating_match_the_python_original_for_every_base_vector() {
    let Some(py) = support::resolve() else {
        return;
    };

    let mut vectors = Vec::with_capacity(2592);
    for av in ["N", "A", "L", "P"] {
        for ac in ["L", "H"] {
            for pr in ["N", "L", "H"] {
                for ui in ["N", "R"] {
                    for s in ["U", "C"] {
                        for c in ["N", "L", "H"] {
                            for i in ["N", "L", "H"] {
                                for a in ["N", "L", "H"] {
                                    vectors.push(format!(
                                        "CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(vectors.len(), 2592);

    let input = serde_json::to_value(&vectors).unwrap();
    let oracle_out = py.run_oracle("cvss_oracle.py", &input);
    let oracle_out = oracle_out.as_array().expect("oracle returns a JSON array");
    assert_eq!(oracle_out.len(), vectors.len());

    let mut mismatches = Vec::new();
    for (vector, entry) in vectors.iter().zip(oracle_out) {
        let rust_score = bc_cvss::score(Some(vector));
        let rust_rating = bc_cvss::rating(rust_score);

        let py_score = entry.get("score").unwrap().as_f64();
        let py_rating = entry.get("rating").unwrap().as_str().unwrap();

        let score_matches = match (rust_score, py_score) {
            (Some(r), Some(p)) => (r - p).abs() < 1e-9,
            (None, None) => true,
            _ => false,
        };
        if !score_matches || rust_rating != py_rating {
            mismatches.push(format!(
                "{vector}: rust=({rust_score:?}, {rust_rating}) python=({py_score:?}, {py_rating})"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} vectors mismatched:\n{}",
        mismatches.len(),
        vectors.len(),
        mismatches.join("\n")
    );
}

#[test]
fn score_and_rating_match_for_malformed_and_absent_vectors() {
    let Some(py) = support::resolve() else {
        return;
    };
    let vectors = vec![
        None,
        Some("".to_string()),
        Some("not a vector".to_string()),
        Some("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
        Some("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
    ];
    let input = serde_json::to_value(&vectors).unwrap();
    let oracle_out = py.run_oracle("cvss_oracle.py", &input);
    let oracle_out = oracle_out.as_array().unwrap();

    for (vector, entry) in vectors.iter().zip(oracle_out) {
        let rust_score = bc_cvss::score(vector.as_deref());
        let rust_rating = bc_cvss::rating(rust_score);
        let py_score = entry.get("score").unwrap().as_f64();
        let py_rating = entry.get("rating").unwrap().as_str().unwrap();
        assert_eq!(rust_score, py_score, "score mismatch for {vector:?}");
        assert_eq!(rust_rating, py_rating, "rating mismatch for {vector:?}");
    }
}
