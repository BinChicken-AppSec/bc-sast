//! Tests for [`redact_diff`]. The load-bearing property is structural:
//! after redaction every hunk must still carry exactly as many old-side
//! and new-side lines as its header claims, each with its original
//! prefix, so the patch still parses (and applies) as the same patch.

use super::*;

/// Every hunk's header counts against its actual body, as
/// `(old_claimed, old_seen, new_claimed, new_seen)`.
fn hunk_counts(diff: &str) -> Vec<(usize, usize, usize, usize)> {
    let mut out = Vec::new();
    let mut current: Option<(usize, usize, usize, usize)> = None;
    for line in diff.split('\n') {
        if let Some(caps) = HUNK_HEADER_RE.captures(line).unwrap() {
            if let Some(done) = current.take() {
                out.push(done);
            }
            let n = |name: &str| caps.name(name).map_or(1, |m| m.as_str().parse().unwrap());
            current = Some((n("old"), 0, n("new"), 0));
            continue;
        }
        let Some(hunk) = current.as_mut() else {
            continue;
        };
        if hunk.1 == hunk.0 && hunk.3 == hunk.2 {
            out.push(current.take().unwrap());
            continue;
        }
        match line.chars().next() {
            Some(' ') => {
                hunk.1 += 1;
                hunk.3 += 1;
            }
            Some('-') => hunk.1 += 1,
            Some('+') => hunk.3 += 1,
            _ => {}
        }
    }
    out.extend(current);
    out
}

fn assert_framing_survives(original: &str, redacted: &str) {
    assert_eq!(
        original.matches('\n').count(),
        redacted.matches('\n').count(),
        "line count changed:\n{redacted}"
    );
    for (a, b) in original.split('\n').zip(redacted.split('\n')) {
        if is_structure(a) || a.starts_with("@@") {
            assert!(
                b.starts_with(&a[..a.find(" @@").map_or(a.len(), |i| i + 3)]),
                "{a:?} became {b:?}"
            );
        } else {
            assert_eq!(a.chars().next(), b.chars().next(), "{a:?} became {b:?}");
        }
    }
    for (old_claimed, old_seen, new_claimed, new_seen) in hunk_counts(redacted) {
        assert_eq!(
            (old_claimed, new_claimed),
            (old_seen, new_seen),
            "{redacted}"
        );
    }
}

const PEM_DIFF: &str = "\
diff --git a/config/keys.py b/config/keys.py
index 1111111..2222222 100644
--- a/config/keys.py
+++ b/config/keys.py
@@ -1,6 +1,2 @@ def load():
-KEY = \"\"\"-----BEGIN RSA PRIVATE KEY-----
-MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun
-VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK
-ab==
------END RSA PRIVATE KEY-----\"\"\"
+KEY = os.environ[\"SIGNING_KEY\"]
 def sign(data):
";

#[test]
fn a_removed_pem_block_is_masked_line_by_line_and_the_framing_survives() {
    let redacted = redact_diff(PEM_DIFF);
    assert_framing_survives(PEM_DIFF, &redacted);
    assert!(!redacted.contains("MIIEowIBAAKCAQEA"), "{redacted}");
    assert!(!redacted.contains("VTLw7onLRnrq0"), "{redacted}");
    assert!(!redacted.contains("-----BEGIN RSA"), "{redacted}");
    // The short trailing fragment is only recognizable once END arrives.
    assert!(!redacted.contains("\n-ab==\n"), "{redacted}");
    // Framing and the safe replacement read are untouched.
    assert!(redacted.starts_with(
        "diff --git a/config/keys.py b/config/keys.py\nindex 1111111..2222222 100644\n"
    ));
    assert!(redacted.contains("\n@@ -1,6 +1,2 @@ def load():\n"));
    assert!(
        redacted.contains("\n+KEY = os.environ[\"SIGNING_KEY\"]\n"),
        "{redacted}"
    );
    assert!(redacted.ends_with("\n def sign(data):\n"));
}

#[test]
fn plain_redact_would_have_collapsed_the_same_hunk() {
    // Why this module exists: the whole-text redactor matches the PEM
    // block across lines and eats the hunk's line structure.
    let collapsed = crate::redact(PEM_DIFF);
    assert_ne!(
        collapsed.matches('\n').count(),
        PEM_DIFF.matches('\n').count()
    );
}

#[test]
fn a_hardcoded_secret_on_a_removed_line_is_masked_and_a_safe_read_is_kept() {
    let diff = "\
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
-password = \"hunter2hunter2\"
+password = os.environ.get(\"DB_PASSWORD\")
 api_key = process.env.API_KEY;
";
    let redacted = redact_diff(diff);
    assert_framing_survives(diff, &redacted);
    assert!(!redacted.contains("hunter2"), "{redacted}");
    assert!(
        redacted.contains("-password = \"[REDACTED-SECRET]\""),
        "{redacted}"
    );
    assert!(
        redacted.contains("+password = os.environ.get(\"DB_PASSWORD\")\n"),
        "{redacted}"
    );
    assert!(
        redacted.contains(" api_key = process.env.API_KEY;\n"),
        "{redacted}"
    );
}

#[test]
fn several_safe_reads_on_one_line_and_a_marker_collision_are_handled() {
    let text = "token = config.TOKEN  # ${BCSAST_SAFE_CONFIG_READ_0}";
    assert_eq!(redact_diff_text(text), text);
    // Only a read that ends the statement is safe: the first one here is
    // followed by more code, so it is masked as Python masks it, while the
    // line's final read survives.
    let two = "a = 1; secret = settings[\"S\"]; password = settings.DB_PASS";
    assert_eq!(
        redact_diff_text(two),
        "a = 1; secret = [REDACTED-SECRET]\"S\"]; password = settings.DB_PASS"
    );
}

#[test]
fn a_crlf_diff_keeps_every_line_ending() {
    let diff = "--- a/x\r\n+++ b/x\r\n@@ -1 +1 @@\r\n-token: \"abcdefghijklmnop\"\r\n+token: \"${TOKEN}\"\r\n";
    let redacted = redact_diff(diff);
    assert_eq!(redacted.matches("\r\n").count(), 5, "{redacted:?}");
    assert!(!redacted.contains("abcdefghijklmnop"));
    assert!(redacted.contains("+token: \"${TOKEN}\"\r\n"));
}

#[test]
fn a_diff_without_a_trailing_newline_is_preserved() {
    let diff = "@@ -1 +1 @@\n-a\n+b";
    assert_eq!(redact_diff(diff), diff);
}

#[test]
fn a_no_newline_note_is_passed_through_redacted() {
    let diff = "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n";
    assert_eq!(redact_diff(diff), diff);
}

#[test]
fn text_outside_a_hunk_is_redacted_but_structure_lines_are_not() {
    let diff = "\
# (synthesized diff for a non-git target)
note: password = \"hunter2hunter2\"
new file mode 100644
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+hello
";
    let redacted = redact_diff(diff);
    assert!(redacted.starts_with("# (synthesized diff for a non-git target)\n"));
    assert!(!redacted.contains("hunter2"));
    assert!(redacted.contains("\nnew file mode 100644\n--- /dev/null\n+++ b/new.txt\n"));
    assert_framing_survives(diff, &redacted);
}

#[test]
fn a_structure_line_inside_a_short_hunk_ends_it() {
    // The header claims three lines but the next file starts after two:
    // a truncated or hand-edited diff. The `diff --git` line is framing.
    let diff = "\
@@ -1,3 +1,3 @@
 a
-b
diff --git a/y b/y
--- a/y
+++ b/y
";
    assert_eq!(redact_diff(diff), diff);
}

#[test]
fn unknown_in_hunk_content_stays_in_the_masking_state() {
    // A line with no ` `/`+`/`-` prefix inside a PEM run is still masked.
    let diff = "\
@@ -1,4 +1,4 @@
------BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
-rest
------END PRIVATE KEY-----
";
    let redacted = redact_diff(diff);
    assert!(!redacted.contains("MIIEvQIBADAN"), "{redacted}");
    assert!(
        redacted.contains("\n[REDACTED-PRIVATE-KEY]\n"),
        "{redacted}"
    );
}

#[test]
fn a_hunk_header_trailer_is_redacted_but_the_range_is_not() {
    let diff = "@@ -1 +1 @@ password = \"hunter2hunter2\"\n-a\n+b\n";
    let redacted = redact_diff(diff);
    assert!(redacted.starts_with("@@ -1 +1 @@ password = \"[REDACTED-SECRET]\"\n"));
}

#[test]
fn an_added_pem_on_the_new_side_is_masked_independently_of_the_old_side() {
    let diff = "\
@@ -1,2 +1,5 @@
 x = 1
+PEM = '''-----BEGIN EC PRIVATE KEY-----
+MHcCAQEEIBkg
+-----END EC PRIVATE KEY-----'''
-y = 2
+y = 3
";
    let redacted = redact_diff(diff);
    assert_framing_survives(diff, &redacted);
    assert!(!redacted.contains("MHcCAQEEIBkg"), "{redacted}");
    assert!(redacted.ends_with("\n-y = 2\n+y = 3\n"), "{redacted}");
}

#[test]
fn pem_header_lines_and_explicit_short_context_are_recognized() {
    assert!(private_key_fragment("Proc-Type: 4,ENCRYPTED", false));
    assert!(private_key_fragment("<privateKey>abcd</privateKey>", false));
    assert!(private_key_fragment("private_key = \"abcd\"", false));
    assert!(private_key_fragment("abcd", true));
    assert!(!private_key_fragment("abcd", false));
    assert!(!private_key_fragment("print(x)", true));
}

#[test]
fn mask_private_key_body_merges_overlapping_spans_and_falls_back_to_the_whole_line() {
    assert_eq!(mask_private_key_body("print(x)"), PRIVATE_KEY_MASK);
    // The bare payload and its quoted form overlap; one mask results.
    assert_eq!(
        mask_private_key_body("\"MIIEvQIBADANBgkqhkiG9w0B\""),
        "\"[REDACTED-PRIVATE-KEY]\""
    );
    assert_eq!(
        mask_private_key_body("x -----END RSA PRIVATE KEY----- y"),
        "x [REDACTED-PRIVATE-KEY] y"
    );
}

#[test]
fn mask_diff_line_keeps_the_prefix_and_ending() {
    assert_eq!(
        mask_diff_line("-abcd\r\n"),
        format!("-{PRIVATE_KEY_MASK}\r\n")
    );
    assert_eq!(mask_diff_line(""), PRIVATE_KEY_MASK);
}

#[test]
fn an_empty_diff_is_empty() {
    assert_eq!(redact_diff(""), "");
}

/// End to end against real git: the redacted patch of a change that
/// carried no secret must still `git apply --check` cleanly. Skipped when
/// no `git` binary is available.
#[test]
fn a_redacted_patch_still_applies_with_git() {
    let git = |dir: &std::path::Path, args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
    };
    let dir = tempfile::tempdir().unwrap();
    if git(dir.path(), &["init", "-q"]).is_err() {
        return;
    }
    std::fs::write(
        dir.path().join("app.py"),
        "import os\npassword = os.environ[\"DB_PASSWORD\"]\nprint(1)\n",
    )
    .unwrap();
    // Build the diff by hand so the test does not depend on git's diff
    // configuration; `git apply` is the thing under test.
    let diff = "\
--- a/app.py
+++ b/app.py
@@ -1,3 +1,3 @@
 import os
-password = os.environ[\"DB_PASSWORD\"]
+password = os.environ[\"DB_PASSWORD_V2\"]
 print(1)
";
    let redacted = redact_diff(diff);
    assert_eq!(redacted, diff, "a safe read needs no masking");
    let patch = dir.path().join("fix.patch");
    std::fs::write(&patch, &redacted).unwrap();
    let check = git(dir.path(), &["apply", "--check", patch.to_str().unwrap()]).unwrap();
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
}
