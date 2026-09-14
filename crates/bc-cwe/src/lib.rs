//! CWE id -> canonical MITRE name. Single source of truth for Markdown
//! rendering, SARIF emission, and any report annotation. Unknown ids
//! resolve to `""` so callers can safely fall back to the bare id.

/// Return the MITRE name for `"CWE-NNN"`, or `""` if unknown/absent.
/// Matching is case-insensitive and tolerant of surrounding whitespace.
pub fn cwe_name(cwe_id: Option<&str>) -> &'static str {
    let Some(id) = cwe_id.map(str::trim).filter(|s| !s.is_empty()) else {
        return "";
    };
    lookup_name(&id.to_uppercase())
}

/// Return `cwe_id` (normalized to uppercase) if given, else the
/// [`VulnClass`]-keyed fallback, else `None`. `vuln_class` is the class's
/// string value (e.g. `"use-after-free"`), matching the Python source's
/// `VulnClass.value`.
pub fn cwe_for(cwe_id: Option<&str>, vuln_class: Option<&str>) -> Option<String> {
    if let Some(id) = cwe_id.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(id.to_uppercase());
    }
    let fallback = lookup_vulnclass_fallback(vuln_class.unwrap_or(""));
    (!fallback.is_empty()).then(|| fallback.to_string())
}

/// `"CWE-862 - Missing Authorization"`, or just `"CWE-862"` if the name is
/// unknown, or `""` if `cwe_id` is absent/empty. Uses the raw (not
/// uppercased) `cwe_id` in the returned label — only the lookup itself
/// normalizes case.
pub fn cwe_label(cwe_id: Option<&str>) -> String {
    let Some(id) = cwe_id.filter(|s| !s.is_empty()) else {
        return String::new();
    };
    let name = cwe_name(Some(id));
    if name.is_empty() {
        id.to_string()
    } else {
        format!("{id} - {name}")
    }
}

fn lookup_name(id: &str) -> &'static str {
    match id {
        "CWE-20" => "Improper Input Validation",
        "CWE-22" => "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
        "CWE-73" => "External Control of File Name or Path",
        "CWE-74" => "Improper Neutralization of Special Elements in Output (Injection)",
        "CWE-77" => "Improper Neutralization of Special Elements used in a Command (Command Injection)",
        "CWE-78" => "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
        "CWE-79" => "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
        "CWE-89" => "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
        "CWE-90" => "Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)",
        "CWE-94" => "Improper Control of Generation of Code (Code Injection)",
        "CWE-95" => "Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)",
        "CWE-119" => "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "CWE-120" => "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
        "CWE-121" => "Stack-based Buffer Overflow",
        "CWE-122" => "Heap-based Buffer Overflow",
        "CWE-125" => "Out-of-bounds Read",
        "CWE-134" => "Use of Externally-Controlled Format String",
        "CWE-190" => "Integer Overflow or Wraparound",
        "CWE-200" => "Exposure of Sensitive Information to an Unauthorized Actor",
        "CWE-209" => "Generation of Error Message Containing Sensitive Information",
        "CWE-269" => "Improper Privilege Management",
        "CWE-276" => "Incorrect Default Permissions",
        "CWE-284" => "Improper Access Control",
        "CWE-285" => "Improper Authorization",
        "CWE-287" => "Improper Authentication",
        "CWE-294" => "Authentication Bypass by Capture-replay",
        "CWE-295" => "Improper Certificate Validation",
        "CWE-306" => "Missing Authentication for Critical Function",
        "CWE-311" => "Missing Encryption of Sensitive Data",
        "CWE-312" => "Cleartext Storage of Sensitive Information",
        "CWE-319" => "Cleartext Transmission of Sensitive Information",
        "CWE-326" => "Inadequate Encryption Strength",
        "CWE-327" => "Use of a Broken or Risky Cryptographic Algorithm",
        "CWE-330" => "Use of Insufficiently Random Values",
        "CWE-345" => "Insufficient Verification of Data Authenticity",
        "CWE-347" => "Improper Verification of Cryptographic Signature",
        "CWE-352" => "Cross-Site Request Forgery (CSRF)",
        "CWE-362" => {
            "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)"
        }
        "CWE-367" => "Time-of-check Time-of-use (TOCTOU) Race Condition",
        "CWE-384" => "Session Fixation",
        "CWE-400" => "Uncontrolled Resource Consumption",
        "CWE-416" => "Use After Free",
        "CWE-426" => "Untrusted Search Path",
        "CWE-434" => "Unrestricted Upload of File with Dangerous Type",
        "CWE-444" => "Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)",
        "CWE-476" => "NULL Pointer Dereference",
        "CWE-489" => "Active Debug Code",
        "CWE-502" => "Deserialization of Untrusted Data",
        "CWE-522" => "Insufficiently Protected Credentials",
        "CWE-532" => "Insertion of Sensitive Information into Log File",
        "CWE-552" => "Files or Directories Accessible to External Parties",
        "CWE-601" => "URL Redirection to Untrusted Site (Open Redirect)",
        "CWE-611" => "Improper Restriction of XML External Entity Reference",
        "CWE-639" => "Authorization Bypass Through User-Controlled Key",
        "CWE-640" => "Weak Password Recovery Mechanism for Forgotten Password",
        "CWE-643" => "Improper Neutralization of Data within XPath Expressions (XPath Injection)",
        "CWE-668" => "Exposure of Resource to Wrong Sphere",
        "CWE-693" => "Protection Mechanism Failure",
        "CWE-732" => "Incorrect Permission Assignment for Critical Resource",
        "CWE-770" => "Allocation of Resources Without Limits or Throttling",
        "CWE-787" => "Out-of-bounds Write",
        "CWE-798" => "Use of Hard-coded Credentials",
        "CWE-829" => "Inclusion of Functionality from Untrusted Control Sphere",
        "CWE-840" => "Business Logic Errors",
        "CWE-841" => "Improper Enforcement of Behavioral Workflow",
        "CWE-843" => "Access of Resource Using Incompatible Type (Type Confusion)",
        "CWE-862" => "Missing Authorization",
        "CWE-863" => "Incorrect Authorization",
        "CWE-915" => "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        "CWE-918" => "Server-Side Request Forgery (SSRF)",
        "CWE-923" => "Improper Restriction of Communication Channel to Intended Endpoints",
        "CWE-1021" => "Improper Restriction of Rendered UI Layers or Frames",
        "CWE-1104" => "Use of Unmaintained Third Party Components",
        "CWE-1188" => "Initialization of a Resource with an Insecure Default",
        "CWE-1236" => "Improper Neutralization of Formula Elements in a CSV File",
        "CWE-1333" => "Inefficient Regular Expression Complexity",
        "CWE-1390" => "Weak Authentication",
        _ => "",
    }
}

/// `VulnClass` value -> canonical CWE fallback, used when a finding carries
/// only a vuln class and no explicit CWE.
fn lookup_vulnclass_fallback(vuln_class: &str) -> &'static str {
    match vuln_class {
        "use-after-free" => "CWE-416",
        "heap-overflow" => "CWE-122",
        "stack-overflow" => "CWE-121",
        "format-string" => "CWE-134",
        "integer-overflow" => "CWE-190",
        "type-confusion" => "CWE-843",
        "race-condition" => "CWE-362",
        "injection" => "CWE-74",
        "unsafe-deserialization" => "CWE-502",
        "logic-flaw" => "CWE-840",
        "info-leak" => "CWE-200",
        "other" => "",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("CWE-862", "Missing Authorization")]
    #[case("cwe-862", "Missing Authorization")]
    #[case("  CWE-862  ", "Missing Authorization")]
    #[case(
        "CWE-79",
        "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)"
    )]
    fn cwe_name_known(#[case] id: &str, #[case] expected: &str) {
        assert_eq!(cwe_name(Some(id)), expected);
    }

    /// Every entry in the CWE_NAMES table, transcribed 1:1 from the Python
    /// reference (`vvaharness/report/cwe.py`). Exercising every arm both
    /// catches transcription typos in a ~80-entry hand-copied table and
    /// gives real (not incidental) coverage of the whole lookup.
    #[test]
    fn cwe_name_covers_every_table_entry() {
        let table: &[(&str, &str)] = &[
            ("CWE-20", "Improper Input Validation"),
            (
                "CWE-22",
                "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
            ),
            ("CWE-73", "External Control of File Name or Path"),
            (
                "CWE-74",
                "Improper Neutralization of Special Elements in Output (Injection)",
            ),
            (
                "CWE-77",
                "Improper Neutralization of Special Elements used in a Command (Command Injection)",
            ),
            (
                "CWE-78",
                "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
            ),
            (
                "CWE-79",
                "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
            ),
            (
                "CWE-89",
                "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
            ),
            (
                "CWE-90",
                "Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)",
            ),
            ("CWE-94", "Improper Control of Generation of Code (Code Injection)"),
            (
                "CWE-95",
                "Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)",
            ),
            (
                "CWE-119",
                "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            ),
            (
                "CWE-120",
                "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
            ),
            ("CWE-121", "Stack-based Buffer Overflow"),
            ("CWE-122", "Heap-based Buffer Overflow"),
            ("CWE-125", "Out-of-bounds Read"),
            ("CWE-134", "Use of Externally-Controlled Format String"),
            ("CWE-190", "Integer Overflow or Wraparound"),
            (
                "CWE-200",
                "Exposure of Sensitive Information to an Unauthorized Actor",
            ),
            (
                "CWE-209",
                "Generation of Error Message Containing Sensitive Information",
            ),
            ("CWE-269", "Improper Privilege Management"),
            ("CWE-276", "Incorrect Default Permissions"),
            ("CWE-284", "Improper Access Control"),
            ("CWE-285", "Improper Authorization"),
            ("CWE-287", "Improper Authentication"),
            ("CWE-294", "Authentication Bypass by Capture-replay"),
            ("CWE-295", "Improper Certificate Validation"),
            ("CWE-306", "Missing Authentication for Critical Function"),
            ("CWE-311", "Missing Encryption of Sensitive Data"),
            ("CWE-312", "Cleartext Storage of Sensitive Information"),
            ("CWE-319", "Cleartext Transmission of Sensitive Information"),
            ("CWE-326", "Inadequate Encryption Strength"),
            ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
            ("CWE-330", "Use of Insufficiently Random Values"),
            ("CWE-345", "Insufficient Verification of Data Authenticity"),
            ("CWE-347", "Improper Verification of Cryptographic Signature"),
            ("CWE-352", "Cross-Site Request Forgery (CSRF)"),
            (
                "CWE-362",
                "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)",
            ),
            ("CWE-367", "Time-of-check Time-of-use (TOCTOU) Race Condition"),
            ("CWE-384", "Session Fixation"),
            ("CWE-400", "Uncontrolled Resource Consumption"),
            ("CWE-416", "Use After Free"),
            ("CWE-426", "Untrusted Search Path"),
            ("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
            (
                "CWE-444",
                "Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)",
            ),
            ("CWE-476", "NULL Pointer Dereference"),
            ("CWE-489", "Active Debug Code"),
            ("CWE-502", "Deserialization of Untrusted Data"),
            ("CWE-522", "Insufficiently Protected Credentials"),
            ("CWE-532", "Insertion of Sensitive Information into Log File"),
            ("CWE-552", "Files or Directories Accessible to External Parties"),
            ("CWE-601", "URL Redirection to Untrusted Site (Open Redirect)"),
            ("CWE-611", "Improper Restriction of XML External Entity Reference"),
            ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
            (
                "CWE-640",
                "Weak Password Recovery Mechanism for Forgotten Password",
            ),
            (
                "CWE-643",
                "Improper Neutralization of Data within XPath Expressions (XPath Injection)",
            ),
            ("CWE-668", "Exposure of Resource to Wrong Sphere"),
            ("CWE-693", "Protection Mechanism Failure"),
            (
                "CWE-732",
                "Incorrect Permission Assignment for Critical Resource",
            ),
            (
                "CWE-770",
                "Allocation of Resources Without Limits or Throttling",
            ),
            ("CWE-787", "Out-of-bounds Write"),
            ("CWE-798", "Use of Hard-coded Credentials"),
            (
                "CWE-829",
                "Inclusion of Functionality from Untrusted Control Sphere",
            ),
            ("CWE-840", "Business Logic Errors"),
            ("CWE-841", "Improper Enforcement of Behavioral Workflow"),
            (
                "CWE-843",
                "Access of Resource Using Incompatible Type (Type Confusion)",
            ),
            ("CWE-862", "Missing Authorization"),
            ("CWE-863", "Incorrect Authorization"),
            (
                "CWE-915",
                "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
            ),
            ("CWE-918", "Server-Side Request Forgery (SSRF)"),
            (
                "CWE-923",
                "Improper Restriction of Communication Channel to Intended Endpoints",
            ),
            ("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"),
            ("CWE-1104", "Use of Unmaintained Third Party Components"),
            (
                "CWE-1188",
                "Initialization of a Resource with an Insecure Default",
            ),
            (
                "CWE-1236",
                "Improper Neutralization of Formula Elements in a CSV File",
            ),
            ("CWE-1333", "Inefficient Regular Expression Complexity"),
            ("CWE-1390", "Weak Authentication"),
        ];
        for (id, expected) in table {
            assert_eq!(cwe_name(Some(id)), *expected, "mismatch for {id}");
        }
    }

    #[test]
    fn cwe_name_unknown_or_absent() {
        assert_eq!(cwe_name(Some("CWE-999999")), "");
        assert_eq!(cwe_name(None), "");
        assert_eq!(cwe_name(Some("")), "");
        assert_eq!(cwe_name(Some("   ")), "");
    }

    #[test]
    fn cwe_for_prefers_explicit_id() {
        assert_eq!(
            cwe_for(Some("cwe-79"), Some("injection")),
            Some("CWE-79".to_string())
        );
    }

    #[rstest]
    #[case("use-after-free", "CWE-416")]
    #[case("heap-overflow", "CWE-122")]
    #[case("stack-overflow", "CWE-121")]
    #[case("format-string", "CWE-134")]
    #[case("integer-overflow", "CWE-190")]
    #[case("type-confusion", "CWE-843")]
    #[case("race-condition", "CWE-362")]
    #[case("injection", "CWE-74")]
    #[case("unsafe-deserialization", "CWE-502")]
    #[case("logic-flaw", "CWE-840")]
    #[case("info-leak", "CWE-200")]
    fn cwe_for_falls_back_to_vulnclass(#[case] vuln_class: &str, #[case] expected: &str) {
        assert_eq!(cwe_for(None, Some(vuln_class)), Some(expected.to_string()));
    }

    #[test]
    fn cwe_for_other_and_unknown_vulnclass_yield_none() {
        assert_eq!(cwe_for(None, Some("other")), None);
        assert_eq!(cwe_for(None, Some("totally-unknown")), None);
        assert_eq!(cwe_for(None, None), None);
    }

    #[test]
    fn cwe_label_known_unknown_and_empty() {
        assert_eq!(
            cwe_label(Some("CWE-862")),
            "CWE-862 - Missing Authorization"
        );
        assert_eq!(cwe_label(Some("CWE-999999")), "CWE-999999");
        assert_eq!(cwe_label(None), "");
        assert_eq!(cwe_label(Some("")), "");
    }
}
