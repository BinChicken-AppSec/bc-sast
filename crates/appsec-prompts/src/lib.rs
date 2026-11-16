pub const EXCLUSION_RULES: &str = "\
OUT OF SCOPE — do not report:

A. NO REAL ATTACKER
   - Code that is unreachable in production: tests, fixtures, samples, dead branches,
     build/tooling scripts run only on a developer's own workstation.
   - Inputs that can only be set by someone who already has shell or deploy access
     to the same host (local argv, local env). Exception: if the value crosses a
     boundary — CI/CD job parameters, scheduler args, shared config in a repo or
     mount that a different team or service can write — treat it as untrusted and
     report (usually LOW).

B. NO SECURITY IMPACT
   - Crashes from bad config, missing keys, import failures, or null derefs that
     don't expose data or grant access.
   - Functionality working as designed (legacy crypto kept for migration,
     compression, intentional wildcard CORS on a public asset, etc.).
   - Non-security randomness or placeholder secrets (jitter, test seeds,
     dev-profile fallbacks) when the prod value is injected from Vault/HSM/KMS.

C. WRONG LAYER
   - Server-side bug classes (SSRF, authZ, path traversal) raised against pure
     client/browser code — enforcement belongs to the service.
   - Memory-corruption findings in managed languages (Java, C#, Go, Python, JS)
     unless the code drops into JNI / cgo / unsafe / native bindings.
   - \"../\" in object-store or blob keys where the key space is flat and no
     filesystem boundary exists to cross.
   - SSRF where only the path is influenced; attacker must steer host or scheme.

D. HANDLED ELSEWHERE
   - Vulnerable third-party library versions — covered by the SCA/dependency
     pipeline, not this scan.
   - Pure volumetric / rate-limit DoS — infra concern. Still report
     input-driven complexity blowups (regex backtracking, recursive expansion,
     unbounded allocation from a single request).

E. NOISE FLOOR
   - Log injection / log forging with no downstream parser.
   - Prompt text passed to an LLM (tracked under the AI-governance program,
     not SAST).
   - Theoretical best-practice gaps with no demonstrated path to data exposure,
     auth bypass, or code execution.";

pub const SELF_VERIFICATION: &str = "\
GATE EVERY FINDING ON THESE FIVE CHECKS — drop it if any fail:

1. REACHABLE   An external or lower-privileged caller can actually hit this
               code path. Walk backward from the sink and name the entry point.
2. UNMITIGATED No validation, encoding, allow-list, or framework control
               between source and sink already neutralizes it.
3. CONCRETE    You can state the exact payload and the exact effect in one
               sentence. \"Could potentially\" = not a finding.
4. IN SCOPE    It does not match any exclusion group A–E above.
5. CITED       Both source_ref and sink_ref are real file:line locations you
               read in this codebase. For single-site issues (hardcoded key,
               weak cipher constant) use the same ref for both. No line
               numbers = no proof of data flow = do not emit.

SEVERITY SANITY: count the preconditions you just listed. Multiple \"must
already have X\" steps, or impact limited to non-prod code, caps the finding
at MEDIUM or below.";

pub const EXHAUSTIVENESS: &str = "\
COVERAGE EXPECTATION — one finding is the minimum, not the target. Files in
scope routinely contain several unrelated issues. After logging a finding,
keep reading; do not return until every line in the assigned scope has been
examined.

If the scope is large enough that output limits become a concern, emit HIGH
items in full, then append a one-line tally of MEDIUM/LOW items held back.";

pub const SEVERITY_GUIDANCE: &str = "\
SEVERITY — rate the exploit, not the bug class. \"SQL injection\" is not a
severity; \"unauthenticated SQLi reachable from the internet\" is.

STEP 1 — write down three things first:
   - Preconditions: every \"attacker must already have/know/be\" required.
   - Access level: anonymous / any authenticated user / privileged role /
     same-host.
   - Blast radius: one record, one tenant, the whole service, or the
     underlying host.

STEP 2 — map to a tier:
   HIGH    Reachable with no auth (or any low-privilege session), zero or one
           precondition, and the impact is RCE, auth bypass, or bulk
           cardholder/PII exposure.
   MEDIUM  Needs a valid session OR a couple of realistic preconditions;
           impact is scoped (single user, partial data, integrity only).
   LOW     Three or more stacked preconditions, local/adjacent access only,
           or impact limited to availability of a non-critical component.

STEP 3 — downgrade triggers (apply after step 2):
   - Sits in test/example/debug/non-prod code        → drop one tier.
   - Requires a second independent vuln to matter    → drop one tier.
   - Can't decide between two tiers                  → pick the lower one.
     A mis-labelled HIGH burns reviewer trust faster than a cautious MEDIUM.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusion_rules_content() {
        assert!(EXCLUSION_RULES.starts_with("OUT OF SCOPE — do not report:"));
        assert!(EXCLUSION_RULES.contains("A. NO REAL ATTACKER"));
        assert!(EXCLUSION_RULES.contains("B. NO SECURITY IMPACT"));
        assert!(EXCLUSION_RULES.contains("C. WRONG LAYER"));
        assert!(EXCLUSION_RULES.contains("D. HANDLED ELSEWHERE"));
        assert!(EXCLUSION_RULES.contains("E. NOISE FLOOR"));
        assert!(EXCLUSION_RULES.ends_with("auth bypass, or code execution."));
        assert!(!EXCLUSION_RULES.ends_with('\n'));
    }

    #[test]
    fn self_verification_content() {
        assert!(SELF_VERIFICATION.starts_with("GATE EVERY FINDING ON THESE FIVE CHECKS"));
        for check in ["REACHABLE", "UNMITIGATED", "CONCRETE", "IN SCOPE", "CITED"] {
            assert!(SELF_VERIFICATION.contains(check), "missing check: {check}");
        }
        assert!(SELF_VERIFICATION.contains("SEVERITY SANITY"));
        assert!(SELF_VERIFICATION.ends_with("MEDIUM or below."));
    }

    #[test]
    fn exhaustiveness_content() {
        assert!(EXHAUSTIVENESS.starts_with("COVERAGE EXPECTATION"));
        assert!(EXHAUSTIVENESS.contains("do not return until every line"));
        assert!(EXHAUSTIVENESS.ends_with("held back."));
    }

    #[test]
    fn severity_guidance_content() {
        assert!(SEVERITY_GUIDANCE.starts_with("SEVERITY — rate the exploit"));
        assert!(SEVERITY_GUIDANCE.contains("STEP 1"));
        assert!(SEVERITY_GUIDANCE.contains("STEP 2"));
        assert!(SEVERITY_GUIDANCE.contains("STEP 3"));
        assert!(SEVERITY_GUIDANCE.contains("HIGH"));
        assert!(SEVERITY_GUIDANCE.contains("MEDIUM"));
        assert!(SEVERITY_GUIDANCE.contains("LOW"));
        assert!(SEVERITY_GUIDANCE.ends_with("a cautious MEDIUM."));
    }

    #[test]
    fn no_constant_is_empty_or_has_leading_whitespace() {
        for c in [
            EXCLUSION_RULES,
            SELF_VERIFICATION,
            EXHAUSTIVENESS,
            SEVERITY_GUIDANCE,
        ] {
            assert!(!c.is_empty());
            assert!(!c.starts_with(char::is_whitespace));
        }
    }
}
