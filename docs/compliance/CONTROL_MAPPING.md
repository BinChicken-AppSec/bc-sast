# Compliance control mapping

## Current implementation note

This document maps the harness's own controls. Target framework presets
instead guide scans and map findings; neither mapping establishes
compliance. The framework references retain their stated review dates and
were not reverified against external standards in this documentation pass.

Tool dispatch, Git control-path protection and rollback checks have changed.
Target testing and branch/ZIP delivery add execution and publication paths.
See [implementation notes](../implementation-notes.md) for those changes
and their validation limits; historical gap assessments below are not a
fresh review of the whole working tree.

Maps this tool's own security-invariant design choices (not the vulnerabilities it
*detects* in target repos) to four external standards. Written for a security tool
that runs inside a customer's CI with their source code and, in the gateway-mediated
model, no direct provider credentials of its own.

**Last verified against primary/official standard text on 2026-07-21, re-checked
2026-07-27** (ASVS section 9 added: the 2026-07-21 pass predates Phase 2/S10
remediation and Phase 3/S11 validation, which add this tool's only write-capable,
autonomous-agent action path; everything else below was unaffected and not
re-fetched), via direct retrieval of official or primary-source documents (not
paraphrased from memory). Re-verify at each phase boundary, since all four
standards revise. A wrong or outdated control ID here is worse than no citation at
all, so gaps are marked **Not present** / **Not yet verified** explicitly rather than
filled with a plausible guess. See per-standard notes below for exactly what was
checked and against what source. See `AI_AGENT_SECURITY_REVIEW.md` for the
AI-specific frameworks (OWASP LLM Top 10, MITRE ATLAS, AARM) covering the same
write-capable action path from a threat-model angle rather than a control-checklist
one. Several concerns there are more actionable than anything below.

| Standard | Version verified | Primary source |
|---|---|---|
| OWASP ASVS | v5.0.0 (May 2025) | `github.com/OWASP/ASVS` v5.0.0 tag, `5.0/en/*.md`. Note the v5.0.0 renumbering: there is no dedicated "Architecture" chapter any more (V1 is now "Encoding and Sanitization"; the closest analog to architecture/dangerous-functionality guidance is **V15 Secure Coding and Architecture**, and formal threat modeling was demoted to a non-normative Appendix D recommendation) |
| NIST SP 800-218 (SSDF) | v1.1 (Feb 2022) | `nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf` |
| NIST SP 800-218A | Final (Jul 2024) | `nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf` |
| PCI-DSS | v4.0.1 (Jun 2024), Requirement 6 only | PCI SSC official document text |
| PCI Secure SLC Standard | v1.1 | Structured mirror (see note below). **Recommend cross-check against primary PDF before external publication** |
| PCI Secure Software Standard | v1.2.1 (v2.0 published 2026-01-15, in assessor transition) | Secondary sources only. Sub-requirement numbers unverified, see note below |

The tool is not itself in a cardholder-data environment, so PCI-DSS is scoped to
**Requirement 6** (secure coding / vulnerability management) only. The rest of DSS
doesn't apply to a stateless CI scanner.

The **PCI Secure Software Standard**'s primary PDF is gated behind a click-through
agreement on pcisecuritystandards.org that couldn't be fetched programmatically.
Objective-level names below are cross-confirmed across two independent secondary
sources; exact sub-requirement numbers under each objective are **not** verified
against primary text and are marked accordingly. Treat that standard's row as
directional until someone with portal access confirms the sub-numbers against the
official PDF. The **Secure SLC Standard** control-objective list was verified via
CycloneDX's machine-readable third-party-standards mirror
(`github.com/CycloneDX/official-3rd-party-standards`), which is a structured
transcription rather than PCI SSC's own site. High confidence, but flagged as a
secondary source rather than primary.

---

## 1. Jailed path resolution (`bc-pathjail`)

Every LLM-, config-, or plugin-provided path is resolved through `confine`, which
rejects `..`, absolute paths, symlink escapes, and UNC/network paths before any
filesystem operation, regardless of what the requesting LLM turn asked for.

| Standard | Control | Note |
|---|---|---|
| ASVS | **V5.3.2**: file paths for file operations use internally generated or trusted data, not user-submitted filenames, to protect against path traversal/LFI/RFI/SSRF | Direct match |
| ASVS | **V5.3.3**: server-side file processing (e.g. decompression) ignores user-provided path information (zip-slip) | Applies to any future archive-handling code path |
| SSDF | **PW.5.1**: secure coding practices appropriate to the language/environment (input validation) | General secure-coding task; SSDF has no dedicated path-traversal task ID |
| PCI-DSS Req 6 | **6.2.4**: engineering techniques to prevent/mitigate common software attacks (access-control attacks named explicitly) | General bucket, not path-traversal-specific |
| PCI Secure Software Standard | Objective 4, "Critical Asset Protection" | **Not yet verified**: sub-requirement numbers unconfirmed against primary text |

## 2. Redact-before-serialize (`bc-redact`)

Secret/PII masking (PAN with Luhn+IIN gating, SSN/ITIN, cloud keys, JWTs, PEM
blocks, a generic secret-keyword heuristic) runs before serialization at every
write, log, and tool-output boundary, never as a post-hoc scrub.

| Standard | Control | Note |
|---|---|---|
| ASVS | **V16.2.5**: logging enforces protection level per data class; credentials/payment data either not logged or logged hashed/masked | Direct match |
| SSDF | *(none found)* | SSDF v1.1 has no task naming output redaction specifically; closest is the general **PW.5.1** secure-coding task |
| PCI-DSS Req 6 | *(out of scope)* | Sensitive-data-at-rest/in-transit protection lives in PCI-DSS Requirements 3/4, not Requirement 6, correctly out of this doc's scope |
| PCI Secure Software Standard | Objective 6, "Sensitive Data Protection" | **Not yet verified**: sub-requirement numbers unconfirmed against primary text |
| PCI Secure SLC Standard | Objective 7, "Sensitive Data Protection" | Verified via CycloneDX mirror (secondary source) |

## 3. Fail-closed config/policy loading (`bc-config`)

Any parse error in a config or policy file is a hard failure, not a fallback to
defaults; a config file resolving inside the scan target itself is refused unless
explicitly opted into via an environment variable.

| Standard | Control | Note |
|---|---|---|
| ASVS | **V16.5.3**: application fails gracefully and securely, including on exception, preventing fail-open conditions | Direct match |
| ASVS | **V13.4.2**: debug modes disabled in production; secure defaults | Related, covering the "no silent permissive fallback" half of this invariant |
| SSDF | **PW.9.1 / PW.9.2**: define and implement a secure default configuration baseline | Direct match |
| PCI-DSS Req 6 | **6.2.4**: engineering techniques against common software attacks | General bucket |
| PCI Secure Software Standard | Objective 2, "Secure Defaults" | **Not yet verified**: sub-requirement numbers unconfirmed against primary text |

## 4. No untrusted deserialization

`bc-cli` opens a persistent `SqliteCheckpointStore` for both scan and
`--remediate` runs, degrading to no checkpointing (with a warning) if the
state directory is unwritable (`NullCheckpointStore` remains available for
embedders/tests that want none at all). The only untrusted-deserialization
path this introduces is `--resume` loading a previously-saved checkpoint's
bytes back into a typed step-checkpoint struct
(`bc-orchestrator/src/lib.rs::load_checkpoint`, `serde_json::from_slice(&bytes).ok()`).
`serde_json::from_slice::<T>` *is* the validation step, by design. There
is no separate unchecked pre-parse pass. A malformed/corrupted/tampered
checkpoint fails that parse and collapses to `None` (`.ok()`), which every
caller already treats identically to "no checkpoint for this step". That is
the same fail-safe "just re-run this step" degrade `CheckpointStore::load`'s
own contract documents, not a distinct error path a bad payload could
divert into.

| Standard | Control | Note |
|---|---|---|
| ASVS | **V15.1.4, V15.1.5, V15.2.5** (chapter V15 introduction names "deserialization of untrusted data" explicitly as an example of dangerous functionality requiring documentation and, where used, sandboxing/isolation) | Direct match |
| SSDF | *(gap, flagged rather than fabricated)* | Searched full SSDF v1.1 text; no task specifically names deserialization. Closest available: **PW.5.1** ("avoid using unsafe functions and calls") |
| PCI-DSS Req 6 | *(gap, flagged rather than fabricated)* | No deserialization-specific language in Requirement 6; **6.2.4**'s "data/buffer attacks" bucket is the nearest general fit |
| PCI SSF | **Not yet verified** for either standard | No sub-requirement found in secondary sources specific enough to cite responsibly |

## 5. One operator-configured credential, gateway-mediated LLM access

The tool holds exactly one model credential: whatever key the operator configures
for `--gateway-base-url` (`--gateway-api-key` / `BC_GATEWAY_API_KEY`). In the
intended deployment that endpoint is an operator-controlled gateway
(`bc-gateway-http` + the dialect crates) and the key is a gateway credential, not a
provider key, so a compromised scan process has nothing provider-side to
exfiltrate. Nothing prevents pointing `--gateway-base-url` straight at
`https://api.openai.com/v1` with a real provider key instead; that is a deployment
choice, and it forfeits this property.

| Standard | Control | Note |
|---|---|---|
| ASVS | **V13.3.1**: secrets management solution used; secrets not included in source or build artifacts | Applies to the gateway's own key custody, which this design deliberately keeps outside the tool entirely |
| SSDF | **PW.1.2**: track and maintain the software's security requirements, risks, and design decisions | This is an architecture-level decision, not a coding-time control; SSDF has no task specifically about "don't hold third-party credentials" |
| PCI-DSS Req 6 | *(out of scope)* | Credential custody is a PCI-DSS Requirement 3/8 concern, not Requirement 6 |
| PCI SSF | *(not mapped)* | Neither standard's control objectives (as verified) address this specific architectural choice directly |

## 6. Least-privilege / hardened container runtime

Final container image is `cgr.dev/chainguard/wolfi-base` plus `git`, running as
uid 65532, with the scanner binary as its entrypoint. Both build stages are
pinned by digest. See `Dockerfile` for the glibc-vs-musl rationale (resolved
dependency tree pulls in `aws-lc-sys`, a C/C++ BoringSSL fork, so the
"pure-Rust, therefore muslable" assumption doesn't hold).

**Restating the attack-surface claim honestly.** This image previously was
`gcr.io/distroless/cc-debian12:nonroot`, and this section previously claimed
"no shell, no package manager". That is no longer true: the image now contains
`sh`, `apk` and `git`, and it is about 33MB larger (135MB against 102MB). What
was bought with that is the ability to *enforce* controls that were previously
inert, which is a net gain for this table rather than a loss:

- `step_remediate.verify_command`, the gate that runs the operator's own build
  or test command before an agent's fix is accepted, could not run at all
  without a shell. It failed closed, so it was a control nobody could turn on.
- The git revert backstop, worktree isolation for `--remediate`, and HEAD-sha
  detection all need `git`.

The agent-facing surface is unchanged, and that is the part this table is
really asserting. The remediation agent's tool allowlist is Read, Glob, Grep,
Edit and Write; there is no shell tool, no `Bash`, and no tool that spawns a
process (`crates/bc-sandbox-tools`). So the claim moves from "no shell exists"
to "a shell exists and the agent cannot reach it". The only string that reaches
`sh -c` is `step_remediate.verify_command`, which is operator config, has no
default, and spawns nothing at all when unset. What did increase is
post-exploitation convenience for an attacker who has already achieved code
execution in the container by some other means: they would now find a shell and
a package manager waiting rather than having to bring their own.

Operators are expected to layer their own image on top of this one to add the
toolchain `verify_command` needs, since this image ships no compilers, test
runners or language package managers.

| Standard | Control | Note |
|---|---|---|
| ASVS | **V13.4.2**: secure defaults, debug disabled in production | Partial fit; ASVS's configuration chapter doesn't have a container-runtime-specific item |
| SSDF | **PW.9.1 / PW.9.2**: secure default configuration baseline | Direct match |
| SSDF | **PS.1.1**: least-privilege access to software code/components during storage | Adjacent (build-time, not runtime), included for completeness |
| PCI-DSS Req 6 | **6.2.4** | General bucket |
| PCI Secure Software Standard | Objective 2, "Secure Defaults"; Objective 4, "Critical Asset Protection" | **Not yet verified**: sub-requirement numbers unconfirmed against primary text |

## 7. Supply-chain integrity (pinned deps, `cargo-deny`)

Every direct dependency is vetted before adding and pinned to an exact `=x.y.z`
version (see `docs/supply-chain.md`); `cargo-deny` gates advisories/bans/licenses/
sources on every PR and weekly against an unchanged lockfile.

**Not implemented here**: image signing, SBOM attestation and build provenance.
This repository publishes no container image. Consumers build from the `Dockerfile`
(see `docs/deployment.md`), so signing, SBOM generation and SLSA provenance are
controls on the consumer's own registry and release pipeline, not on this repo. The
three rows below are marked as gaps rather than matches for that reason.

| Standard | Control | Note |
|---|---|---|
| ASVS | **V15.1.1**: documented risk-based remediation timeframes for vulnerable third-party components | Direct match via `cargo-deny`'s advisory gate + the weekly schedule job |
| ASVS | **V15.1.2**: SBOM/inventory maintained; components sourced from trusted, continually maintained repositories | **Partial**. `Cargo.lock` plus `cargo-deny`'s `sources` check (crates.io only) give a complete, pinned inventory; no SBOM artifact is generated or attested. |
| ASVS | **V15.2.4**: components and transitive dependencies sourced from the expected repository (dependency-confusion protection) | Direct match via `cargo-deny`'s `sources` check |
| SSDF | **PW.4.1**: acquire and vet third-party software components before use | Direct match via the pre-add crates.io vetting checklist in `docs/supply-chain.md` |
| SSDF | **PW.4.4**: verify acquired third-party components continue to comply with requirements throughout their lifecycle | Direct match via `cargo-deny`'s recurring/scheduled check |
| SSDF | **PO.1.3**: communicate security requirements to third-party component providers | Weak fit. This project consumes, doesn't supply, components; included for completeness only |
| SSDF | **PS.3.1**: secure archival of release files plus provenance data | **Gap**. Signed release archival and provenance attestation are not established by this review. Target-source ZIP and branch delivery do not provide release attestation for the harness itself. |
| PCI-DSS Req 6 | **6.3.2**: inventory of bespoke/custom software and third-party components maintained | Direct match |
| PCI-DSS Req 6 | **6.3.1**: vulnerabilities identified and risk-ranked, covering both bespoke and third-party software | Direct match via `cargo-deny` advisories |
| PCI-DSS Req 6 | **6.3.3**: critical/high-risk patches installed within one month of release | Direct match via the weekly scheduled `cargo-deny` run against an unchanged lockfile |
| PCI Secure SLC Standard | **3.2.3, 3.2.6, 3.2.7, 3.2.8, 3.2.9** (Objective 3, third-party/open-source component management) | Verified via CycloneDX mirror (secondary source) |
| PCI Secure SLC Standard | **6.1.1** (Objective 6, "Software Integrity Protection": process protects integrity of code including third-party components) | Verified via CycloneDX mirror (secondary source). **Partial**: covered for source/dependency integrity, not for image signing, which this repo does not do. |

## 8. LLM-specific: attacker-influenced text re-entering model context

Findings text, repo content, and any other LLM-visible or LLM-produced text is
treated as untrusted input at every trust-boundary crossing. Most concretely,
`bc-report-md`'s heading-demotion/cell-escaping sanitization prevents
LLM-generated Markdown from breaking out of its intended structure when rendered.

| Standard | Control | Note |
|---|---|---|
| ASVS | *(gap, flagged rather than fabricated)* | ASVS v5.0.0 has no dedicated LLM/AI chapter; the closest analog is the general output-encoding chapter (**V1 Encoding and Sanitization**), which the Markdown/SARIF renderers already satisfy for their respective output formats |
| SSDF | **PW.5.1 (AI-augmented, per SP 800-218A)** | **Caveat, quoted directly from 800-218A §1 Scope**: "practices for the deployment and operation of AI systems with AI models are out of scope." This tool's use case (LLM output re-entering the trust boundary at *runtime*) sits outside what 800-218A actually covers. PW.5.1's AI-augmented guidance ("code the handling of inputs including prompts... and outputs carefully... sanitized or dropped") is the nearest available citation, not a perfect scope match. Treat as directional. |
| PCI-DSS Req 6 | *(gap, flagged rather than fabricated)* | Full text of Requirement 6 v4.0.1 contains no mention of "AI," "generative AI," or "LLM" |
| PCI SSF | *(not mapped)* | No LLM-specific language found in either standard's verified objective list |

## 9. Write-capable remediation actions (`bc-stage-s10`, `bc-policy-gate`,
   `bc-diffcapture`): Phase 2/3 catch-up

Sections 1-8 predate the optional `--remediate` step, which is
this tool's only path where the LLM's own output drives a real filesystem mutation
(`Edit`/`Write` tool calls) rather than just producing report text. Verified against
the actual code, not the architecture plan, via a direct read of
`bc-sandbox-tools`/`bc-pathjail`/`bc-policy-gate`/`bc-diffcapture`/`bc-stage-s10`/
`bc-stage-s11`. See `AI_AGENT_SECURITY_REVIEW.md` for the full write-up this table
summarizes.

| Standard | Control | Note |
|---|---|---|
| ASVS | **V5.3.2**: file paths for file operations use internally generated/trusted data, not user-submitted filenames | Direct match, reconfirmed for this path specifically: `write_file`/`edit_file` (`bc-sandbox-tools`) enforce path confinement and protected-control-path checks before writing before any `fs::write`; no bypass found in either function or in the dispatch loop that calls them |
| ASVS | **V1.5.2**: deserialization of untrusted data enforces safe input handling (allowlist of types, no client-defined behavior) | **Partial**. The LLM's JSON is parsed into typed structs (not deserialized into behavior-carrying types), but the *path* value inside that JSON is untrusted-input-driven data reaching a dangerous sink; V5.3.2's jailing is what actually neutralizes it, not the deserialization step itself |
| ASVS | **V8.3.1**: authorization enforced at a trusted layer, not one an untrusted party could manipulate | **Concern, not a direct match**: the deterministic CWE/path policy gate (the "trusted layer" for *which* findings may be patched) is **off by default**. `enforce_remediation_policy` defaults `false`, and `bc-config`'s own bare `step_remediate` defaults don't turn it on either. In the default configuration there is no CWE/path allow-deny layer at all. Writes are still bounded by four other default-on controls: pathjail (V5.3.2), throwaway-worktree isolation (the user's own checkout is never edited for a git `--repo`), the post-patch tree-sitter syntax gate (`step_remediate.syntax_check: true`), the diff-size caps (`max_diff_lines: 200`, `max_files_touched: 1`, so a cross-file fix is never applied), and the unverified-patch rollback (`keep_unverified: false`). See `AI_AGENT_SECURITY_REVIEW.md` §AARM-R1 for the same finding from the AARM angle. |
| ASVS | **V16.5.3**: fails gracefully/securely on exception, no fail-open | **Partial**: the *pre*-execution CWE/path gate is prevent-then-write (fail-closed) when enabled. The `deny_paths`/`forbid_patch_paths` *post*-gate is write-then-inspect-then-revert, and a real write briefly lands on disk before a deny decision is enforced. Not a classic "fail open" (the write IS undone), but not prevent-then-execute either; flagged because ASVS's own language ("preventing fail-open conditions") reads most naturally as pre-execution enforcement. |
| SSDF | **PW.5.1** | Same general secure-coding task already cited in section 1; no dedicated SSDF task for LLM-agent action authorization exists |
| PCI Secure Software Standard | Objective 4, "Critical Asset Protection" | **Not yet verified**: sub-requirement numbers unconfirmed against primary text (same caveat as section 1) |

**The six S10 gates.** Each `--remediate` patch passes through, in order: the policy
post-gate (only when `--enforce-remediation-policy` is set), the post-patch
tree-sitter syntax gate, the operator's `--verify-command` (only when set), the
diff-size caps, the dry-run rollback (`--remediate-dry-run`), and the
unverified-patch rollback. Anything a gate rejects is reverted from the
`bc-diffcapture` snapshot rather than left half-applied. The flags that tune them
(`--no-syntax-check`, `--keep-unverified`, `--max-diff-lines`, `--max-files-touched`,
`--remediate-dry-run`, `--verify-command`, `--verify-timeout`), plus
`--remediate-in-place`/`--keep-remediation-worktree` for the worktree isolation and
`--remediate-from` for remediating a prior export, all postdate this section's first
draft and are documented in [`../remediation.md`](../remediation.md). ASVS/SSDF/PCI
rows above are unchanged by them: every gate is a defense-in-depth control on the
same V5.3.2/V16.5.3 path, not a new control category.

---

## Open items

- Confirm PCI Secure Software Standard sub-requirement numbers (rows 1, 2, 3, 6)
  against the primary PDF once portal access is available. Everything cited from
  that standard here is objective-level only, sourced secondarily.
- SSDF has no dedicated task for two of this tool's invariants (deserialization,
  redaction) and 800-218A explicitly scopes out the LLM-runtime-output case this
  tool actually cares about. These are real gaps in the standard's current
  coverage, not omissions in this mapping. Re-check on 800-218A's next revision.
- PCI-DSS Requirement 6 v4.0.1 has no generative-AI-specific language at all;
  re-check whenever PCI SSC publishes a new DSS revision.
- Re-verify every ID in this document whenever any of the four standards publish a
  new version. ASVS v5, SSDF, and the PCI Secure Software Standard (v2.0, already
  published 2026-01-15 and in assessor transition) are all live/moving targets.
  Section 9 (2026-07-27) closes the "re-verify at Phase 2" item from the prior
  revision of this note.
- Section 9's two flagged concerns (policy gate off by default; post-hoc revert
  timing for `deny_paths`) are architecture-level design choices, not ID-citation
  errors. Decide whether to change the defaults/timing or accept them as
  documented risk before treating this tool's remediation path as fully
  ASVS-aligned. See `AI_AGENT_SECURITY_REVIEW.md` for the full analysis and
  severity ranking.
