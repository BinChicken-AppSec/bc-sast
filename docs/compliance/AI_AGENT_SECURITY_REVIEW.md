# AI agent security review: OWASP LLM Top 10, MITRE ATLAS, AARM

## Current implementation note

The framework references and broader assessment below retain their stated
review dates. They were not reverified against external standards during
this documentation update. The current working tree adds the following
controls and execution paths:

- Session dispatch enforces advertised tool names. Write/Edit tools reject
  protected Git control paths and use resolved journal destinations with
  captured original bytes. Unreadable baselines fail before writing.
- S10 uses actual touched files and downgrades no-change fix claims to
  review. A failed nonempty patch export retains the proposed worktree.
- Compiled target-testing profiles discover existing suites before
  generation and independent review. The opt-in `discovered-offline`
  profile authorizes discovered suites through compiled ecosystem
  allowlists, and installs each package's lockfile-pinned dependencies in
  one networked container per package before any test phase; the test
  phases themselves keep `--network none`. Other profiles do not execute
  target code and install nothing. Commands run inside restricted Linux
  containers; this is an additional execution boundary.
- Explicit full-scan delivery can create and push one new branch or
  export a Git-free source ZIP. These paths keep the original source
  unchanged and enforce their delivery gates. CI upload remains a
  separate consumer step.

These changes do not close every finding below. Host verification in the
legacy workflow, unknown secrets in source, concurrent filesystem changes,
and Git transport cleanup still need appropriate operational controls.
See [implementation notes](../implementation-notes.md),
[target testing](../target-testing.md), and
[remediation delivery](../remediation-delivery.md) for current scope and
validation limits. Requirement mappings are not a compliance conclusion.

**Scope**: this tool's own design as an autonomous AI agent, not the
vulnerabilities it *detects* in scanned repos, and not general application
security (see `CONTROL_MAPPING.md` for OWASP ASVS/NIST SSDF/PCI-DSS/PCI SSF).
This doc asks a narrower question: given bc-sast reads attacker-influenced source
code into LLM context, and can optionally write back to that same repo via an
agentic Edit/Write tool loop, where are the concrete gaps against the three
frameworks purpose-built for exactly that shape of system?

**Framework content last verified 2026-07-27** (category lists, technique
IDs, requirement text), fetched directly from each project's primary
source, not recalled from training data. See the source URLs in each
section. **Codebase claims re-checked 2026-09-07** against the current
tree; anywhere a doc comment's claim didn't match the code's actual
behavior, that's called out explicitly (see AARM §R1/R5 below). The
remediation path has gained a substantial set of safety gates and budget
controls since the original pass. Findings 1, 2 and 3 below are updated
accordingly, and the framework sections that referenced "no budget
enforcement" no longer do.

## Summary of findings, ranked by severity

| # | Severity | Finding | Framework(s) |
|---|---|---|---|
| 1 | **Medium-High** | The deterministic CWE/path policy gate, the only control on *which* findings may be auto-patched, is **off by default** (`enforce_remediation_policy` defaults `false`): there is no allow/deny logic at all unless an operator explicitly passes `--enforce-remediation-policy`. Writes are not unbounded, though. Five controls are on by default: path-jailing, throwaway-worktree isolation (a git `--repo`'s own checkout is never edited), the post-patch tree-sitter syntax gate, the diff-size caps (`max_diff_lines: 200` / `max_files_touched: 1`, so a cross-file fix is never applied), and the unverified-patch rollback. What is missing by default is the *authorization* layer that decides which CWEs and which paths may be touched at all. | AARM R1, R4; OWASP LLM06 |
| 2 | **High** | No **in-process** step-up / per-diff human approval exists. Interactive mode gates *which finding* gets remediated, not the resulting diff; batch/CI mode is fully autonomous. Once a finding is selected, Edit/Write executes with no further checkpoint. The closest available approximation is an out-of-band split: `--remediate-dry-run` + `--out-remediation-json` produces every diff without keeping any of them, and a later `--post-fixes-from` run publishes the ones a human has since read. That is an approval *loop*, not an approval *gate*. | AARM IV-D, R4 |
| 3 | **Medium** | S11 validation is **on by default** but **never blocking**. Nothing in the orchestrator, CLI, or GitHub-posting path conditions "merge-ready" or comment-posting on a validation score existing, let alone passing. A fix graded `Not Fixed` is posted identically to one graded `Fixed`. | OWASP LLM09 (overreliance); AARM R4 |
| 4 | **Medium** | Even with policy enforcement on, the `deny_paths`/`forbid_patch_paths` check is enforced *after* the write (capture, then agent writes, then inspect, then revert), not before. The CWE/file-level pre-gate IS prevent-then-write; this one specific check is write-then-undo. | AARM R1 |
| 5 | **Medium** | The audit trail of what a remediation actually did (diff, policy decision, verdict) is **opt-in and unsigned**. It exists only in-process unless `--out-remediation-json` is passed, and even then it's plain JSON, not a tamper-evident/cryptographically-signed record. | AARM R5, R6 |
| 6 | ~~Medium~~ **Fixed this review** | Passing `--config` at all (even a file that never mentions `step_validate`) silently disabled S11 validation, contradicting the documented "on by default" intent, because the merged config tree always carries `bc-config`'s own bare default (`false`) once any file is loaded, with no way to distinguish "not mentioned" from "explicitly set." Root-caused, fixed, and regression-tested (`bc-config::LoadedConfig` now exposes `user_provided`, the pre-defaults-merge tree, for exactly this class of override). | None |
| 7 | **Low** | No shipped default policy file exists at all, not even an allow-all one. This is actually **safe**, not a vulnerability: `RemediationGate::new(None)` fails closed to guidance-only for every decision. Noted as a usability gap (an operator who enables enforcement without also supplying `--remediation-policy` gets silent no-op patching, not an error), not a security concern. | None |
| 8 | **Low** | Posted GitHub PR comments (fix suggestions, findings) are the *only* persistent record of what the tool told a reviewer, by default, and are editable/deletable by the same token that posted them. Typical for GitHub-comment-based tooling generally; not unique to this tool's risk profile. | AARM R5/R6 (partial) |

**What's already well-designed**, so the above isn't read as a blanket
indictment: path-jailing has no found bypass anywhere on the write path
(§AARM-R1 below); the policy gate's post-write check cross-references real
`git diff`/`git status`/worktree-glob output rather than trusting the
remediation LLM's own self-reported change list, specifically defeating an
under-reporting bypass; S11 runs in a separate read-only tool
executor (`SandboxTools::new`, plus five deterministic read-only fact tools
wrapped around it: `DiffTouched`/`ChangedLines`/`DiffImpactMap`/
`PatternScan`/`TestInventory`) *and* a fresh conversation (not a
continuation of S10's), which
meaningfully contains (though doesn't eliminate, see LLM01 below) the
"same injected content compromises both the fix and its own grader" failure
mode; and the redact-before-serialize architecture (`bc-redact`, already
covered in `CONTROL_MAPPING.md` §2) is a real mitigation for the data-leakage
concerns both LLM02 and ATLAS name below.

---

## AARM (Autonomous Action Runtime Management)

**Source**: `arxiv.org/html/2602.09433v1` ("Autonomous Action Runtime
Management (AARM): A System Specification for Securing AI-Driven Actions at
Runtime", Errico, Feb 2026): MUST requirements R1-R6, SHOULD requirements
R7-R9. AARM is the most directly applicable of the three frameworks here:
bc-sast's remediation step is precisely "an AI agent taking runtime actions,"
which is AARM's entire scope.

| Req | Requirement (source) | bc-sast's status | Evidence |
|---|---|---|---|
| **R1** Pre-Execution Interception (intercept actions before execution without bypassing policy evaluation) | **Partially met, with the two findings above.** Path-jailing is real pre-execution interception with no found bypass (`bc-sandbox-tools`'s `write_file`/`edit_file` enforce path confinement and protected-control-path checks before writing; every dispatch path was traced, none skips it). But (a) the CWE/path policy layer, AARM's actual "policy evaluation" concept, is off unless explicitly enabled, which reads as exactly the "fail-open mode" R1 says must not exist, and (b) `deny_paths` is enforced post-hoc even when enabled (finding #4). |
| **R2** Context Accumulation (append-only, hash-chained session context tracking prior actions/intent) | **Not implemented.** No session-context accumulation, hash-chaining, or cross-action intent tracking exists anywhere in the remediation path. S10 processes each finding independently with no memory of prior findings' actions in the same run. |
| **R3** Policy Evaluation with Intent Alignment (including semantic-distance-based drift detection) | **Partially met for the static half** (CWE/path allow-deny, when enabled), **not met for the intent-alignment half**. There is no embedding-similarity or other drift measurement between what a finding asked for and what the agent actually did. |
| **R4** Authorization Decisions (ALLOW/DENY/MODIFY/STEP-UP/DEFER) | **Only ALLOW/DENY exist**, and only when policy enforcement is on (`RemediationGate::decide` returns Patch or GuidanceOnly, a binary, not AARM's five-way decision set). MODIFY, STEP-UP, and DEFER have no equivalent anywhere in the codebase. |
| **R5** Tamper-Evident Receipts (signed records binding action+context+decision+outcome) | **Not met.** The closest analog, `--out-remediation-json`, is opt-in, unsigned, and captures the outcome but not a policy-decision-bound receipt in AARM's sense (finding #5). |
| **R6** Identity Binding (human principal, service account, agent session, role/privilege scope, with freshness/revocation checks) | **Not met.** No identity-binding concept exists in the remediation path; the GitHub-posting layer uses whatever single token is configured, with no session/role separation from the scanning credential. |
| **R7** Semantic Distance Tracking (SHOULD) | Not implemented (same gap as R3's intent-alignment half). |
| **R8** Telemetry Export (SHOULD) | Not implemented. No SIEM/security-event export exists; `ScanMetrics`/`tokens_by_phase` are operational telemetry, not security-decision telemetry. |
| **R9** Least Privilege Enforcement (action executes with minimal necessary permissions) | **Partially met.** S11's tool executor is more restricted than S10's (read-only vs. write-capable), which is real least-privilege separation between the two stages. But within S10 itself, the remediation agent's Edit/Write scope is the whole jailed repo tree, not narrowed to the specific finding's file unless the (optional) policy gate's `deny_paths` restricts it. |

**IV-D "Human escalation"**, requiring step-up authorization and
context-dependent allow or defer decisions, has no implementation at all. This is finding #2 above, restated in
AARM's own vocabulary.

## OWASP Top 10 for LLM Applications (2025)

**Source**: `genai.owasp.org/llm-top-10/`, canonical category text from
`github.com/OWASP/www-project-top-10-for-large-language-model-applications`.

- **LLM01 Prompt Injection**: the highest-relevance category. The scanned
  repo's own content (code, comments, filenames) is the injection channel,
  parsed identically at every pipeline stage including the optional
  remediation step. S11's separate read-only executor + fresh conversation
  (noted above) contains this *partially*: an injection that manipulated
  S10's tool-calling session doesn't automatically carry into S11's own
  context object, but content embedded in the resulting diff is still
  visible to S11 verbatim (it's passed into S11's prompt as the thing being
  graded), so an injection crafted to *also* read as a plausible "this fix
  is correct" justification isn't structurally prevented from influencing
  the grader too.

  A second, narrower repo-controlled channel into a prompt exists: S11's
  penetration-tester persona reads per-CWE hints from an
  `inputs/validator_hints.yaml` **committed in the scanned repository**,
  which replaces (not merges with) the bundled defaults. It is gated
  behind the same `BC_ALLOW_CWD_CONFIG` opt-in as an in-repo `--config`
  and is therefore **off by default**, but an operator who sets that
  variable for an unrelated reason also hands the scanned repo a direct
  line into the grader's system prompt. Worth knowing before setting it.
- **LLM02 Sensitive Information Disclosure**: mitigated by `bc-redact`
  (see `CONTROL_MAPPING.md` §2), but redaction is pattern-based and, per
  OWASP's own note, prompt-level restrictions "may not always be honored and
  could be bypassed via prompt injection". Worth remembering this is a
  strong mitigation, not a guarantee, especially for secrets an attacker
  deliberately obfuscates (split across lines, encoded) specifically to
  evade the regex layer.
- **LLM03 Supply Chain**: the gateway endpoint is operator-configured and
  not pinned/reviewed by anything in this tool; already partially covered
  by `CONTROL_MAPPING.md` §5's single-operator-credential invariant, which
  reduces blast radius (nothing provider-side to steal) but doesn't address
  a malicious/compromised gateway sitting as a MITM on prompts and
  completions.
- **LLM04 Data and Model Poisoning**: low applicability today (bc-sast calls
  hosted models via a gateway; it doesn't train or fine-tune anything).
  Flagged only as a forward-looking note if a future triage/scoring model
  is ever fine-tuned on historical findings data.
- **LLM05 Improper Output Handling**: the second-highest-relevance
  category, and the flip side of LLM01: every stage's JSON output is parsed
  by code that drives real actions (file writes, GitHub-suggested diffs).
  Concretely mitigated for path data specifically by pathjail (finding
  table, AARM-R1); **not** independently mitigated for diff *content*. A
  manipulated "fix" that is itself a backdoor is a content-handling
  question the policy gate's CWE/path checks don't address (they gate
  *where* a patch may land, not *what* it contains).
- **LLM06 Excessive Agency** maps directly to findings #1 and #2: the
  remediation agent has real filesystem-mutation capability in the same
  trust context that ingests attacker-controlled code, with the
  autonomy-limiting control (the policy gate) off by default and no
  approval checkpoint at any autonomy level.
- **LLM07 System Prompt Leakage**: no specific concern found; the design
  already treats prompts as non-secret architecturally (gating logic lives
  in Rust code, in the policy gate and pathjail, not in prompt wording),
  which is exactly OWASP's recommended posture for this category.
- **LLM08 Vector and Embedding Weaknesses** is **not applicable**. The dedup
  stage (S7) uses deterministic prefilter/semantic-LLM-pass logic, not
  embedding similarity search: confirmed no vector/embedding retrieval
  exists anywhere in the pipeline.
- **LLM09 Misinformation** maps directly to finding #3: a hallucinated or
  manipulated "pass" from S11 is exactly the kind of credible-but-false
  signal this category warns about, surfaced right before a human-facing
  merge-readiness claim, with no gate downstream that would catch it.
- **LLM10 Unbounded Consumption**: the nine-stage pipeline (through
  remediation and validation) means a single large or adversarially
  structured PR can trigger many chained LLM calls. Budget enforcement
  **does** exist and is real, not merely observability: `--max-tokens` and
  `--max-scan-seconds` are checked at the S4-S7 stage boundaries *and*
  before each individual deep-dive chunk, verification session and
  semantic-dedup call, and a trip stops the scan starting new work,
  records the reason in `ScanMetrics::budget_stop`, and renders a
  **BUDGET REACHED** line in the report's `## Scan Health` section. A
  provider reporting quota exhaustion trips the same gate from inside a
  stage. Per-stage `max_turns` ceilings (S1 40, S6 30, S10 40, S11 50)
  bound each agentic session independently. The residual gap is that both
  global caps are **opt-in with no default value**, so an operator who
  never passes them runs unbounded. `max_budget_usd`, which used to look
  like a third control, is no longer shipped as a default and now warns
  when a loaded config sets it.

## MITRE ATLAS

**Source**: `atlas.mitre.org/atlas-data/dist/v6/ATLAS-2026.06.yaml` (current
release 2026.06). The site itself is a client-rendered SPA with no static
per-technique pages, so this was fetched from its own underlying data feed
rather than being guessed from memory.

The specific techniques most applicable, with the concrete bc-sast mechanism
each maps to:

- **AML.T0051 / .001 (Indirect) Prompt Injection**, **AML.T0099 AI Agent Tool
  Data Poisoning**, **AML.T0080/.001 AI Agent Context Poisoning**: the
  scanned repo is the injection channel; a malicious file positioned for
  the scanning agent's own Read/Glob/Grep calls to retrieve is squarely
  T0099's description. T0080's "persists for the remainder of the thread"
  is why S11's *fresh* conversation (not a continuation of S10's) is a
  meaningful, verified mitigation, not just an implementation detail.
- **AML.T0068 LLM Prompt Obfuscation**: comments/string literals/docstrings
  are a natural place to hide injected instructions from a human PR
  reviewer skimming a diff; nothing in the pipeline specifically screens
  for obfuscated instruction-shaped content before it reaches the model.
- **AML.T0094 Delay Execution of LLM Instructions** is relevant specifically
  *because* bc-sast is a staged pipeline: an injection could stay dormant
  through scanning and trigger only when the separate validation-pass LLM
  later processes the same (or derived) content.
- **AML.T0053 AI Agent Tool Invocation**, **AML.T0101 Data Destruction via
  AI Agent Tool Invocation** are the direct ATLAS framing of finding #1/#2:
  an adversary's influence over the agent (via injection) reaching a real
  mutative tool with no policy gate or human checkpoint in the way.
- **AML.T0086 Exfiltration via AI Agent Tool Invocation**: a manipulated
  Edit/Write call could in principle encode data read elsewhere in the repo
  into a committed file's content, to be read back out via the PR an
  attacker controls; not something the current write-then-inspect policy
  check (when enabled) is designed to catch, since it inspects *paths*
  touched, not semantic content of what was written.
- **AML.T0067 LLM Trusted Output Components Manipulation** is the ATLAS-level
  framing of finding #3: content crafted to make an LLM's own output
  "appear trustworthy" to whatever consumes it next, which for bc-sast is
  specifically the S11 validation grader consuming S10's diff.
- **AML.T0057 LLM Data Leakage**, **AML.T0077 LLM Response Rendering**: the
  first is what `bc-redact` exists to stop; the second applies when results are posted to GitHub, which renders
  Markdown. An unredacted or injected finding is a concrete
  beacon-exfiltration vector (e.g. an image link with data embedded in the
  query string) even where raw-text redaction is otherwise sound.
- **AML.T0010/.001 AI Supply Chain Compromise**, **AML.T0008.005 AI Service
  Proxies**: same gateway-trust surface as OWASP LLM03 above, restated in
  ATLAS's vocabulary.

---

## Recommendations (not yet implemented; decisions for you, not unilateral changes)

Ranked by the severity table above. These are architecture/default-behavior
changes, not bugs. They are presented as options, not applied, since they
trade off autonomy/convenience against containment in ways only you can
weigh:

1. **Consider defaulting `enforce_remediation_policy` to `true`** (or at
   minimum, making its current `false` default loud with a startup warning
   when `--remediate` runs without it). This closes finding #1, the
   highest-severity gap. Ships-with-no-policy-file already fails closed
   (finding #7), so flipping the default doesn't require also shipping a
   policy; it would just require operators to explicitly opt *out* of
   enforcement instead of into it.
2. **`--remediate-dry-run` now exists**. It runs every gate, rolls
   everything back, and keeps the diffs for `--out-remediation-json` /
   `--post-fixes-from`, so a human can read every proposed patch before
   any of it is published. That closes the *preview* half of finding #2.
   What remains open is an in-process **approval checkpoint**: nothing
   pauses a batch run to ask. Consider a per-diff confirmation step for
   the batch/CI path, or treating dry-run, then review, then apply as
   the documented supported workflow.
3. **Consider conditioning GitHub-posting/merge-readiness language on a
   passing S11 verdict** when validation is enabled, rather than posting
   identically regardless of outcome. This addresses finding #3 with a
   small, localized change (a check in `bc-cli`'s posting path, not a new
   capability).
4. Findings #4/#5/#8 are smaller, more clearly "harden later" items:
   moving the `deny_paths` check to a true pre-write dry-run diff inspection
   (rather than write-then-revert), and/or writing `--out-remediation-json`
   unconditionally (already low-cost, same reasoning `action.yml` already
   applies to it) plus considering a signed-receipt format if this tool is
   ever deployed somewhere the AARM R5/R6 conformance bar actually matters.
