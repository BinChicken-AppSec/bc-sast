# The scan pipeline, S0 to S11

`bc_orchestrator::run_scan` sequences the detection pipeline. It knows only
stage *order*, degrade handling and early stop, and delegates rendering to S9.
Remediation (S10) and validation (S11) are separate phases behind
`--remediate`, not steps of `run_scan`.

**S9 is reporting.** It redacts the typed `FinalReport` from S8 and renders
Markdown and SARIF directly, without another model call or Markdown parsing.
The CLI publishes those artifacts and CSV/JSON exports. `--stop-after s8`
returns analysis without publishing reports; `--stop-after s9` publishes
reports and stops before remediation.

## Detection and reporting: S0 through S9

```mermaid
flowchart TD
    S0["S0 s0-seed<br/>tree-sitter call graph, routes, guards, taint paths<br/>OFF via step0.enabled"]
    S1["S1 s1-preprocess<br/>one agentic Read/Glob/Grep exploration<br/>skips exploration under step1.mode gap_fill"]
    S2["S2 s2-threatmodel<br/>single-shot call over deterministic evidence<br/>OFF via step2.enabled"]
    S3["S3 s3-decompose<br/>risk-ranked manifest, then a deterministic<br/>pipeline guaranteeing 100 percent file coverage"]
    S4["S4 s4-deepdive<br/>N single-shot calls per chunk,<br/>majority-voted in chunk, collapsed across chunks"]
    B1{"budget check"}
    S5["S5 s5-prefilter<br/>deterministic gates, evidence backfill,<br/>then S7 dedup tier 0 to 2"]
    TP["third-party findings<br/>join here, bypassing S4 and S5"]
    B2{"budget check"}
    S6["S6 s6-verify<br/>fresh agentic session per finding tries to<br/>PROVE IT WRONG. Emits input order, not completion order"]
    B3{"budget check"}
    S7["S7 s7-dedup<br/>deterministic tiers plus one optional semantic call"]
    EN["enrich and compliance<br/>environmental CVSS, offensive priority, CWE tagging"]
    S8["S8 s8-chain<br/>all verified findings at once: exploit chains,<br/>exploitability re-ranking. ALWAYS RUNS"]
    RD["S9 reporting<br/>redact FinalReport, render Markdown and SARIF"]
    OUT["report.md, report.sarif, report.csv,<br/>findings.json, remediation.json"]

    S0 -->|SeedPackage| S1
    S1 -->|ContextPackage| S2
    S2 -->|ThreatModel attached to ctx| S3
    S3 -->|TaskManifest, chunks| S4
    S4 -->|candidate Findings| B1
    B1 -->|under cap| S5
    TP --> B2
    S5 -->|survivors plus DroppedFindings| B2
    B2 -->|under cap| S6
    S6 -->|verdicts| B3
    B3 -->|under cap| S7
    S7 --> EN
    EN --> S8
    B1 -->|cap tripped| S8
    B2 -->|cap tripped| S8
    B3 -->|cap tripped| S8
    S8 --> RD
    RD --> OUT
```

### What each stage consumes and produces

| Stage | Consumes | Produces | Off switch |
|---|---|---|---|
| **S0** `s0-seed` | repo root | `SeedPackage`, holding entry points, framework entry points with `reachable_from_unauth`, unsafe sinks, taint paths, taint evidence, call graph, def spans, file inventory | `step0.enabled` |
| **S1** `s1-preprocess` | repo root, known CVEs, design controls, changed files, `SeedPackage` | `ContextPackage` | not skippable; exploration skippable via `step1.mode: gap_fill` |
| **S2** `s2-threatmodel` | `ContextPackage`, on-disk docs and manifests, app profile | `ThreatModel`, attached to `ctx` | `step2.enabled`; also silently becomes `None` on any error |
| **S3** `s3-decompose` | `ContextPackage`, no raw code | `TaskManifest`: chunks plus unreachable files | not skippable |
| **S4** `s4-deepdive` | chunks, `ContextPackage` | `Finding` candidates, per-chunk outcomes | not skippable |
| **S5** `s5-prefilter` | candidates, `ContextPackage` | survivors plus `DroppedFinding`s | not skippable |
| **S6** `s6-verify` | survivors, `ContextPackage` | verified findings plus drops | not skippable |
| **S7** `s7-dedup` | verified findings | canonical findings plus duplicate drops | tiers individually toggleable |
| **S8** `s8-chain` | canonical findings, drops, raw count, metrics | `FinalReport` | **not skippable, and runs even after a budget stop** |
| **S9** `s9` | `FinalReport` | redacted report, Markdown and SARIF; CLI publishes exports | `--stop-after s8` stops before reporting |
| **S10** | a built `FinalReport` | `RemediationRun` | opt-in `--remediate` |
| **S11** | a finding plus its remediation record | `ValidationScore` | `step_validate.enabled` |

## The budget gate

One `SpendCap` with two independently-tripping fields: `--max-tokens` and
`--max-scan-seconds`. Both unset by default, in which case nothing ever
trips.

```mermaid
flowchart LR
    C["SpendCap<br/>max_total_tokens, max_wall_clock"]
    G["SpendGate<br/>always constructed, even with no cap"]
    Q["provider quota exhausted<br/>trips the shared gate from inside S4 or S6"]
    M["mid-stage: S4 per chunk, S6 per session,<br/>S5 and S7 semantic dedup call"]
    B["stage boundary: after S4, after S5, after S6"]
    U["surviving candidates become<br/>Unconfirmed drops, detail 'not verified'"]
    R["S8 analysis plus S9 reporting<br/>STILL RUN, producing a real partial report"]

    C --> G
    Q --> G
    G --> M
    G --> B
    B --> U
    M --> U
    U --> R
```

The distinction that matters: a **`--stop-after` stop** returns no report at
all. A **budget stop** falls through to the S8 tail with whatever is on hand,
and every candidate that never reached the verifier is recorded as
`Unconfirmed` with a detail beginning `"not verified"`, never as a
confirmed finding, and never silently dropped.

The report says so out loud, in `## Scan Health`:

> ⚠️ **BUDGET REACHED**: {reason}. The scan stopped starting new work at
> that point; findings from the work not done are absent, and any finding
> listed as not verified was never sent to the verifier.

The motivating incident is recorded in the code. A Juice Shop run rendered
160 unverified S4 candidates as 160 true positives at "100% precision",
which the code calls "the one thing this report must never do."

## S5's deterministic gates

Applied in a strict first-match-wins chain, so **a finding is dropped by at
most one gate**. Every rejection is recorded as a `DroppedFinding` with a
reason and a human-readable detail. Nothing is dropped silently.

```mermaid
flowchart TD
    IN["S4 candidate"]
    G0["path repair<br/>rewrite a hallucinated directory when exactly<br/>one inventory file matches at a path boundary"]
    G1{"test, mock or example path?"}
    V1["secret-class veto:<br/>a hardcoded-credential finding is KEPT<br/>even in a test path"]
    G2{"file in repo inventory?"}
    G3{"S4 confidence at or above min_pre_confidence?"}
    G4{"source_ref AND sink_ref both present?"}
    G5{"language gate"}
    G6{"route gate"}
    BF["evidence backfill<br/>synthesize a missing ref, mark it<br/>'inferred from AST, unverified'"]
    D7["S7 dedup tiers 0 to 2,<br/>plus semantic above pre_verify_threshold"]
    OK["to S6"]
    DROP["DroppedFinding<br/>reason plus detail"]

    IN --> G0
    G0 --> G1
    G1 -->|yes| V1
    V1 -->|not secret-class| DROP
    V1 -->|secret-class| G2
    G1 -->|no| G2
    G2 -->|no| DROP
    G2 -->|yes| G3
    G3 -->|below| DROP
    G3 -->|at or above| G4
    G4 -->|missing| DROP
    G4 -->|present| G5
    G5 -->|impossible in this language| DROP
    G5 -->|possible| G6
    G6 -->|guarded route, no bypass claimed| DROP
    G6 -->|kept| BF
    BF --> D7
    D7 --> OK
```

Gates 5 and 6 run last **because they are the only ones that read from
disk**. A finding the cheap gates already rejected never costs a file read.

The two language gates are deliberately one-directional: they only ever drop
a finding whose language rules make it *impossible*, and every ambiguity
(an unreadable file, an unknown extension, a construct that might be in a
script or URL context) resolves to *keep*.

| Gate | Drops | Measured effect |
|---|---|---|
| **Event-loop gate** | a CWE-362 race claim on JS/TS code with no suspension point in a ±2-line window. `await` and `.then` are boundaries; a bare `async` keyword is not; a callback counts only if its callee is on an allowlist | Juice Shop race false positives fell from **16** to **8** |
| **Template auto-escape gate** | an XSS finding on a construct the template engine escapes by default, in HTML text or attribute context. Vetoed inside `script` or `style`, in a `javascript:` URL, in an inline event handler, in CSS context, or on a dangerous attribute, checked per construct, not per window | JSX/TSX and Angular are deliberately excluded: `{expr}` is not distinguishable by regex |
| **Route gate** | see [`guard-gate.md`](guard-gate.md) | n/a |

## S7's dedup tiers

```mermaid
flowchart TD
    T0["Tier 0: canonical ordering, not a merge<br/>sort so 'lowest index wins' is CONTENT-derived,<br/>not arrival-derived"]
    T1["Tier 1: collapse_trivial<br/>flow identity, or sink identity, or same-file line proximity"]
    T2["Tier 2: collapse_same_range_cwes<br/>same file, EXACTLY equal line range, different explicit CWE"]
    T3["Tier 3: semantic<br/>one LLM call over the UNRESOLVED indices only"]
    FIN["attach duplicates to the canonical,<br/>fold the loser's CWE into related_cwes,<br/>record each loser as a Duplicate drop"]

    T0 --> T1
    T1 --> T2
    T2 --> T3
    T3 --> FIN
```

Tier 0's sort keys, in order: sink-anchoredness, file, `line_start`,
severity, `vuln_class`, **CWE rank** (a specific CWE beats an umbrella one
such as CWE-20 or CWE-200), verdict confidence, S4 confidence, title. The
CWE key sits deliberately *before* the confidence keys, because model
confidence flips between runs and was observed flipping a finding's identity
between two runs of the same commit.

Tier 2 runs **after** tier 1, and that ordering is load-bearing: tier 1's
matches are the higher-confidence ones, so letting them claim their
canonicals first means the same-range pass can only ever join clusters that
nothing else explained. It collapsed **20-23 duplicate findings per run** on
Juice Shop: 11 findings for 3 near-identical functions in one file, filed
under four different CWEs on the same lines.

S5 runs tiers 0-2 too, before verification, because every lens collapsed
pre-verify is a whole multi-turn agentic S6 session that never has to happen.

## S10's safety gates

S10 treats the agent's edits as **a proposal that must earn the right to
stay**. Everything the agent writes is journalled with its pre-edit bytes
first, so a rollback is exact and works on a non-git target.

```mermaid
flowchart TD
    PRE{"policy pre-gate"}
    AG["agentic fix loop<br/>write-capable Read/Glob/Grep/Edit/Write, never Bash"]
    RT["one retry when the agent claims a fix<br/>but wrote nothing. Capped at one, never a loop"]
    G1{"deny-list post-gate"}
    G2{"tree-sitter parse gate"}
    G3{"operator verify command"}
    G4{"size caps"}
    G5{"dry run?"}
    G6{"verdict is Fixed?"}
    KEEP["patch stays on disk"]
    REV["revert, verdict downgraded to NeedsReview,<br/>final_verdict REJECT"]
    NOP["guidance only, zero tokens spent"]

    PRE -->|deny| NOP
    PRE -->|allow| AG
    AG --> RT
    RT --> G1
    G1 -->|forbidden path touched| REV
    G1 -->|clean| G2
    G2 -->|a touched file no longer parses| REV
    G2 -->|parses| G3
    G3 -->|non-zero exit or timeout| REV
    G3 -->|passes| G4
    G4 -->|over max_diff_lines or max_files_touched| REV
    G4 -->|within caps| G5
    G5 -->|yes| REV
    G5 -->|no| G6
    G6 -->|no, and not keep_unverified| REV
    G6 -->|yes| KEEP
```

Details that are easy to get wrong:

- **The parse gate runs *after* the deny-list gate on purpose**, so a
  deny-listed path that also got mangled keeps its compliance audit trail
  rather than being reported as a mere syntax error.
- **Size caps are measured over everything *touched*, not just what the
  agent admitted to**, so an under-reported rewrite cannot slip the cap.
  Defaults: 200 diff lines, 1 file.
- **Dry run reverts but keeps the diff**, so PR fix suggestions still work.
- **The verdict gate exists because a half-applied fix is worse than no
  fix**: it looks addressed. `Not Fixed`, `Partially Fixed`, `Needs Review`
  and `False Positive` all revert unless `--keep-unverified`.
- The legacy operator verify command **executes a host shell command**.
  Its string is operator-configured, but the command can execute hostile
  target code. Target-testing mode rejects it and uses separately approved
  isolated execution instead.
- **A rolled-back finding is never checkpointed**, so `--resume` re-attempts
  it rather than skipping past a fix that is not on disk.

## S11 validation

A two-persona panel by default (`security-architect` and
`penetration-tester`, run concurrently) grading an S10 fix against four
weighted gates. A third, `cross-repo-analyzer`, is opt-in. The personas get
a **read-only** executor, never the write-capable one S10 used.

| Gate | Weight | Critical |
|---|---|---|
| `root_cause` | 0.43 | **yes** |
| `instance_coverage` | 0.2467 | no |
| `no_new_vulnerabilities` | 0.1867 | **yes** |
| `security_best_practices` | 0.1366 | no |

A critical gate that is skipped or garbled makes the whole result
`Unverifiable`; either critical gate being unclean caps the verdict below
`Fixed` regardless of the numeric score. A `Skip` leaves a gate out of the
denominator; an `Invalid` scores 0.0 and **stays in** it, so a garbled report
drags the score down rather than vanishing. Thresholds: `Fixed` at 0.80,
`PartiallyFixed` at 0.50.

A `NotFixed` or `Unverifiable` verdict reverts the patch using S10's
byte-exact baseline, while protecting files a *later* finding's kept patch
also touched.

## Full-scan target tests and delivery

```mermaid
flowchart TD
    SC["Full scan through S9"] --> COMPLETE{"Scan complete and eligible?"}
    COMPLETE -->|yes| DISC["Optional target testing: inspect existing suites and gaps"]
    DISC --> BASE["Approved existing baseline commands, if configured"]
    BASE --> GEN["Generate missing tests for the selected level and review independently"]
    GEN --> PRE["Approved functional and security baseline commands, if configured"]
    PRE --> FIX["S10 remediation and S11 model assessment"]
    FIX --> CHECK["Protect bound tests and run approved postpatch checks"]
    CHECK --> GATE{"Delivery gates satisfied?"}
    GATE -->|yes| MODE{"Delivery selection"}
    MODE --> PATCH["Default: combined source and test patch"]
    MODE --> BRANCH["Branch: one commit pushed to a new branch"]
    MODE --> ZIP["ZIP: updated source snapshot for CI upload"]
    COMPLETE -->|no| STOP["Record refusal or blocker"]
    GATE -->|no| STOP
```

Without target testing, eligible remediation proceeds directly to S10/S11.
The shipped testing levels never execute target code: baseline and postpatch
commands require a vetted embedded execution profile. Generation and model
review alone do not establish a passing suite. Branch and ZIP modes require
a full scan and explicit delivery selection; ZIP uses an isolated source
snapshot without requiring Git. See [target testing](../target-testing.md)
and [remediation delivery](../remediation-delivery.md).
