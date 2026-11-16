# bc-sast vs. the Python harness it was ported from

`bc-sast` is a Rust port of
[`visa-vulnerability-agentic-harness`](https://github.com/visa/visa-vulnerability-agentic-harness)
("VVAH"). This document is the head-to-head measurement between the two,
re-measured on **2026-10-21/22 against VVAH v1.5.0**, the current upstream
release, with both scanners on the same model, the same wire API, the same
per-step token caps and the same scorer.

**48 runs: three per app per scanner, across eight languages.** Earlier
revisions of this document reported single runs against v1.2.0 on
`gpt-4o`; those numbers are superseded and are not reproduced here,
because several of them were measured under controls that were not
actually equal.

The short version: **the two find about the same bugs, and one of them
says so far more precisely.**

| | VVAH v1.5.0 | `bc-sast` |
|---|---|---|
| Recall | 86.5% (83/96) | **92.7%** (89/96) |
| Precision | 30.1% (97/322) | **57.7%** (90/156) |
| False findings per run | 9.2 | **2.5** |
| Findings reported per run | 13.4 | **6.5** |
| Cost per scan | **$0.0836** | $0.1305 |

The precision gap is the result: **1.9x, in the same direction in eight of
eight languages.** The recall edge is six findings out of 96 and is
smaller than it looks. The Python harness is cheaper per scan, and whether
it is cheaper overall turns on one number no manifest contains -- what it
costs to read and dismiss a finding that is not real. That is stated as a
[break-even](#the-cost-that-actually-matters) rather than a verdict.

Two of eight apps go the other way, and they are in the table like
everything else: VVAH wins `c-cli` (100% against 91.7%) and `php-laravel`
(91.7% against 83.3%).

> [!IMPORTANT]
> **This port had four defects fixed during the study; the upstream
> harness had none.** These tables compare `bc-sast` at HEAD against stock
> `vvaharness` v1.5.0, not two designs given equal scrutiny. One of those
> fixes removed a handicap on this port and one of the benchmark
> corrections removed a handicap on the Python side. See
> [What is not equal](#what-is-not-equal-and-must-be-read-with-the-numbers),
> which is the section to read before quoting any number here.

---

## Contents

- [Feature comparison against v1.5.0](#feature-comparison-against-v150)
- [Methodology](#methodology)
- [Results: the polyglot test bed](#results-the-polyglot-test-bed)
- [Results: OWASP Juice Shop backend](#results-owasp-juice-shop-backend)
- [Results: a multi-file Flask pull request](#results-a-multi-file-flask-pull-request)
- [Cost](#cost)
- [What each one does better](#what-each-one-does-better)
- [Behavioral differences and what was not ported](#behavioral-differences-and-what-was-not-ported)
- [Limitations of this comparison](#limitations-of-this-comparison)
- [Reproducing these numbers](#reproducing-these-numbers)

---

## Feature comparison against v1.5.0

Current as of **2026-10-20**, read from both codebases rather than from
release notes. Every row was checked against the source on both sides; where
a capability is partial, the cell says what is missing rather than taking a
tick or a cross.

No benchmark number appears in this section. Nothing here has been measured
head-to-head against v1.5.0, and that is stated rather than implied.

### Detection

| | `bc-sast` | VVAH v1.5.0 |
|---|---|---|
| Structural analysis | In-process call graph and taint walk over tree-sitter | Embedded ArcadeDB code graph, queried by agent tools |
| Token-free seed plane | Yes | Yes |
| Model-free stages | S0 | S0, S1, S3, S5, and S8 ranking |
| Graph exposed to the model as tools | No | Yes, for S2/S4/S6 |
| Multi-run voting on the deep dive | Configurable, defaults to one run | Removed in v1.5.0 |
| Deterministic detectors that add findings | No, S5 gates only suppress | Yes |
| Injected detection skills | No | 17 |
| Languages in the seed plane | 11 | Tree-sitter grammars, pinned exactly |

### Verification and triage

| | `bc-sast` | VVAH v1.5.0 |
|---|---|---|
| Adversarial verification stage | Yes, S6 | Yes, S6 |
| Semantic dedup | Yes, S7 | Yes, S7 |
| Exploit chaining | Yes, S8 | Yes, S8 |
| Live exploit verification | No, deliberately not ported | Yes, since v1.4.0 |
| Third-party scan ingestion | 5 vendors: Aikido, Checkmarx, Semgrep, Snyk, Sonatype | Semgrep, as a reference plugin |
| Assessments written back to the vendor | Yes | No |
| Plugin SDK for outside enrichers and tools | No | Yes |

### Remediation

| | `bc-sast` | VVAH v1.5.0 |
|---|---|---|
| Agentic fix loop | Yes, S10 | Yes |
| Worktree isolation | Yes | Yes |
| Validation panel | Yes, S11, on by default | Yes, opt-in |
| Rollback when a fix cannot be verified | Yes | Yes |
| Cross-file fixes applied automatically | No, reported only | Configurable |
| Target-repository test execution | Yes, opt-in, no execution in shipped profiles | No |
| API specification step | Yes, 9 standards | No |

### Operations

| | `bc-sast` | VVAH v1.5.0 |
|---|---|---|
| Install | Single static binary, or a container | Python 3.11+, plus native wheels |
| Platform matrix | Any target Rust builds | macOS arm64, Linux x86_64/aarch64 (glibc 2.34+), Windows amd64 |
| A failed graph build aborts the scan | No graph to fail | Yes |
| Cooperative Ctrl-C, partial report, exit 130 | Yes | Cancellation, without the partial-report contract |
| Diff scope enforced end to end | Yes, including imported third-party findings | Diff scope, not extended over imports |
| Per-call cost reporting | Yes, priced per context tier | Yes |
| Token and wall-clock budgets that degrade | Yes | Yes, plus coded exhaustion errors |
| Per-stage model routing | Yes, `models.<role>` | Yes, plus per-stage reasoning effort |
| SARIF built from typed data | Yes, since 1.0.0 | Yes, as of v1.5.0 |
| `findings.json` versioned | No | Yes, `schema_version: "1.0"` |
| Resumable checkpoints | Yes, engine-keyed | Yes, typed schema |

### No longer a difference

Four rows that were advantages and are not any more. A stale comparison is
worse than none:

- **Typed SARIF.** This port built SARIF from typed data from the start.
  v1.5.0 has now moved to the same thing and deleted its Markdown re-parse
  producer. The advantage is gone.
- **The OpenAI Responses API.** Both have a native transport.
- **CWE case-insensitivity in dedup**, and **refusing a corrupt
  `findings.json` before remediating.** v1.5.0 fixed both; this port already
  behaved that way.

### What has not been compared

Every recall, precision and cost figure in this document now reflects
**v1.5.0 on both sides**, re-measured 2026-10-21/22. The v1.2.0 numbers
earlier revisions carried are gone rather than annotated, because several
were measured under controls that turned out not to be equal -- an
unverified wire API on one side and a 4:1 output-token cap on the other.

What is still **not** compared: remediation (both sides run detection
only, `--stop-after s9`), any model other than `gpt-6-luna`, and any
target outside the polyglot bed for the Python side. The Juice Shop and
Flask sections below have no Python column and say so.

Worth stating plainly, because the shape of a comparison document invites
the opposite reading: v1.5.0 made three stages deterministic and added
detectors that contribute findings, and both changes could move its
precision and recall in its own favour. This document does not claim a
current detection result in either direction.

---

## Methodology

### The two scanners

|  | Rust | Python |
|---|---|---|
| Name | `bc-sast` (this repository) | `visa-vulnerability-agentic-harness` **v1.5.0** |
| Invocation | `appsec-scan --repo ... --model gpt-6-luna --openai-api responses --temperature 0 --stop-after s9` | `vvaharness scan --repo ... --config ... --stop-after s9` |
| Configuration | CLI flags | shipped `default.yaml` profile **verbatim**, plus a `config.local.yaml` overlay (the harness's own documented, logged override mechanism) |

The Python side is run as close to stock as it can be run: installed from
the upstream `v1.5.0` tag by `pip install ./vvah-src` on every run, never
from a local copy. The overlay is confined to what the comparison itself
requires:

1. **Model routing.** The shipped profile runs every detection role as
   `via: cli` (a Claude Code subprocess), which would compare two scanners
   on two different models. Every role is repointed at the same OpenAI
   model the Rust runs use, at `temperature: 0`.
2. **Per-step output caps**, set to the same `64000` the Rust port gives
   every step. See [Held equal](#held-equal) -- this one was wrong for a
   while and the correction is recorded there, because it mattered.
3. **S11 validation off**, and its model panel repointed at OpenAI anyway,
   because the startup preflight probes every role in `models.*` whether or
   not its stage is enabled. S11 has no counterpart in the Rust runs.

Everything else keeps the harness default, including its S0 static seed
plane, which `default.yaml` enables.

### Held equal

- **Same model:** `gpt-6-luna`, `temperature 0`, same OpenAI endpoint.
- **Same wire API, verified rather than assumed.** Both sides speak the
  OpenAI **Responses** API. On the Rust side this is pinned with
  `--openai-api responses` and then **checked in all 24 run manifests**:
  every role records `transport_resolved: responses` with `fell_back:
  false` and a run-wide `responses_fallbacks: 0`. An earlier series was
  discarded because it ran under `--openai-api auto`, which records only
  the strategy and not the endpoint, so nothing in the artifacts could say
  which API had answered.
- **Same per-step output cap: 64000.** This was *not* equal in an earlier
  series, and the correction is the reason this section is explicit. The
  Python overlay capped every step at 16000, correct for `gpt-4o`'s
  16384-token completion ceiling and a 4:1 handicap once the benchmark
  moved to `gpt-6-luna` against the Rust port's 64000. It bit: those
  manifests record `llm_truncated_retry_attempted: 4` and
  `llm_truncated_retry_recovered: 4` across 27 runs, against zero
  truncations on the Rust side. The harness's own retry recovered every
  one, so nothing was lost -- but an unequal setting does not belong in a
  like-for-like benchmark whether or not it changed the answer. At matched
  caps there are **no truncations on either side**.
- **Neither side sends a seed.** The Responses API has no `seed`
  parameter, so `--seed` is inert there for both. `temperature 0` is sent
  and accepted by both. This is the ceiling on determinism and it is
  OpenAI's, not either scanner's -- see
  [the variance caveat](#sample-sizes-and-the-variance-caveat).
- **Same scope:** the same `step1` exclude list on both sides. Supplying it
  on the Python side also disables the profile's AI auto-exclude survey, so
  the scope is deterministic and costs no extra model call.
- **Same stopping point:** detection only, `--stop-after s9` on both. No
  remediation on either side.
- **Same scorer, same ground truth:** `polyglot/score.py` in the demo
  repository, against the identical checked-in `ground-truth.json`.
- **Ground truth is hidden from both.** Each app's `ground-truth.json` is
  moved out of the scan target before the scan starts and moved back
  afterwards. Neither scanner ever sees the answers.
- **Both runs happen in GitHub Actions**, on `ubuntu-latest`, one app per
  run, with the scanner built from a **pinned commit** rather than a branch
  name.

### What is not equal, and must be read with the numbers

**The Rust port had four defects fixed during this study. The Python
harness had none.** Fixing upstream's code is not ours to do, but it means
these tables compare *`bc-sast` at HEAD* against *stock `vvaharness`
v1.5.0*, not two designs given the same scrutiny. A reader could
reasonably assume otherwise, so it is stated here rather than inferred.

Corrections went in both directions, which is the part that makes the
comparison usable:

| fix | effect | whom it favoured |
|---|---|---|
| `gpt-6` sampling rule | `--temperature 0` was being dropped before the request was built, so Rust runs sampled non-deterministically while Python's did not | **removed a handicap on Rust** |
| Python per-step output caps | 16000 against Rust's 64000 | **removed a handicap on Python** |
| S3 taint-chunk dedup | ~3% fewer LLM calls, ~5% lower cost, and 11 fewer false positives over 21 runs | Rust |
| S7 dedup survivor | kept an arbitrarily-anchored member of a merged cluster, so a found bug could read as a miss | Rust |

One fixture was corrected too, and it changed a result more than any
scanner fix did. `c-cli` marked all four of its flaws
`reachable_from_unauth: true` while installing the binary `0755`
non-setuid with no config install rule -- so every input was the invoking
user's own, nothing crossed a privilege boundary, and **both** scanners
correctly put all four out of scope under a standard triage exclusion.
Both found the flaws and both refuted them, one verifier writing *"the
repository shows no lower-privileged way to modify that file"*. The
fixture was scoring correct reasoning as a miss. It now installs setuid to
a service account with a group-writable notice config, which is what its
ground truth always asserted. `c-cli` numbers from before that change are
not comparable with these, and the deliberate non-fix is worth naming:
the exclusion rule was **not** weakened, because it is what produces the
precision this bed exists to measure.

### Ground truth

Each polyglot app ships a `ground-truth.json` holding:

- `expected`: one entry per seeded vulnerability, carrying its id, CWE, the
  **exact** sink file and line, the **exact** source file and line, a title,
  and `reachable_from_unauth`.
- `negative_controls`: the safe counterpart of a seeded shape (a bound
  placeholder, a bounded copy), with the line it lives on and why it is safe.
- `routes`: method, path, handler, and whether the route carries an auth
  guard.

Line numbers were generated mechanically from markers in the source, so
they are exact rather than approximate.

### The scorer, and what "precision" means here

A finding **matches** an expected item when *both* hold:

1. **The CWE agrees**: the finding's CWE equals the expected CWE, or sits
   in the same family. The scorer carries eleven explicit families (SQL/NoSQL
   injection; command injection; path traversal; code injection and dynamic
   include; deserialization; XXE; SSRF; memory bounds; use-after-free and
   double-free; format string; authorization), so a scanner that says
   CWE-787 where the truth says CWE-125 has still found the same bug.
2. **The location agrees**: one of the finding's locations names the
   expected item's sink *or* source file, with the expected line inside
   `line_start - 5 .. line_end + 5`. A finding's locations are its top-level
   `file` plus `line_start`/`line_end`, and also whatever its `source_ref` /
   `sink_ref` fields say.

Then:

```text
recall    = seeded flows found / seeded flows            (out of 4 per app)
precision = matched findings / ALL findings reported
controls  = negative controls wrongly reported           (out of 1 per app)
```

> [!IMPORTANT]
> **"Precision" here is stricter than the word usually implies.** The
> denominator is *every* finding the scanner reported. A finding that is a
> perfectly real vulnerability, correctly located, but simply not one of the
> four the app's author seeded and wrote down, still counts against
> precision. It is better read as **"share of output that lands on a
> known-planted flaw"** than as "share of output that is true". Both
> scanners are penalized the same way by the same rule, which is what makes
> the comparison fair, but neither number is a false-positive rate.

Negative controls are scored the other way round and **without regard to
CWE**: any finding landing within ±5 lines of a control counts against it.
Some apps deliberately keep the safe query a few lines from the seeded one
(discriminating between them in the same file is the point), so a finding is
credited to whichever line it is actually nearer. Only a report *strictly*
closer to the safe line is a false positive; ties go to the expected item.

The scorer always exits 0. It measures; it does not gate.

### Sample sizes, and the variance caveat

**Three runs per app per scanner -- 24 runs each side, 48 in total.** Every
per-app cell below is the pooled result of three samples, not one.

> [!WARNING]
> **This is still a stochastic system, and the variance is large.**
> `temperature 0` is sent and accepted by both scanners, but neither sends
> a seed, because the OpenAI Responses API has no `seed` parameter. So
> `temperature 0` is the only determinism control available to either
> side, and it is not sufficient.
>
> One concrete case shows the size of that.
> On `rust-axum`, one scanner at `temperature 0` over identical source
> scored **75%, 75% and 50%** across three runs -- a 25-point swing from
> sampling alone. On `c-cli`, two of the four planted flaws were found in
> one run out of three each, until a dedup defect behind that was fixed.
>
> Read per-app rows as indicative and the pooled totals as the signal. A
> one- or two-finding difference in a single row means nothing. The
> precision gap -- roughly two-fold, in the same direction in **eight of
> eight** languages -- is what survives the noise. The recall difference is
> six findings out of 96 and should be read as near parity, not as a
> win.

Pooling, rather than averaging the per-run percentages, is deliberate: a
mean of means weights a run that found 1 of 4 the same as one that found
4 of 4. Every aggregate below is `sum(matched) / sum(expected)` over all
runs in scope.

One asymmetry in the sampling itself: the Python side is **uncapped**. It
has no token budget and no wall-clock cap, so its cost figures are a
single sample of a distribution with no ceiling, stopped only by the
workflow's `timeout-minutes`. The Rust runs carry `--max-tokens 1500000`
and `--max-scan-seconds 4800`. Neither limit was reached in any run
reported here, so they did not shape these results, but they bound the
Rust tail and nothing bounds Python's.

---

## Results: the polyglot test bed

Eight small applications, one per language, each with the same skeleton:
**4 seeded cross-file vulnerabilities** (user input read at an entry
point, passed through a helper in a second file, reaching a sink in a
third), **1 parameterized negative control** (the same shape done
safely), and, for the seven with an HTTP surface, one unauthenticated
route plus at least one behind a framework-idiomatic auth guard. `c-cli`
is a command-line tool and has no routes; its privilege boundary is its
setuid install.

Three vulnerability classes are common to all eight (SQL injection,
command injection, path traversal), plus one idiomatic to each language.
So a gap in the table is a gap in a language's coverage, not a difference
in the sample code.

### The table

| app | Python recall | Rust recall | Python precision | Rust precision |
|---|---|---|---|---|
| `c-cli` | **100.0%** (12/12) | 91.7% (11/12) | 44.4% (12/27) | **50.0%** (11/22) |
| `csharp-aspnet` | 75.0% (9/12) | **91.7%** (11/12) | 29.4% (10/34) | **78.6%** (11/14) |
| `go-gin` | 83.3% (10/12) | **100.0%** (12/12) | 24.6% (14/57) | **48.0%** (12/25) |
| `java-spring` | 100.0% (12/12) | 100.0% (12/12) | 25.5% (13/51) | **72.2%** (13/18) |
| `kotlin-ktor` | 100.0% (12/12) | 100.0% (12/12) | 24.6% (14/57) | **50.0%** (12/24) |
| `php-laravel` | **91.7%** (11/12) | 83.3% (10/12) | 37.8% (14/37) | **52.6%** (10/19) |
| `ruby-rails` | 100.0% (12/12) | 100.0% (12/12) | 38.2% (13/34) | **54.5%** (12/22) |
| `rust-axum` | 41.7% (5/12) | **75.0%** (9/12) | 28.0% (7/25) | **75.0%** (9/12) |
| **all eight** | **86.5%** (83/96) | **92.7%** (89/96) | **30.1%** (97/322) | **57.7%** (90/156) |

![Recall by language](diagrams/recall-by-language.svg)

![Precision by language](diagrams/precision-by-language.svg)

### Reading it

**Precision is the result.** 57.7% against 30.1% is a 1.9-fold gap, and
it runs in the same direction in **eight of eight** languages. That
consistency is what makes it a finding; at three runs per cell no single
app's number is trustworthy on its own.

**Recall is a real but smaller edge.** 89/96 against 83/96 -- six
findings. This is the first batch where it clears the measured noise
floor, and it only does so because a dedup defect was fixed first (see
[What is not equal](#what-is-not-equal-and-must-be-read-with-the-numbers)).
Read earlier claims of a recall advantage with suspicion; earlier batches
put it at three findings, which is inside the noise.

**Two apps go to the Python harness.** `c-cli` 100% against 91.7%, and
`php-laravel` 91.7% against 83.3%. The `c-cli` row is the honest one to
dwell on: it is the memory-safety app, the Python harness finds all four
planted flaws in all three runs, and this port does not.

**The negative controls barely separate the two.** The Python harness
reported none of its 20; this port reported one of 18, on `rust-axum`.

### False findings

Precision expressed as a count is the number that reaches whoever has to
read the report, so it is stated separately from the ratio.

| app | Python false findings/run | Rust false findings/run |
|---|---|---|
| `c-cli` | 5.0 | **3.7** |
| `csharp-aspnet` | 8.0 | **0.7** |
| `go-gin` | 14.3 | **4.3** |
| `java-spring` | 12.7 | **1.7** |
| `kotlin-ktor` | 14.0 | **3.0** |
| `php-laravel` | 7.7 | **2.3** |
| `ruby-rails` | 6.0 | **3.3** |
| `rust-axum` | 6.0 | **1.0** |
| **mean** | **9.2** | **2.5** |

![False findings per run](diagrams/false-findings-per-run.svg)

Every reported finding that matches no planted vulnerability costs
somebody the time to open the file, follow the flow and decide it is not
real. That is the work the precision gap is actually about.

### Negative controls

Each app ships one safe counterpart of a seeded shape -- a bound
placeholder, a bounded copy -- and reporting it is a false positive of the
most embarrassing kind, because the control exists precisely to look like
the bug.

Across all 24 runs each side: the Python harness wrongly reported **0 of
20**; the Rust port **1 of 18** -- `rust-axum`'s bound-parameter query,
detailed under [where the Python harness was
credited](#where-the-python-harness-was-credited-and-the-rust-port-was-not).

### Where the difference comes from

The Python harness reports **13.4 findings per run** to convey **3.46**
real ones. This port reports **6.5** to convey **3.71**. It is not
finding less and reporting less; it is finding slightly more and
reporting half as much.

The stages that do it have no Python counterpart in these runs: the seed
plane's evidence packing, an adversarial verifier that can refute a
candidate outright, and a pre-verify dedup pass. That is also where the
extra cost goes, so the precision and the price are the same mechanism
seen from two sides.

## Results: OWASP Juice Shop backend

A real application rather than a test bed: 199 backend files, 150 of them in
scope after exclusions. **These are Rust-only runs** (back-to-back, on the
same commit family), measuring what the S0 seed plane is worth. There is no
Python column here.

| | seed plane **off** | seed plane **on**, correct scope |
|---|---|---|
| wall-clock | 1313 s | **428 s** |
| tokens | 6.40M | **4.56M** |
| raw candidates | 277 | 141 |
| confirmed | 171 | 98 |
| refuted | 74 | 30 |
| verification precision | 69.8% | **76.6%** |
| verifier errors | n/a | **0** |
| rate-limit retries | n/a | **0** |
| budget outcome | **cap tripped before S7** | completed |
| canonical challenge files hit | 14/15 | 14/15 |

Verification precision here is `confirmed / (confirmed + refuted)`, the
share of what the detection stage proposed that survived the verifier. It is
a different measurement from the polyglot bed's precision, which is scored
against hand-written ground truth. In the seed-on run every raw candidate
is accounted for: 98 confirmed, 30 refuted, 8 collapsed as duplicates
before verification, 4 excluded by the deterministic S5 gates (three
template auto-escape, one test path) and 1 left unconfirmed by the
verifier. In the seed-off run the remainder never reached a verdict,
which is what the budget cap tripping before S7 means.

**3.1x faster, 29% fewer tokens, and it finished instead of hitting the
cap**, while hitting the same 14 of 15 canonical challenge files. The
seed plane is not a detection aid so much as a *targeting* aid: it
spends static analysis to avoid spending model calls.

The verification-precision difference in that table (69.8% to 76.6%) is
not claimed as a result. This is one run pair, and the variance warning
above documents a 25-point swing on identical source from sampling
alone; a 6.8-point difference between single runs is inside it. The
wall-clock and token deltas are large enough to survive that noise.

See [`diagrams/seed-plane.md`](diagrams/seed-plane.md) for what it actually
computes.

### The fix series that got it there

Juice Shop was scanned repeatedly while defects found in the previous run
were fixed. The measurable deltas, each attributable to one change:

| change | before | after |
|---|---|---|
| `Retry-After` handling on burst 429s | 24 verifications lost to rate limiting | **0** |
| JS/TS event-loop gate | 16 race-condition false positives | **8** |
| template auto-escape gate | n/a | XSS candidates in auto-escaped templates dropped deterministically |
| same-range CWE merge in S7 | 20-23 duplicate findings per run | **collapsed** |

These are the deterministic gates described in
[`diagrams/finding-lifecycle.md`](diagrams/finding-lifecycle.md). None of
them asks the model anything; they are all cheap, repeatable filters applied
to what the model already said.

---

## Results: a multi-file Flask pull request

Seven runs against the same multi-file Flask pull request, exercising the
GitHub Action path end to end.

- The **last two runs kept 5 of 5 finding identities** across runs. The
  same finding got the same id, so a PR comment could be updated rather than
  duplicated.
- **Remediation succeeded 5/5 and 6/6.**
- **PR comments reconciled**: on re-run, existing comments were updated in
  place; no duplicates were posted.

Finding identity stability is the thing that makes the Action usable on a
busy PR. Without it, every push re-posts every comment. See
[`diagrams/finding-lifecycle.md`](diagrams/finding-lifecycle.md) for how the
id is built and matched.

---

## Cost

Both sides are priced by the **same external calculation**, not by one
side's own figure against a derivation of the other's. That matters here:
the Python harness reports `cost_usd: null` with
`pricing_status: {"status": "unavailable", "reason": "no pricing table
configured"}`, so it supplies token counts and no money. Taking the Rust
port's self-reported cost and hand-deriving Python's would compare two
different methods.

The formula is `fresh_input x rate + output x rate + cache_read x rate +
cache_write x rate`, at `gpt-6-luna`'s published per-token rates, where
`fresh_input = input - cache_write` because **both manifests report input
GROSS** -- the cache-write tokens are already inside it. It is validated
against the Rust port's own `cost_usd` on every run and reproduces it to
**zero error**, which is the check that makes the Python column
trustworthy rather than plausible.

> [!NOTE]
> That validation exists because the obvious version of this arithmetic
> was wrong. Charging `input` and `cache_write` both at full rate
> double-counts the overlap and inflates every figure by
> `cache_write x input_rate` -- about 26% on these runs. It produced a
> self-consistent table that disagreed with the scanner's own number, and
> the discrepancy was briefly explained away as per-call price tiering
> before the actual cause was found. The harvest script now asserts the
> reproduction and refuses to print numbers it cannot reconcile.

### Per scan

| app | Python $/scan | Rust $/scan | ratio |
|---|---|---|---|
| `c-cli` | $0.0731 | $0.1354 | 1.85x |
| `csharp-aspnet` | $0.0664 | $0.1056 | 1.59x |
| `go-gin` | $0.1055 | $0.1510 | 1.43x |
| `java-spring` | $0.0969 | $0.1342 | 1.38x |
| `kotlin-ktor` | $0.1055 | $0.1451 | 1.37x |
| `php-laravel` | $0.0750 | $0.1266 | 1.69x |
| `ruby-rails` | $0.0700 | $0.1027 | 1.47x |
| `rust-axum` | $0.0762 | $0.1430 | 1.88x |
| **mean** | **$0.0836** | **$0.1305** | **1.56x** |

![Cost per scan](diagrams/cost-per-scan.svg)

### The cost that actually matters

Cost per scan is the wrong denominator on its own, because the two
scanners do not deliver the same thing. A finding that is not real still
has to be read, traced and dismissed by somebody.

| | Python | Rust |
|---|---|---|
| findings reported per run | 13.4 | **6.5** |
| distinct planted bugs found per run | 3.46 | **3.71** |
| false findings per run | 9.2 | **2.5** |
| cost per bug found | $0.0242 | $0.0352 |
| cost per REPORTED finding | $0.0062 | $0.0201 |

So the Rust port costs more per scan and returns a smaller pile with a
larger true share. Whether that is cheaper depends on one number nobody
can take from a manifest -- what it costs to triage a false finding -- so
the honest form of the claim is a **break-even**:

The Rust port spends **$0.0469** more per scan and returns **6.7** fewer false findings. Break-even is **$0.0070** of triage time per false finding.

Above that figure, the Rust port is cheaper in total cost of ownership.
Below it, the Python harness is. The figure is small enough that any
plausible cost of a security engineer's attention clears it, but it is
stated as a threshold rather than a conclusion because the inputs to it
are not ours to assert.

### What the extra spend buys

The Rust port makes more calls per scan, and they are not the same calls.
Python's pipeline stops at detection with no source/sink references
emitted; the Rust port additionally runs the seed plane's evidence
packing, an adversarial verifier that can refute a candidate, and the
attack-chain stage. The verifier is where most of the precision gap comes
from, and it is a cost line Python does not have because it does not do
the work.

## What each one does better

### Where the Python harness was credited and the Rust port was not

Stated first, because it is the part a comparison written by the porting
team is most likely to bury.

1. **`csharp-aspnet` recall: Python 4/4, Rust 3/4.** The port anchored the
   SQL injection at the method header, outside the scorer's window. Python
   put it on the sink line. Anchoring precision is a real property and
   Python won that row on the measurement as run.
2. **`go-gin` recall: Python 4/4, Rust 3/4.** Python filed the SSRF as
   CWE-918. The port filed it as CWE-20/285, a defensible reading (the
   handler does fail to validate a URL) that is nonetheless the *less
   useful* classification, and it cost the match.
3. **`c-cli` recall: Python 4/4 on the class, Rust 3/4.** The port anchored
   the use-after-free at the `free()` rather than the later read. Fixed
   and re-measured in the batch these numbers come from.
4. **`rust-axum` negative control: Python 0/1, Rust 1/1.** The port reported
   the safe bound-parameter query as a finding. Python did not. This is a
   plain false positive on the port's side, on the one app where the safe
   path is *statically impossible* to misuse (it takes `&'static str`).
5. **`csharp-aspnet` precision denominator: Python found 5 matching
   findings, the port 3.** Python's extra credited finding is a second
   report hitting the same seeded item. It is noisier, but it did land.
6. **Python is cheaper on `go-gin`** (273,225 vs 220,831 tokens, though
   note this is the direction *against* Python; see the caveat above).

Taken together: the port's anchoring and CWE-assignment discipline is
**not** strictly better than the harness's. On three of eight apps it was
worse in a way that a stricter scorer would punish and a human triager would
forgive.

### Where the Rust port is better

1. **Precision: 57.7% vs 30.1%**, in the same direction in eight of eight
   languages, on slightly better recall. **6.7 fewer false findings per
   run** -- 160 fewer across the 24 runs -- which is the number that reaches
   whoever reads the report.
2. **Reproducibility of everything that is not the model.** Verification
   results are emitted in input order rather than completion order and
   then sorted by content; dedup keys on CWE and flow identity rather than
   on the model's chosen class label; the static seed plane is fully
   deterministic and measured as such (identical sink and entry-point
   counts across all three runs of every app).

   **This does not make a run reproducible, and an earlier revision of
   this document wrongly implied it did.** It claimed "two runs of the
   same commit produce the same report". They do not. `--seed` is plumbed
   through, but the OpenAI **Responses API has no `seed` parameter**, so
   on the transport both scanners now use it is inert; `temperature 0` is
   the only control either side has, and greedy decoding is not
   deterministic on production serving infrastructure. Measured on this
   bed: the same scanner, same commit, same app, same model scored 40%,
   33% and 80% precision across three runs. The divergence is traceable  --
   it begins at the first model call that exercises judgement and
   cascades, because a threat model with 18 entries instead of 27 packs
   different chunks, which changes how many deep-dive calls run and what
   each one sees. See
   [the variance caveat](#sample-sizes-and-the-variance-caveat).
3. **Honesty of reporting.** Structured `findings.json` carrying source and
   sink references, a real SARIF built from the finding objects with stable
   fingerprints, and a `## Dropped Findings` section recording every
   rejected candidate with a tagged reason, plus a `Not verified` count
   under `## Verification` and a **BUDGET REACHED** line under
   `## Scan Health`. A run that ran out of budget says so, rather than
   silently reporting less.
4. **Robustness.** Quota exhaustion is distinguished from a burst rate-limit
   and fails in seconds rather than retrying for the length of the timeout;
   `Retry-After` is honored; an oversized `max_tokens` is self-corrected
   rather than turning into a zero-finding scan.
5. **Operability.** Token budget, wall-clock cap, output paths, checkpoint
   resume, diff scope, batch `--repo-file`.
6. **Remediation safety.** Fixes run behind a deterministic policy gate with
   diff capture and revert, rather than editing target source by default.

---

## Behavioral differences and what was not ported

Where this port diverges from the Python original, and what was left
out on purpose, are in [porting notes](porting-notes.md). None of it is
measurement, which is why it is not in this document.

## Limitations of this comparison

Read these before quoting any number above.

1. **This port was fixed during the study; the upstream harness was not.**
   Four defects in `bc-sast` were found and fixed between the first and
   last batch, so these numbers are HEAD against stock v1.5.0 rather than
   two designs given equal scrutiny. Corrections ran both ways -- one
   removed a handicap on this port, one benchmark correction removed a 4:1
   output-token handicap on the Python side -- but upstream's own defects
   were left alone, because fixing them is not ours to do. Read
   [What is not equal](#what-is-not-equal-and-must-be-read-with-the-numbers)
   before quoting anything.

2. **Three runs per cell, against a noise floor larger than most of the
   differences.** Within a single batch, the same scanner on the same code
   swung **up to 47 points of precision** between runs, median spread 11-15
   points. So no per-app row is trustworthy on its own, and only two claims
   here clear that floor: the precision gap (because it repeats in eight of
   eight languages) and `c-cli`'s 25-point recall gain (because the dedup
   fix behind it has unit tests on the exact shapes). The aggregate
   precision difference between the last two batches, **-4.9 points, is
   inside the noise and is not attributed to the change that separates
   them** -- in either direction. No confidence intervals are offered
   because three samples cannot support them.

3. **Neither scanner can be made reproducible on this transport.** The
   OpenAI Responses API has no `seed` parameter, so `temperature 0` is the
   only determinism control available to either side, and it is not
   sufficient. The divergence is observable and starts at the first model
   call that exercises judgement: the static seed plane produces identical
   output across every run, S1's constrained output is stable, and the
   threat model is where runs begin to differ (18, 27 and 24 threats on
   one app) -- after which chunk packing, call counts and findings all
   diverge downstream. This is a property of the platform, affects both
   scanners equally, and is the main reason to read totals rather than
   rows. `step4.runs: 2` or higher enables vote-across-samples and trades
   cost for stability; it was deliberately left off so both sides ran
   single-sample.

4. **"Precision" penalizes real findings.** The denominator is all output,
   and the numerator is only findings matching a hand-written ground-truth
   item. A genuine vulnerability the app's author did not seed and write
   down counts as a miss. Both sides are penalized identically, but the
   absolute numbers are not false-positive rates and must not be quoted as
   such.

5. **The Python findings had to be converted, and lost fields on the way.**
   The harness emits no findings JSON, only Markdown and SARIF. A converter
   reconstructs the scorer's input shape from both (the SARIF for file, CWE
   and `startLine`; the Markdown for `line_end`, because the SARIF writer
   only ever emits `startLine`). Critically, the harness's own internal
   `Finding` model *does* carry `source_ref`/`sink_ref` as `"file:line"`,
   but **neither its Markdown writer nor its SARIF writer emits them**, so
   they are lost before any converter can see them. The scorer treats those
   as extra locations a finding may match on. **The Python side is therefore
   matched on its primary location only, while the Rust side gets up to
   three shots at the ±5-line window.** That is a genuine advantage to the
   Rust port, but it is an advantage in *reporting completeness*, not in
   detection, and some unknown part of the precision gap is attributable to
   it rather than to better analysis.

6. **Eight small apps are not a benchmark.** They are 3-4 seeded flows each,
   written to be parseable, in a known set of shapes. Real code is longer,
   messier, and has vulnerabilities nobody wrote down. Juice Shop is the
   only real-application datapoint here, and it has no Python column.

7. **No Python column for Juice Shop, the Flask PR, or remediation.** The
   most operationally interesting results are Rust-only.

8. **One model only (`gpt-6-luna`).** No claim is made about how either scanner behaves on a
   different model, and the Python harness's shipped defaults target
   Anthropic models it was not run against here.

9. **Written by the people who did the port.** The ground truth, the test
   bed, and the scorer were all written on this side of the comparison. The
   scorer's CWE families and ±5-line slack were chosen before the runs, and
   both scanners are scored by the identical code path, but a reader should
   weight self-reported benchmarks accordingly. Everything needed to
   re-derive these numbers independently is listed below.

---

## Reproducing these numbers

Both workflows live in the demo repository, take one target per run, upload
their full output as an artifact, and print the score table into the run
summary.

**Rust port:**

```sh
gh workflow run bc-sast-polyglot.yml -f app=java-spring
```

Inputs: `app` (one of the eight), `max_tokens` (default `1500000`), `top`
(default `2`), `scanner_ref`. Builds the scanner image from source at
`scanner_ref`, deletes the source before scanning, scans `polyglot/<app>`,
scores it, and uploads `bc-sast-polyglot-<app>`.

**Python harness:**

```sh
gh workflow run vvah-python-baseline.yml -f target=java-spring
```

Inputs: `target` (the eight apps plus `flask` and `juice-shop`), `model`
(default `gpt-6-luna`, matching the bc-sast workflow), `max_output_tokens`
(default `64000`, matching what this port gives every step -- lower it to
`16000` for `gpt-4o`, which rejects any completion cap above 16384),
`vvah_ref` (default `v1.5.0`), `remediate`, `top`,
`scan_timeout_minutes`. Installs the harness from source at `vvah_ref`, runs
it with the verbatim `default.yaml` plus the overlay, converts its
Markdown+SARIF output into the scorer's shape, scores it, and uploads
`vvah-python-<target>`.

**Comparing two runs:**

```sh
gh run download <rust-run-id>   -n bc-sast-polyglot-java-spring
gh run download <python-run-id> -n vvah-python-java-spring
diff <(grep -A6 '^Totals' bc-sast-polyglot-java-spring/score.txt) \
     <(grep -A6 '^Totals' vvah-python-java-spring/score.txt)
```

The `Totals` block is the head-to-head number. The per-item tables above it
show *which* seeded vulnerability each scanner missed, which is usually the
more useful read.

**Scoring by hand:**

```sh
python3 polyglot/score.py <findings.json> <ground-truth.json>
```

---

## See also

- [`diagrams/README.md`](diagrams/README.md): the diagram index.
- [`diagrams/pipeline.md`](diagrams/pipeline.md): the S0-S11 pipeline.
- [`diagrams/seed-plane.md`](diagrams/seed-plane.md): what the seed plane
  computes, and what the 3.1x Juice Shop speedup comes from.
- [`diagrams/finding-lifecycle.md`](diagrams/finding-lifecycle.md): where
  the precision difference is made.
