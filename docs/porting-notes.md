# Porting notes

Where this port's behavior diverges from the Python original, and what
was deliberately not carried over. Verified against the code rather
than against the original's documentation.

Split out of [comparison.md](comparison.md), which measures which
scanner finds more bugs. This answers a different question -- why the
port diverged -- and contains no measurement.

## Behavioral differences, verified against the code

Every row below was checked against both codebases before publication.
Where the convenient version of a claim turned out to be too strong, the
weaker true version is what appears here. Four of these seven needed
correcting, and the corrections are called out in place.

| | Python VVAH | Rust `bc-sast` |
|---|---|---|
| **HTTP 429** | classified by status code alone and retried on a fixed ladder; no `Retry-After` handling anywhere. Only the Claude-CLI backend detects a hard cap, and only for its own call | body classified: quota exhaustion is a distinct non-retryable error that trips a **scan-wide** gate; `Retry-After` honored as a floor |
| **Determinism knobs** | no `--seed`, no token budget, no wall-clock cap; model and temperature config-file only | all five on the CLI |
| **Outputs** | Markdown + SARIF only, into a hardcoded directory. **SARIF is regex-parsed back out of the Markdown.** No fingerprints | Markdown + SARIF + CSV by default, findings JSON opt-in. SARIF built from typed data, with v1 and v2 fingerprints |
| **`gpt-4o` out of the box** | ships `max_tokens: 64000`; the model rejects it and the error is unrecoverable, so a stock run finds **nothing** | same defaults, but the limit is parsed out of the provider's own error text and retried |
| **Output ordering** | S6 emits in completion order and never reorders; S7 keeps the lowest index, so **network timing chose the survivor** | S6 emits in input order; S7 applies a nine-key content sort |
| **Dedup key** | same file **and** same class required; CWE can only veto | flow identity, or sink identity under an equal CWE, or line proximity; plus a same-range different-CWE merge |
| **Step-0 rules fallback** | **inert** (its rule files ship in neither the repo nor the wheel) | corpus embedded in the binary: 21 source rules, 87 sink rules |

### 1. What happens on an HTTP 429

**Python** classifies a 429 by status code alone, without looking at the
body: `_RETRYABLE_STATUS = {429, 500, 502, 503, 504, 529}`. It retries on a
fixed ladder (60 s twice on the single-shot path, 10/20/30/40 s on the
agentic path), and there is **no `Retry-After` handling anywhere** in the
package.

One correction to the simple story: Python's Claude-CLI subprocess backend
*does* recognize a hard cap, matching `hit your (usage )?limit.*resets` and
returning immediately. But that is the Claude subscription-window message,
not an API billing 429 (`insufficient_quota`, "credit balance is too low"),
and it aborts only that one call. There is no scan-wide gate, so every
other in-flight and queued session rediscovers the wall independently.

**The Rust port** reads the body. `QuotaExhausted` (matching
`insufficient_quota`, `credit_balance_exhausted`, `spend_limit_exceeded`,
`usage_limit_exceeded`, "exceeded your current quota", "billing hard limit")
is a distinct, deliberately non-retryable error, and hitting it **trips a
scan-wide budget gate** from inside S4 or S6 so queued work skips its own
calls instead of rediscovering the failure. `Retry-After` is honored as a
*floor* rather than a schedule.

The port carries the reason in a code comment: without the shared gate, each
of S6's ~250 verification sessions had to rediscover quota exhaustion
independently, and retry it six times apiece first.

### 2. Determinism and budget knobs

| | Python | Rust |
|---|---|---|
| `--seed` | none (the harness never sends a seed) | yes, on the OpenAI dialect |
| token budget | none | `--max-tokens` |
| wall-clock cap | none | `--max-scan-seconds` |
| model, temperature | **config file only** | `--model`, `--temperature`, `--top_p`, `--step-timeout` |
| output paths | hardcoded `<repo>/security-scan/`, no `--out-*` flags | same `<repo>/security-scan/` default, movable with `--out-dir` or per format with `--out-md`, `--out-sarif`, `--out-csv`, `--out-findings-json`; plus opt-in `--out-remediation-json` |

Python's complete `scan` flag list is `--repo`/`--repo-file`, `--config`,
`--repo-name`, `--application-id`, `--workspace`, `--keep-clones`,
`--group-by-app`, `--resume`, `--stop-after`, `--remediate`, `--top`,
`--force`, `--skip-preflight`, `--step1-config`, and
`--auto-step1`/`--no-auto-step1`. That is the whole surface.

### 3. What each one writes

**Python** emits Markdown and SARIF only, and **the SARIF is regex-parsed
out of the rendered Markdown**: step 9 hands `md_to_sarif` the on-disk `.md`
path, which reopens it and rebuilds `Finding` objects from the text with
header/location/CWE/CVSS regexes. The typed objects that produced the report
are discarded and reconstructed from their own rendering. No findings JSON,
no CSV.

Two corrections worth making, because the uncharitable version is wrong:

- **Python's SARIF is not location-poor.** It emits `relatedLocations` from
  dedup-collapsed call sites, a CWE taxonomy in `taxa`, `rank`,
  `security-severity`, and CVSS properties. What it lacks is
  `partialFingerprints`: it has none, which is why nothing downstream can
  match an alert across runs.
- **`source_ref` and `sink_ref` exist in Python.** They are fields on its
  internal `Finding` model. They are rendered only into the S8 chain
  prompt, never into the Markdown, and therefore never into the SARIF
  parsed from it. The correct phrasing is *carried internally but never
  emitted*, not *absent*.

**The Rust port** writes Markdown, SARIF and CSV by default and findings
JSON on request. Its SARIF is built directly from the typed `FinalReport`
and carries `partialFingerprints` under both `bc/findingId/v1` and
`bc/findingId/v2`. Note the symmetry with the correction above: only the
findings JSON carries `source_ref`/`sink_ref`, and the Rust Markdown and
CSV do not either.

### 4. Talking to `gpt-4o` at all

**Python** ships `max_tokens: 64000` per step in its built-in defaults and
in every shipped profile, an Anthropic-shaped number. `gpt-4o` accepts at
most 16384 completion tokens, and the harness forwards the value straight
through. Its `BadRequestError` handler covers exactly three recoveries: drop
`temperature`, swap `max_completion_tokens` for `max_tokens`, and swap back.
A `"max_tokens is too large: 64000"` body matches none of them, so it
raises, and **a stock run against `gpt-4o` produces zero findings**. Getting
the baseline in this document to run at all required a hand-built config
overlay.

**The Rust port** kept the same 64000 defaults, and clamps at the client.
On a 400 it parses the limit out of the provider's own error text (the
integer after `"supports at most "`) and retries with it, rather than
hardcoding a per-model table. The `64000` to `16384` case is a regression
test.

### 5. Output ordering

**Python's S6** drains a thread pool with `as_completed` and appends each
result as it lands, with no reassembly afterwards. S7 then keeps the
**lowest-index** member of each duplicate cluster, so network timing
decided which duplicate survived, and with it the file, line range, snippet,
CVSS vector and SARIF rule id that got reported.

One correction: **Python's S4 does reassemble in chunk order**. The code
even says "reassemble in risk-rank order so downstream ordering is stable".
The nondeterminism is specific to S6, and the claim should not be made about
Python generally.

**The Rust port** writes S6 results into indexed slots and drains them in
input order, then applies a nine-key content sort in S7.

### 6. What dedup keys on

**Python** requires the same `file` **and** the same `vuln_class`. CWE can
only *veto* a merge, never justify one. `source_ref`/`sink_ref` are
snapshotted into the duplicate record but never consulted as a key.

One correction: **`vuln_class` is not free text.** It is a closed
twelve-value enum, and anything off-list is coerced to `other` before
validation. It is still a per-chunk model choice that moves for the same
bug (which is the substance of the point), but calling it free-text is
factually wrong.

**The Rust port** has three tiers: flow identity (normalized `source_ref`
*and* `sink_ref` both equal; the anchor file need not match at all), sink
identity under an explicit equal CWE, and same-file line proximity. An
equal explicit CWE is **sufficient on its own**, where Python required class
equality. A second pass merges findings on an *exactly* equal line range
filed under *different* CWEs, which has no Python equivalent and is worth
20-23 collapsed duplicates per Juice Shop run.

### 7. The step-0 rules fallback is inert in the shipped package

**Python's** default profile runs step 0 in `llm` mode, which falls back to
`rules` on three conditions: no observed calls, zero specs detected, or an
exception. Rules mode then resolves its rule files to
`rules/sources.generated.yaml` and `rules/sinks.generated.yaml`.

**Neither file ships**, not in the repository, not in the wheel. They are
built from external Semgrep and CodeQL corpora by a separate tool the
operator must run. And the config override that would point elsewhere
defaults to an empty string, which is falsy, so it falls through to the
missing paths. The result is a guaranteed empty seed, and the code prints
exactly that.

This is known rather than accidental: the module docstring says so, and
`pyproject.toml` lists both files in its package-data allowlist: packaging
prepared for files that do not exist. The practical consequence is that if
the LLM pass fails mid-run, step 0 returns **nothing** rather than a
rules-based seed.

**The Rust port** embeds the corpus in the binary (21 source rules and 87
sink rules), so `step0.enabled: true` produces real rule content out of the
box.

### 8. What Ctrl-C does

**Python** has real cooperative cancellation inside S4 and S6: an abort
flag plus a hard kill of every live verifier subprocess tree, because
`KeyboardInterrupt` only fires on the main thread while worker threads
keep dequeuing tasks. The interrupt then propagates: the run ends and no
report is written.

**The Rust port** stops the way a budget stops (`bc_pipeline_core::
CancelToken`, `crates/bc-cli/src/cancel.rs`). The first Ctrl-C trips a
run-wide token every stage gate consults: S4 and S6 start no new chunk or
session, the calls in flight finish, every stage not yet started is
recorded as skipped, S8 builds the report without a model call, and the
partial report, SARIF, CSV and run manifest are still written, marked
`CANCELED` in Scan Health and `"canceled": true` in the manifest.
Nothing is published, posted or remediated from a canceled run. Mid-S10,
the running agent's next model call is refused (its own error path rolls
the partial patch back) and the `verify_command` is killed as a whole
process group. A second Ctrl-C exits at once. Both exit with code 130.
The port differs from Python in writing the partial report at all, and in
not killing an in-flight model call on the first press: there is no
subprocess to kill, only an HTTP request that is left to finish or time
out.

---

## Deliberately not ported

Four Python features were left out on purpose. Each is a decision, not an
omission, and each is recorded as such in the code.

**The Claude Code CLI subprocess backend.** Worth stating clearly: this is
Python's *default* backend, not one option among several: a bare model
string resolves to `via: "cli"`, and every detection role in the shipped
profile uses it. The Rust port has only HTTP dialects (`--dialect
openai|anthropic`), so every call goes through the same gateway-mediated
client. This is also why the baseline runs in this document needed a config
overlay at all: without repointing the roles, the two scanners would have
been compared on two different models. The one piece kept is a
`GuardrailBlocked` error variant, as the gateway-mediated equivalent.

**`max_budget_usd`.** Python enforces this on its Claude-CLI and agent-SDK
backends. On its API backends it is accepted and ignored: the source
comment says `# accepted for parity; unused`. Neither enforcing backend is
ported, so there is nothing here for the key to reach and the Rust port no
longer ships it as a default at all: it is gone from
`bc_config::step_defaults()`, and a config that still sets it loads and
prints a warning naming the caps that are real. The accurate phrasing
is **removed**, not "carried but dead". `--max-tokens` and
`--max-scan-seconds` are the functional replacement, and unlike a USD figure
they are enforceable without a price table.

**`--group-by-app`.** Python's version stages every repository sharing an
application id into one directory and scans the combined tree as a single
repo, so cross-repo call-graph edges become visible. That is a change to
*scan scope*, not a reporting convenience. Approximating it by grouping
separate per-repo reports afterwards would silently misrepresent what the
flag does, so it is left unimplemented rather than faked.

**`scan_progress.style: llm_debug`.** Python's progress tracker
(`util/scan_progress.py`) has a style that prints every model call's full
system and user prompt to stderr. The other four styles are ported
(`--progress-style`, `crates/bc-cli/src/progress_lines.rs`); this one is
not, because prompts carry the target's source code, and a debug switch
that copies source into a CI log is how source ends up in a CI log.

---
