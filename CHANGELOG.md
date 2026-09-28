# Changelog

All notable changes to this project are recorded here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-09-28

This release brings the port up to vvaharness v1.3.0 and v1.4.0, apart
from v1.4.0's exploit verification. That feature sends live attack
traffic at a running API, which is dynamic testing and out of scope for a
static analysis tool, so it is deliberately not ported. The release also
adds an OpenAI Responses API transport, request-side prompt caching for
both dialects, a per-model capability table, an API specification step in
target testing, and cooperative Ctrl-C cancellation.

Most of this was tested offline against mocked providers. What has since
been checked against the real thing is named below; the checks that still
need a live provider are called out on the capabilities they affect.

### Behavior changes to know about before upgrading

- **The default model is `gpt-5.6-luna`**, a reasoning model, and the
  default OpenAI transport is `--openai-api auto`, which sends reasoning
  models to the Responses API. Pass `--model gpt-4o --openai-api chat`
  for the old behavior. On reasoning models, `--temperature`, `--top-p`
  and `--seed` are dropped with a warning unless `--reasoning-effort none`
  is set, because the provider rejects them.
- **Retired models are refused before any spend.** Claude 2 and 3.x,
  `gpt-3.5*`, the original `gpt-4`, `gpt-4-turbo`, `o1-preview` and
  `o1-mini` stop the run with a suggested replacement;
  `--allow-unsupported-model` overrides it for a gateway with its own
  names. Deprecated and legacy models (including `gpt-4o`) get one
  warning each. Unknown names are allowed.
- **A remediation run can now exit non-zero.** `1` when an S10 or S11
  call failed, `3` when validation ran and nothing came out fixed, and
  `130` for a run canceled with Ctrl-C. A plain scan's exit code is
  unchanged. `--remediation-exit-code false` restores the old behavior;
  the GitHub Action only fails on these when `fail-on-remediation: "true"`.
- **Config loading is stricter.** A secret-named environment variable
  (`*TOKEN*`, `*API_KEY*`, `*SECRET*` and similar) can no longer be
  interpolated into any config key; a Python profile still carrying
  `api_key: ${...}` needs that line deleted (it was never read here).
  `config.local.yaml` is refused when it is a symlink, owned by another
  user, or group or world writable (`BC_NO_LOCAL_CONFIG=1` skips it).
- **S4 refuses a malformed findings reply** (`{}`, `{"findings": null}`,
  a misspelled key) instead of counting it as zero findings, and asks the
  model once to repair it.
- **Eleven specialist lenses run by default instead of six**:
  `injection`, `csrf`, `sensitive-data`, `hardcoded-creds` and
  `log-injection` join the six, and `deserialization` is on by default.
  Expect more S4 calls on repositories with those surfaces.
- **S11 stays on by default after `--remediate`**, which differs from
  v1.4.0, where validation is opt-in: here S11 is what rolls back a patch
  it grades Not Fixed. `--no-validate` turns it off.

### OpenAI Responses API, reasoning effort and a per-model capability table

- `--openai-api chat|responses|auto` (env `BC_OPENAI_API`, config
  `llm.openai_api`, per role `models.<role>.use_responses_api`). Requests
  send `store: false` and ask for encrypted reasoning, which is replayed
  across tool-calling turns, so reasoning models keep their reasoning with
  tools instead of running with it switched off. `auto` falls back to
  Chat Completions only when the endpoint does not serve Responses (404,
  405, 501, or a 400 naming a Responses-only parameter) and never on a
  429, 5xx or timeout, and remembers the answer per model.
- `--reasoning-effort none|minimal|low|medium|high|xhigh|max`, per role
  `models.<role>.effort`. Anthropic models get adaptive thinking with
  `output_config.effort` on 4.6 and later, and a thinking budget on older
  models; thinking blocks are kept and replayed verbatim.
- `bc_llm_client::capabilities` knows, per model family, which sampling
  parameters are accepted, the effort levels, the output token cap, the
  cache minimum, and whether forced tool choice is allowed. Requests drop
  or clamp what a model would reject before sending, and a per-model
  memory of learned rejections is the backstop for anything the table
  gets wrong. `--doctor` prints each configured model's row.

### Prompt caching on both dialects, and cost tracking that counts it

- Anthropic: breakpoints on the tool list, the system prompt, a shared
  prefix block and the conversation tail, at most four, gated on the
  model's minimum cacheable size, never on a thinking block. Config
  `llm.cache_markers`, `llm.cache_min_block_tokens`, `llm.cache_ttl`
  (`5m` or `1h`), and `--no-cache-markers`.
- OpenAI: a hashed `prompt_cache_key` per stage, and the stable prefix
  sent first so implicit prefix caching can match it. Cache writes are
  parsed as well as reads.
- S4 sends one byte-identical shared context block (application profile,
  compact threat model, entry-point inventory, trust rule) as the cached
  prefix of every chunk, and the source code as well for consecutive lens
  chunks of the same shard. The first chunk of a shard runs first so its
  siblings hit a warm cache (`step4.shard_cache_gating`).
- Cached reads and writes are priced at the right rates, including the
  1-hour Anthropic write at twice the input rate.
- `--doctor --cache-probe` makes two calls through the real client and
  reports whether caching actually works on that route. It spends tokens.

### Transport hardening

- A reply that stops at its output budget (VVAH-E005) is retried once at
  double the budget. If it is still cut off, S2, S3, S4, S7 and S8 keep
  what arrived: S4 closes the cut-off findings document back to its last
  complete finding instead of losing the reply.
- A rejected credential (VVAH-E001) or a proxy or TLS failure (VVAH-E002)
  stops the whole scan through the budget gate, as quota exhaustion
  already did, instead of failing every chunk in turn.
- Mutual TLS with `--client-cert` / `--client-key`, failing closed on a
  missing or malformed file. Anthropic OAuth tokens (`sk-ant-oat...`) are
  sent as Bearer auth. The startup probe asks for 256 tokens, not 4.

### Detection pipeline (ported from v1.3.0 and v1.4.0)

- S2 sends redacted, capped excerpts of representative config files,
  finds manifests up to three directories deep, reads everything through
  the path jail, repairs a malformed reply once, caps threats, assets and
  boundaries deterministically without dropping a boundary's only cover,
  and gives every baseline item an id and a required disposition. An
  optional read-only agentic pass is available (`step2.agentic`).
- S3 groups files by their immediate directory with a cap, emits lens
  chunks shard by shard, stops splitting taint chunks, grounds the
  strategist with a file id inventory, salvages individual chunks from an
  off-schema reply, and has a coverage backstop that keeps files the
  reachability filter would drop.
- S1's model-authored auto-exclude overlay can no longer exclude a whole
  language or the whole repository, and warns when under 10% of files
  survive. S5 exempts point-of-occurrence findings (hard-coded
  credentials, missing controls) from `require_evidence`.
- S4 votes against the runs that succeeded, skips chunks with no files,
  and leaves binary files and base64 data URIs out of prompts. S6 repairs
  an unparseable verdict once and accepts it only if it agrees with the
  first reply. S8 degrades on an empty scope and redacts before
  truncating.
- Markdown output strips bidi overrides, zero-width characters and
  Unicode line breaks from model text.
- Tree-sitter call graph fixes for Java and C# class definitions and
  constructor calls, `*.d.ts` is no longer treated as source, and the
  COBOL `COPY` pattern is anchored.

### Remediation and validation hardening

- The post-patch repository walk, the validator's scope walk and the
  `Glob` tool no longer follow symlinked directories, and every walk is
  capped, so a symlink loop cannot hang or exhaust a run.
- The validator's pattern scanner returns no matched text and has hard
  per-file, per-scan and per-match limits with a truncation summary.
- A patch that introduces a reusable workflow pinned to anything but an
  existing full commit SHA is rolled back and rejected
  (`unsafe_workflow_reference`).
- Diffs are redacted with their hunk structure intact before the
  validator sees them. Agent-supplied evidence is bounded and redacted
  before truncation. An inconclusive validation is reported as `n/a` or
  `null`, never as a score of 0.
- An ACCEPT needs a kept, non-empty Fixed or Partially Fixed diff. The
  summary counts fixed, not fixed and failed separately. S10 and S11
  resume checkpoints are keyed by model, so changing `--model` no longer
  reuses another model's result.
- Exported patches no longer silently drop deleted files.

### Input hardening

- `--checkmarx-xml` reports are read with the bounded `bc-xml` reader. A
  deeply nested report used to overflow the stack and abort the whole
  scan; now a report over 64 MiB, nested deeper than 32 levels, or with
  any `<!DOCTYPE` is skipped with a WARN naming the file and the limit.
  Real CxSAST exports parse to the same findings as before.
- Every vendor export file (`--checkmarx-xml`, `--snyk-json`,
  `--semgrep-json`, `--aikido-json`, `--sonatype-json`) is read with a
  256 MiB cap instead of being read whole into memory first; a larger
  file is skipped with a WARN and recorded as unreadable.

### Observability

- Every stage, S0 to S11, reports an outcome (completed, completed with
  errors, cached, skipped, disabled, error), a duration and its own
  counters. `run_manifest.json` (`--out-run-manifest`) records them with
  per-stage tokens, cache reads and writes, cost, the models and
  transports used, input file hashes and a scrubbed command line.
- Plain-text progress lines for CI logs: `--progress-style
  compact|verbose|summary_only|stage_only`, `scan_progress.*`, or
  `BC_SCAN_PROGRESS_ENABLED`. `--s6-progress-file` writes S6 counters
  atomically as verification runs.
- A Pipeline Diagnostics report section appears when something
  noteworthy happened: repairs, truncations, forced coverage, vetoed
  auto-excludes, capped threats, shard gating waits.
- Resume is chained: S5 is reused only when S4 was, S6 only when S5 was,
  and S7 only when S6 was. A resumed S4 still reports its failed chunks.
- The `--log-file` output is redacted, and the local overlay is announced
  once with every key it overrode (secrets shown only as set or unset).

### API specification step in target testing

New, not a port. With `--target-tests integration` or above and an HTTP
API in the repository, `--api-spec auto` (the default) makes sure the
repository has a correct OpenAPI or Swagger document: it creates one at
the framework's conventional location when there is none, repairs an
existing one with a minimal edit that keeps its version and format, and
moves a misplaced one (updating references in docs and config) when that
is unambiguous. Every route it documents cites its handler, a
deterministic validator checks the document, and an independent reviewer
must accept it before anything is written. It is static: nothing is sent
to a running application.

The step covers the other API description standards too. GraphQL SDL,
AsyncAPI 2.x and 3.x, and OpenRPC 1.x documents are created, repaired
and (for GraphQL under Spring for GraphQL, DGS or Lighthouse) relocated
the same way, with their own parsers, validators and inventories (root
fields, send and receive operations on channels, JSON-RPC methods).
Protocol Buffers, RAML and API Blueprint documents are checked and
reported, never rewritten: `.proto` files are compared with the gRPC
services the code registers, and RAML and API Blueprint outcomes note
that they could be converted to OpenAPI by hand. `--api-spec-formats`
narrows the step to some standards, and the compiled profiles cap each
standard separately.

SOAP and OData complete the set. WSDL 1.1 and 2.0 documents, with XML
Schema embedded or imported from `.xsd` files in the repository, are
validated (target namespace, imports, unique names, message parts that
resolve to a declared element or type or an XML Schema built-in, port
type or interface, binding and service consistency, SOAP style and
transport, credential-free addresses), repaired with minimal edits that
keep the version, prefixes and definitions, and created as WSDL 1.1
document/literal wrapped for JAX-WS, Spring-WS, WCF, CoreWCF, ASMX,
spyne, PHP SoapServer and Node soap services that have none (as a
reviewed snapshot where the framework generates the WSDL at run time).
OData CSDL in XML (EDMX) or JSON is validated (keys, types, navigation
targets and partners, entity sets, singletons, bindings, action and
function imports) and version 4 is repaired in place; it is never
created, because ASP.NET Core OData, SAP CAP and Olingo generate it at
run time, and a run note says so. OData 2 and 3 metadata is recognized
as legacy and only validated and reported. All XML is read with the
project's own `bc-xml` reader, which refuses any DOCTYPE and bounds its
work, and no imported schema, WSDL or referenced CSDL is ever fetched: a
remote import is recorded as unverifiable.

### Checked against the real thing

The work above was built and tested offline. These were then verified for
real, and three of them turned up bugs.

- **The parity harness tracks upstream v1.4.0**, up from v1.2.0. That
  surfaced real drift: upstream moved merge readiness out of the scoring
  package and renamed its verdict vocabulary, so the oracle died on import
  and the test failed with a broken pipe rather than a mismatch. Across all
  256 gate-status combinations the new derivation agrees with this port, so
  only the wire shape moved. The comparison now runs in upstream's value
  space, and this port keeps `UNVERIFIABLE` as the label its reports show.
- **The parity job could not fail.** It piped `cargo test` into `tee` under
  a shell without `pipefail`, so the step reported `tee`'s exit status and
  only a skip could fail the job. A genuinely failing parity test passed CI.
- **The vendored price table refreshes again**, 202 to 213 providers and
  7149 to 7745 models. The refresh script could not reach `models.dev`
  because the site answers the default Python User-Agent with 403; it now
  identifies itself. Upstream publishes `claude-opus-5-5` at the figures
  this repository had entered by hand, so the supplement that carried them
  is gone and its mechanism is kept for the next model to ship early.
- **`o3-mini` and `o4-mini` carry their published retirement date**
  (2026-10-23). Without it the startup gate warned about them indefinitely
  instead of refusing them once they are gone. Every other dated row was
  checked and already correct.
- **A liveness check in the remediation tests read `/proc`**, which macOS
  does not have, so it reported every process dead. One test failed
  deterministically there; worse, two that assert a process was killed had
  been passing without ever observing one alive. It asks `ps` now. The
  process-group kill itself was never broken.

Not yet verified, and still tracked: everything that needs a live model
gateway, including the container execution path, prompt-cache behavior on
real endpoints, and Ctrl-C against a real provider.

### Ctrl-C

The first Ctrl-C stops the scan cooperatively: nothing new starts,
remediation never begins, `verify_command` process groups are killed, and
the partial report and run manifest are written marked as canceled. The
exit code is 130. A second Ctrl-C exits at once.

## [1.0.0] - 2026-09-14

### Diff-scoped scans no longer edit or report files the pull request never touched

`--diff-scope` confines the scan to a pull request's changed files. Third
party ingestion (`--checkmarx-xml`, `--snyk-json`, `--semgrep-json`,
`--aikido-json`, `--sonatype-json`, and the live vendor API flags) joins
the pipeline after S5, past the two places that boundary was enforced: S3
trims chunks to the diff, and S4 drops a finding reported outside its
trimmed chunk. Neither can see a vendor finding. The result, observed on a
real run, was a diff-scoped pull request scan reporting, commenting on,
and **remediating** pre-existing vendor findings in untouched files. Under
branch delivery those edits were committed and pushed.

Two independent layers now close it, so a regression in either does not
reopen the hole.

**S10 refuses out-of-scope findings outright.** When diff scope is active,
remediation declines any finding whose file is not in the changed set,
before the policy gate, before the pre-agent snapshot, and before a single
token is spent. It is recorded, never silent: the remediation record
carries the policy action `out_of_diff_scope`, a reason naming the file and
the flag, and a summary reading `Out of diff scope (...)`, distinct from
the policy gate's `Denied by policy (...)`. Nothing is checkpointed, since
a refusal is not work done. The boundary lives on the S10 config that every
route into the loop has to build, so the batch `--top` walk, the `-i`
picker, `--remediate-from`, and a direct `remediate_finding` call are all
covered. `--remediate-from` previously accepted `--diff-scope` and silently
ignored it; it now resolves the diff itself, with the same credential
requirement and fail-hard-on-fetch-error posture the scan path has.

**Out-of-scope vendor findings no longer enter the findings flow.** They
are classified at the merge point and retained, not discarded: a
pre-existing vendor finding is real information, and dropping it silently
would invite the reader to take the absence as evidence that it was
resolved. Each becomes an `OUT_OF_DIFF_SCOPE` entry in the report's dropped
list, keeping its provider origins, rendered in `report.md` under
`## Dropped Findings` tagged `[OUT OF DIFF SCOPE]`, counted on its own
`Outside the PR diff` line in `## Verification`, carried in the provider
ledger with the scope reason as its limitation, and surfaced in
`report.sarif` as a run-level note. It is not a finding, so it is absent
from `## Findings`, from SARIF `results`, from `findings.json`, and
therefore from `--pr-comments`, which requires `--diff-scope` precisely
because an unanchorable comment is not worth posting.

The scan counts stop blending the two. An out-of-scope retention is counted
on that one line and in no other bucket, so it is not a false positive, not
a verifier error, and not in the verification-precision denominator: the
scan formed no verdict on it.

Provider write-back already refused a diff-scoped run wholesale
(`--provider-writeback apply` is a startup error with `--diff-scope`, and
the generated plan carries `full_scan_required` for every origin). Each
set-aside finding now also carries the scope reason as its own assessment
limitation, so the refusal holds per record as well as per run, and the
ledger still inventories what the vendor reported rather than omitting it.

Path matching is exact after normalization (leading `./` and `/` stripped,
backslashes folded) and fails closed: an unmatched vendor path is out of
scope. There is no suffix or basename matching, so a vendor finding in
`vendor/copy/src/app.py` never passes for a changed `src/app.py`. An active
diff scope with zero changed files (a rename-only pull request) scopes to
nothing rather than to everything, as everywhere else.

Behavior without `--diff-scope` is unchanged: every ingested finding is
verified, deduplicated, reported and remediated exactly as before.

### The scanner can run the target project's own tests around remediation

A remediation run used to produce a patch and a model panel's opinion of
it. Nothing consulted the project being fixed. `--target-tests <level>`
adds an opt-in workflow that inspects the target's own test suite,
proposes the coverage it is missing, has a second model review that
proposal, and, where a profile authorizes it, runs the suite before and
after the patch. These are the target's tests, in the target's language
and layout, not this scanner's Rust tests.

Preparation runs before S10 and post-patch execution after S11, against
the final combined proposal rather than any single finding's diff.
Discovery is deterministic and LLM-free: the new `bc-target-tests` crate
reads package manifests, native test layouts, framework hints,
workspaces, CI evidence, and the command each package would be tested
with. Generation is a separate agentic session with read-only tools,
given the findings S10 is about to fix; every proposed expectation must
cite an existing file, line, and exact snippet, and those citations are
checked locally. Review is a further independent session that must
accept the proposal and affirm four separate properties (its
expectations are supported, existing assertions are preserved, it
exercises real behavior, and its layout is appropriate) before a single
file is written. Both roles can be routed to their own models through
the build-time `generator_model` and `reviewer_model` settings;
otherwise both inherit the configured remediation model in independent
sessions. Accepted files, and the existing tests discovery found, are
then bound to their bytes: if remediation changes one of them, patch
export is withheld rather than an assertion quietly weakened.

`--target-tests` names a profile compiled into the binary, not a path to
a JSON file, so no repository content, model output, or runtime file can
grant itself a command or an image. It requires `--remediate`, and
conflicts with `--remediate-from`, `--diff-scope`, `--stop-after`,
`--interactive`, `--remediate-in-place`, and `--resume`, as well as
dry-run remediation and a host `verify_command`. Each of those breaks
the one property the results depend on, which is that discovery,
baseline, remediation, and post-patch execution all read the same
snapshot. A bare `--target-tests` selects `comprehensive`;
`--testing-level` is an alternate spelling.

**Nothing executes unless you ask for it by name.** The profiles this
change shipped authorize no execution at all: `discover`, `unit`,
`integration`, `comprehensive`, `e2e`, and `generate`, which are six
registered names over five policy files, since `e2e` and `comprehensive`
share one. Select any of them, or the bare flag, and you get discovery,
generation, and independent review, and nothing runs. Execution arrived
separately, in the `discovered-offline` profile described two entries
below, and has to be asked for by that name.

**A test that passes after the patch is not proof that the fix works.**
Discovery cannot supply a trustworthy security failure signature, so an
existing suite is never relabeled a security regression, and even when
the suite passes both before and after, the recorded result stays
`functional_checks_passed_security_unverified`. Individual generated
files stay `not_individually_verified`, because runner collection
reports are not parsed to prove which cases actually ran; what is
recorded is the approved command and the exit status it produced. A
security reproduction is recorded only for a command carrying a reviewed
failure signature that fails before the patch with that signature and
passes after, and no shipped profile can produce one: every discovered
suite is classified as an existing test, and a security-regression
command exists only in a literal policy an operator writes and compiles
in themselves. One further limit, described under dependency
provisioning below, means a file the patch deletes can still be present
when the post-patch suite runs.

**None of the execution path has been observed against a live Docker
engine.** The container controls, the argv catalog, and the install
commands are designed, reviewed, and unit-tested. No live target
execution, image pull, live package installation, or model-provider
request was performed. Unit coverage is not evidence that a given
ecosystem's upstream image can install and run a given target's suite.

Everything a run learned goes to `security-scan/target-tests.json`, and
a successful run annotates the Markdown and SARIF reports with the
scoped assurance status. The artifact separates the compiled policy name
and version, static discovery, generated and reviewed test artifacts,
actual execution results, baseline failures, missing security
reproduction, post-patch failures, and remaining gaps, so an operator can
tell which of those a given run does and does not have.

The same change adds delivery modes for the combined proposal.
`--remediation-delivery patch` remains the default and the existing
review-and-apply workflow is untouched. `branch` commits the combined
source and test changes in an isolated detached worktree and pushes them
to a new branch named by `--delivery-remote` and `--delivery-branch`; an
existing branch is never overwritten, executable credential helpers and
interactive prompts are disabled, and no pull request is opened. `zip`
needs no git at all: it takes an isolated source snapshot, scans and
remediates that same copy, and writes
`security-scan/remediated-source.zip` for a CI job to upload. That
snapshot path is what makes a target that is not a git checkout usable
by this workflow at all. Both explicit modes reject the same partial-run
flags target testing rejects, and neither authorizes test execution nor
changes the selected testing level. Delivery does not weaken the
remediation gates: a blocked proposal is not published as an approved
result. Live push, CI upload, and native Windows delivery remain
untested. `docs/target-testing.md`, `docs/remediation-delivery.md`, and
`docs/built-in-policies.md` have the detail.

### Test generation is chunked, so a real scan is no longer refused for being too large

Generation serialized every finding in the report into one prompt and
refused outright above 128,000 bytes. That number was a token figure
applied to a byte length, so it fired at roughly a quarter of the
ceiling it was written for. It measured the findings alone rather than
the request they were about to be embedded in, and it was scoped to the
whole report rather than to the findings the run had actually asked to
remediate. A 49-finding scan was refused after a complete run, with the
scan's model spend already paid.

Generation is now split into source-scoped batches. Findings are grouped
by the source file they are reported against, and a group is never split,
because a source file's tests belong in one destination test file.
Groups are packed in sorted path order, so a directory's files normally
share a batch as well, and each batch is one generator session that sees
only its own findings and is told which source files it owns.

The per-batch budget is derived rather than written down. Nothing in the
workspace publishes a per-model context limit, and the price table's
long-context tiers are pricing thresholds, not window sizes, so the
budget starts from an assumed 128,000-token window, the smallest the
generator role is realistically routed to. Half of it is reserved for
everything in the request that is not findings evidence: the role
instructions, the discovery inventory, the bounded existing-test
excerpts, the read and search results the generator collects across its
turn budget, and its own reply. The remaining 64,000 tokens are
estimated at four bytes per token, which is 256,000 bytes of findings
evidence per batch today. The number moves when the window or the
reserve does.

Refusals are kept where they are the honest answer, and now say which
case they are: one source file whose findings exceed a whole batch,
which no further splitting can fix; a report needing more than eight
batches, the ceiling on how many model calls one preparation will spend,
and eight batches is two megabytes of serialized findings; or two
batches proposing the same destination test file. That last one is
refused rather than merged, because the two contents were authored by
sessions that never saw each other, so concatenating them would produce
a file neither model wrote, and keeping one would silently drop coverage
the other batch reported as covered.

Independent review stays a single session over the combined proposal, so
the combined proposal is bounded by the same caps one batch already had:
24 files, 64 KB per file, 256 KB in total. Batching bounds the evidence
going in and buys no room for more reviewed output coming out. When more
than one batch ran, the reviewer is given each batch's source-file scope
rather than every batch's findings repeated, and that is recorded as a
remaining gap. A report that fits in one batch sends exactly the prompt
this feature always sent and still costs exactly one generator call.

Generation is also now given only the findings S10 will actually
remediate, which is the same `--top N` CVSS selection S10 makes.
A run asking for two fixes used to hand the generator every finding in
the scan: a bigger prompt, a bigger bill, and tests proposed for code
that run was never going to touch.

### A discovered test command can be run

Discovery already worked out how to test a target and recorded a command
suggestion for each package it found. Nothing outside that crate ever
read one. The executor, meanwhile, ran a fixed list of commands from a
build-owned policy, and every shipped policy carried an empty list. So
the tool determined the right test command, wrote it down, and never ran
it.

The new opt-in `discovered-offline` profile bridges the two, and it is
the only shipped profile that authorizes execution at all. Discovery
supplies the command; a build-owned catalog decides whether to allow it
and which image to run it in. Matching is on the full argv vector and is
case-sensitive, with no wildcard, prefix, shell-text substitution, or
additional argument permitted, so a scanned repository cannot smuggle an
argument past it by appending one. A suggestion whose working directory
or evidence file does not match its own discovered package is refused
before matching starts.

| Detected ecosystem | Pinned upstream image family | Allowed discovered command |
|---|---|---|
| Rust | `rust:1-bookworm` | `cargo test --locked --offline` |
| JavaScript/TypeScript | `node:22-bookworm-slim` | `npm run` with exactly `test`, `test:unit`, `test:integration`, or `test:e2e` |
| Python | `python:3.12-slim-bookworm` | `python -m pytest` |
| Go | `golang:1-bookworm` | The exact `go test` invocation discovery emits, including its recursive package selector |
| Java/Kotlin | `maven:3-eclipse-temurin-21` | `mvn --offline test` |
| .NET | `mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim` | `dotnet test --no-restore` |

The policy carries immutable digests, not those mutable tags, and the
executor runs with `--pull never`, so preloading each image at its exact
reference is a separate, trusted operator task. Digest pinning makes a
change to an image reviewable; it is not a vulnerability assessment of
the image. Every resolved command also passes the existing container
policy validation, at most 64 commands are authorized across the whole
target, and resolution happens once before any model edits source, so
later target changes cannot expand the approved set. The resolved list is
recorded in `resolved_execution_policies` in the artifact.

Refusals are recorded rather than dropped, and every one of them blocks
verified export even when other packages pass. An unmatched suggestion is
named with its manifest and argv. A recognized package with no suggestion
names its package and ecosystem. An ecosystem absent from the catalog is
refused explicitly, and a target where no package ecosystem is recognized
at all is refused with its inspected-entry counts and whatever test and
project evidence discovery did find. Discovery does not currently suggest
Gradle, tox, or nox commands, and pnpm, Yarn, and Bun packages are
refused by this profile because the Node image provides npm only.

These are base toolchain images, not universal application test images.
The Python image contains no pytest and the Node image contains no Jest,
and neither carries the target's own dependencies. That is what the next
entry exists to fix.

### A target's dependencies are installed before its tests run, and an environment failure stops looking like a test failure

`discovered-offline` could authorize a target's test command and then run
it in an image carrying a toolchain and nothing else. With no network and
nothing installed, `npm run test` without `node_modules`, pytest with
nothing importable, and `mvn --offline test` against an empty local
repository all fail. That is most real codebases.

Worse, they failed as tests. The executor read exit 1 as `Failed`, and
the classifier reads pass-versus-not-pass to decide whether a fix is safe
to export, so an absent dependency tree could withhold a good fix while
looking exactly like a genuine regression. An absent signal was being
rendered as a confident one.

Provisioning is now its own phase with its own container invocation, run
once per package before any baseline. That container is the only one in
the whole run with a network. Every test phase keeps Docker's
`--network none`, along with a read-only container root, an unprivileged
UID, dropped capabilities, `no-new-privileges`, a cleared host
environment, and an empty private `DOCKER_CONFIG`. Nothing about the
test phases was relaxed to make provisioning possible: an install and a
test command are different command kinds, and only the build-owned
install kind selects the networked invocation. A test command that looks
like a dependency install is refused outright.

**Install-time script execution can be disabled for some ecosystems and
not others, and the run says which.**

| Detected ecosystem | Pin the build requires | Provisioning command | Install-time scripts |
|---|---|---|---|
| Rust | `Cargo.lock` | `cargo fetch --locked` | No control. Build scripts do not run during a fetch, but they do run later during `cargo test`, as they would anywhere. |
| JavaScript/TypeScript | `package-lock.json` or `npm-shrinkwrap.json` | `npm ci --ignore-scripts --no-audit --no-fund` | Disabled. `--ignore-scripts` stops `preinstall`, `install`, and `postinstall` hooks. |
| Python | `requirements.txt` | `pip install --user --no-input --no-cache-dir --only-binary :all: -r requirements.txt` | Disabled in effect. Wheels only, so no `setup.py` runs during the install. A project with only source distributions fails the install instead. |
| Go | `go.mod` | `go mod download` | None to disable. Downloading a module does not execute it. |
| Java/Kotlin | `pom.xml` | `mvn -B dependency:go-offline` | No control. Maven can execute plugin code during resolution and offers no equivalent flag. |
| .NET | `packages.lock.json` | `dotnet restore --locked-mode` | No control. Restore evaluates the project's own MSBuild logic and any `.props` or `.targets` a restored package brings. |

Each command is the ecosystem's lockfile-respecting form, not its
resolving one, so the versions installed are the ones the target
committed. `npm ci` fails outright without a lockfile rather than writing
one, `cargo fetch --locked` refuses a stale or absent `Cargo.lock`, and
`dotnet restore --locked-mode` fails if a restore would change
`packages.lock.json`. A package carrying none of the pins its ecosystem
accepts is refused before its tests are considered, and the refusal names
both the pins accepted and the pins found. There is no
resolve-from-the-internet fallback. Two of the six are pinned by
something that is not a lockfile: Maven has no lockfile at all, so a
POM's own exact versions are the only pin it has and a POM written with
version ranges is not reproducible, and Go is pinned by its `go.mod`
manifest rather than by the `go.sum` discovery also records.

**Python authorizes `requirements.txt` and nothing else.** A
`poetry.lock`, `uv.lock`, or `Pipfile.lock` is detected and recorded as
discovered evidence, and then refused, because installing from one needs
a tool the vetted image does not carry. A `requirements.txt` is also only
as pinned as the project made it; hashes are not required, because
requiring them would refuse nearly every real requirements file.

Provisioning is per package, and a package is a manifest with a pin
beside it. That is a real limit for workspace layouts that keep one
lockfile at the repository root: an npm workspace member with no
`package-lock.json` of its own is refused, even though the root package
it belongs to may install and test fine. Workspace-aware installs are not
implemented, and assuming an ancestor lockfile covers a member is exactly
the kind of guess this profile refuses to make.

`ExecutionState` gains `EnvironmentFailed`, for an install that exits
nonzero and for any test phase refused because its dependencies were
never installed. A failed install blocks its suites with the install
command and its outcome named in the result, so nothing runs to produce a
confusing failure, and the classifier judges provisioning separately and
never reports an unprepared environment as a baseline or post-patch test
result. The artifact carries `environment_blocked` alongside
`export_blocked`, repeated in the Markdown and SARIF annotations, so an
unusable environment is visible without reading every result. An
environment failure still withholds export: being unable to run the tests
is not permission to skip them, it is a different and honestly labeled
reason to stop.

The install container keeps every control the test containers have, and
its one writable mount is not a path from the host project: a private
per-run dependency store in a fresh temporary directory, removed when the
run ends. Every later phase mounts that store read-only and copies what
it needs into its own throwaway working copy, so target code can never
modify what a later phase reads. The install gets 1,200 seconds rather
than the 600 a test command gets, because a cold dependency tree takes
longer to fetch than the suite it enables takes to run, and the memory
and temporary-filesystem limits rise from 2 GB and 512 MB to 4 GB each,
because that filesystem now holds the installed tree as well as the
working copy.

One consequence deserves stating plainly. Each phase copies the current
source over the store's older copy rather than into an empty directory,
so a file the patch changed is the patched one, while **a file the patch
deletes can still be present in the working copy**. A post-patch run that
passes is therefore not yet proof on that specific point.

### An unreadable repository is no longer reported as a dirty one

The clean-tree precondition that target testing and branch delivery share
shells out to `git status --porcelain`, and it treated a non-zero exit
and a non-empty output as the same failure. They are opposite problems. A
non-empty output means the tree carries uncommitted changes. A non-zero
exit means git would not read the repository at all, most often because
the scanner runs as a different uid than the checkout's owner and git
refuses the path for dubious ownership. Reporting that as a dirty tree
sends an operator looking for uncommitted changes that do not exist.

It cost two failed runs to diagnose in our own demo workflow, which is
exactly where a user would meet it, since the container runs as uid 65532
against a runner-owned checkout.

The two cases now report separately. The unreadable case names the path,
quotes git's own stderr, and gives the remedy, which is to mark the path
safe, written out in the `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_0`, and
`GIT_CONFIG_VALUE_0` form so it can be pasted into a container
environment. The dirty-tree message is unchanged.

### Logs stream to the console when nothing is redrawing on it

A scan in GitHub Actions used to show nothing at all until it finished
and somebody downloaded an artifact. Logs were installed only by
`--log-file`, and without that flag no subscriber existed, so every
`tracing` call site short-circuited to nothing. For a twenty-minute run
that made the tool a black box, and the one line most worth seeing was
the transient-retry warning: a 2026-09 run spent eighty minutes retrying
a provider error in complete silence.

The reason for file-only logging was real. Two pieces of UI redraw in
place while a scan runs, and both write to **stderr**: the progress bar
and the `--interactive` picker. A log line arriving mid-frame corrupts
the display.

Neither can redraw when stderr is not a terminal. The progress bar hides
itself outright and the picker falls back to a numbered prompt that only
appends lines. So `stderr().is_terminal()` is the whole discriminator,
and it is the same `std::io::IsTerminal` check those two already make.
Nothing reads `CI` or `GITHUB_ACTIONS`.

- **No `--log-file`, stderr is not a terminal**: logs now stream to
  stderr. This is the CI case and the only changed behavior.
- **No `--log-file`, stderr is a terminal**: still silent.
- **`--log-file` given**: still the file and nothing else, either way.
- **New `--log-stderr`**: streams to stderr on a real terminal too, and
  streams alongside `--log-file` when both are given. Both destinations
  at once are supported rather than refused; one formatted line is teed
  to each.

`WARN` stays the default level for every destination. Every
`tracing::warn!` in this codebase marks an exceptional path, so a healthy
scan prints nothing and a stuck one prints the line that explains itself.
`-v` (`INFO`, then `DEBUG`, then `TRACE`) is no longer ignored without
`--log-file`; it now applies to whichever destinations are active, and
its help text says so. `RUST_LOG` keeps precedence over `-v` exactly as
before.

Output is plain text with a timestamp and no ANSI color on both
destinations. GitHub Actions adds its own timestamp column when it
renders the console, but a downloaded or piped log has none, so the
subscriber keeps writing one. No `::group::` markers are emitted:
collapsing the output defeats the point of a live view.
### A scan reports what it cost

`bc-pricing` was built, tested and used by nothing. It is now wired into
the pipeline, so every run reports its own spend in dollars beside the
token counts it already reported: a `Cost (USD)` column on `report.md`'s
`### Tokens by Phase` table, a `- Cost (USD):` bullet for the run total,
`cost_usd`/`unpriced_tokens`/`unpriced_calls`/`unpriced_models` on
`ScanMetrics` and so on every serialized report, and one line on the
`bc-sast` run summary. Rates come from a committed snapshot of
[models.dev](https://models.dev), so a price change arrives as a
reviewable diff rather than as a silent change in what yesterday's scan
would have cost.

Two properties of real pricing shaped the implementation, and both are
things a simpler version would have got quietly wrong.

**Cost is accumulated per call, never per phase.** Several models charge
a higher rate above a context threshold, and a single stage's calls
routinely land on both sides of it, so a phase's summed token counts have
no single correct rate: pricing them as one notional call is wrong by the
whole tier difference, a factor of two on the Anthropic long-context tier,
not by rounding. Calls are therefore costed as they return, inside
`UsageTrackingClient`, where the individual call's context size and model
still exist, and only the resulting dollars are added up. That also keeps
memory flat: one fixed-size accumulator per phase, whether the scan makes
ten calls or ten thousand.

**A provider is required, and this scanner does not have one.** The same
model id is priced differently by different providers (775 ids in the
snapshot are published by more than one; `claude-sonnet-4-5` is 3.00 USD
per million input tokens direct from Anthropic and 3.75 through a
reseller), but what the scanner knows is a base URL and a wire dialect.
The provider is now inferred from `--gateway-base-url`'s host when that
host is a first-party API endpoint, overridden by `pricing.provider` in
`--config`, and overridden again by the new `--pricing-provider` flag.
When none of those settles it, which is what a private deployment or a
pass-through proxy gets, the run is reported as **unpriced** rather than
guessed at: the tokens are still counted, the models that could not be
priced are named, and no dollar figure is invented. A missing rate is
never rendered as `0`.

`pricing.rates` in `--config` replaces published rates with negotiated
ones, in the vendored file's own JSON shape, which is the case a public
catalog gets most wrong. A `rates` block the price table cannot parse is
refused as a whole with a `[config] WARN`, rather than half-applied: a
typo must not leave an operator believing a negotiated rate reached a
report that used list prices.

Remediation and fix validation are not included, matching their existing
absence from `tokens_by_phase`; the figure covers the S0-S8 scan.
`USER_GUIDE.md` §10 and `outputs.md` have the details.

### The runtime image is Wolfi, and four features stop being inert

The published image ran on `gcr.io/distroless/cc-debian12:nonroot`, which
ships no shell and no `git`. Four things that are already implemented did
nothing there, and the first of them is a safety feature:

- **`step_remediate.verify_command` can run.** The gate shells out to the
  operator's build or test command before accepting an agent's fix. With
  no shell it could only fail closed, rolling every patch back and
  downgrading every finding to `Needs Review`, so it was a control nobody
  could actually turn on in the deployment it was written for.
- **The git revert backstop in S10 works.** It restores through
  `git checkout` and is the fallback for a `--resume`d record that
  carries no in-memory baseline.
- **`--git-sha` is recommended rather than required.** `head_sha` can
  shell out to `git rev-parse HEAD` again. Passing the sha the workflow
  checked out is still the better input, because a shallow or detached
  checkout can leave `git rev-parse` disagreeing with it.
- **`--remediate` can get worktree isolation in the container.** Every
  containerized run previously degraded to editing the checkout in place.
- **`--repo-file` entries that are git URLs can be cloned.** Batch mode
  shells out to `git clone`, which was simply unavailable before.

**One caveat that decides whether any of this fires in CI.** A
bind-mounted checkout keeps the runner's ownership, and git 2.35 and
later refuse a repository owned by another user
(`fatal: detected dubious ownership`). Every probe above then answers
"no git" and the run degrades exactly as it did before, so nothing
breaks, but nothing improves either. Fix it by giving the checkout to uid
65532 (`chown -R 65532:65532 .`) or by setting `safe.directory` for that
one path through `GIT_CONFIG_COUNT`. The image deliberately does not ship
a global `safe.directory=*`: disabling an ownership check for every
repository by default is not a decision to make on an operator's behalf.
`docs/deployment.md` has both recipes.

- **The GitHub Action applies the fix itself.** `action.yml` is a docker
  action, so it has nowhere to run a shell step before its entrypoint and
  its nonroot container cannot `chown` its own mount. It now sets
  `GIT_CONFIG_COUNT` and two `safe.directory` entries in `runs.env`,
  marking the workspace it mounts, and nothing else, safe for that one
  container. Git counts its environment-variable config scope as
  protected configuration, which is why this works where a repository's
  own `.git/config` could not grant itself the same thing. The two
  entries are the same directory written both ways, as
  `${{ github.workspace }}` and as the literal `/github/workspace`: the
  runner does rewrite host paths inside `runs.env`
  (`ContainerActionHandler.cs:255-258` calls `TranslateToContainerPath`
  on every environment value), but that is an undocumented internal, and
  the same file does **not** apply it to `runs.args`, so the two halves
  of `action.yml` do not resolve that expression alike. Consumers of the
  action no longer need the `chown` step for git's sake; a plain
  `docker run` still does.
- **`--doctor` stops the degradation being silent.** Its `git` check used
  to answer "found on PATH" and nothing more, which is true and useless
  on a checkout git will refuse to open. It now probes the scan target
  too, and reports one of three things: the target is a usable worktree,
  the target is not a git worktree at all (fine, and `--git-sha` becomes
  the only source for `report.git_sha`), or git refuses it for dubious
  ownership, in which case the check warns and prints the remedy with the
  path already filled in.

**What it costs.** About 33MB (135MB against 102MB), and the image now
contains `sh`, `apk` and `git` where it previously contained none of
them. The security claim changes in wording rather than in substance: it
was "no shell exists", and it becomes "a shell exists and the agent
cannot reach it". The remediation agent's tool allowlist is Read, Glob,
Grep, Edit and Write, with no shell tool and no tool that spawns a
process; the only string that reaches `sh -c` is
`step_remediate.verify_command`, which comes from operator config, has no
default, and spawns nothing when unset. What genuinely increases is how
convenient the container is to an attacker who has already achieved code
execution in it by some other route. `docs/compliance/CONTROL_MAPPING.md`
§6 and `docs/compliance/THREAT_MODEL_ATLAS.md` restate their claims
accordingly.

**The verify gate only helps a project whose toolchain is in the image**,
and this image ships no compilers, test runners or language package
managers. The intended pattern is a thin `FROM` on top of it that adds
what your `verify_command` needs; Wolfi's `apk` repositories make that a
two-line change. `docs/deployment.md` and `docs/remediation.md` carry the
example.

Both build stages are now pinned by digest. The builder stays on
`rust:1-slim-bookworm`: its glibc is older than Wolfi's, and glibc is
backward compatible, so the binary it produces runs on both families.

- **The no-shell verify-gate message no longer names distroless.** It used
  to end with "(the packaged distroless runtime image ships none)", which
  is wrong for the packaged image now. It reads
  `verify_command could not run: no shell. 'sh' is not present on this
  system, so the operator's build or test command could not be started.`
  and stays accurate for anyone running the binary somewhere that
  genuinely has no shell.

### Pull request comments are opt-in, and scoped to the pull request

A live run posted 82 comments on a five-file pull request: 6 useful inline
ones on the changed files, and 76 conversation comments about the rest of
the repository, 35 of them fix suggestions whose lines were not in the
diff and so carried no commit button. The scanner did what it was
configured to do. The configuration was the problem.

- **New `--pr-comments` flag, default off.** Posting used to happen
  whenever `--github-token`, `--github-repo` and `--pr-number` were all
  present. Those three say which pull request a run is about, which a run
  needs to know for `--diff-scope` whether or not it may write anything
  back, so their presence is no longer read as consent to comment. With
  the credentials and without the flag, the scan runs, writes its
  Markdown/SARIF/CSV reports, and leaves the pull request alone.
- **`--pr-comments` requires `--diff-scope`, and fails at startup without
  it.** A comment only anchors to a line the pull request changed, and a
  fix suggestion is only committable inside the diff. The check runs
  before any mode dispatch, alongside `--diff-scope`'s own credential
  requirement, so the run fails in a second rather than after a full scan.
- **`--post-comments-from` and `--post-fixes-from` are unchanged**: each
  of those is already the explicit request to post, and neither runs a
  scan.

### A cross-file fix is never applied automatically

- **`step_remediate.max_files_touched` now defaults to `1`** (was `3`).
  Reaching into a second file is a design decision about how two parts of
  a system talk to each other, and that is a reviewer's judgment, not an
  agent's. The finding is still reported in full; only the automated patch
  is declined and rolled back. `--max-files-touched` still raises the cap
  for an operator who wants the wider blast radius.
- **A refused patch says so.** `report.md`'s `#### Remediation` block used
  to render `- **Patch:** no patch produced` for a rolled-back fix, which
  reads as the tool having had nothing to say. It now renders the gate's
  own reason, so a fix that was attempted and declined (over the file cap,
  breaking the parse, failing the verify command) is visibly different
  from a finding nobody tried to fix.

### Every scan writes every report

`findings.json` used to be the one artifact you had to ask for. A run
without `--out-findings-json` produced Markdown, SARIF and CSV but no
findings snapshot, so `--post-comments-from`, `--remediate-from` and a
later `--baseline` all had nothing to read unless the flag had been
remembered at scan time.

- **New `--out-dir`, default `<repo>/security-scan`.** One directory for
  `report.md`, `report.sarif`, `report.csv` and `findings.json`. It is
  created before the scan starts, so a directory that cannot be created
  (a read-only bind mount, a non-root container uid) fails the run in a
  second with an error naming the directory, rather than after a full
  run's model spend.
- **`findings.json` is written by every scan**, at `<out-dir>/
  findings.json`. Its one remaining precondition is a known git SHA,
  since the commit is half of what the export is for. `report.md`,
  `report.sarif` and `report.csv` are unchanged: their default was
  already `<repo>/security-scan/`.
- **The four `--out-*` flags now only MOVE a file.** Each overrides the
  path for its own format and leaves the other three in the out-dir;
  none of them is needed to ask for output any more. The run summary
  names every file it wrote.
- **`--out-remediation-json` stays opt-in.** It is only meaningful when
  remediation actually ran, so it is not forced.
- **Nothing changes for a mode that skips scanning.**
  `--post-comments-from`, `--post-fixes-from`, `--remediate-from`,
  `--gc`, `--doctor`, `--setup` and `--estimate` write no reports and
  create no out-dir. `--repo-file` batch mode still gives every entry its
  own `<path>/security-scan/`, and deliberately ignores a top-level
  `--out-dir` so entries cannot write over each other.

### A suggestion comment no longer repeats itself

An anchored fix-suggestion comment carried GitHub's one-click "Commit
suggestion" button and, directly beneath it, a sentence offering to do
the same thing if the reader retyped a forty-character hex id. That
sentence is gone from the suggestion comment. The fallback conversation
comment keeps it, where `/apply-fix <id>` is the only way to apply what
it shows. Both comments still carry the same hidden marker, so
`apply-fix.yml` and re-scan reconciliation are unaffected and
`/apply-fix` still works on either.

### S3 packs by code volume, not by group count

The packing pass that turns cohesion groups into deep-dive buckets emitted
at least one bucket per group and never back-filled, so the bucket count
tracked *group* count rather than code volume. A repository whose groups
are mostly small directories produced dozens of buckets filled to a small
fraction of the line cap, and every bucket costs one S4 model call per
enabled lens.

Adjacent under-filled buckets are now coalesced after the split, still
respecting the line, character, and file caps. Merging is adjacent-only on
purpose: cohesive grouping already decides which files belong together, so
folding neighbours keeps call-graph components and directory siblings in
the same bucket. Buckets are never reordered to pack tighter. The flattened
file sequence is unchanged, so the selected file set is identical either
way, and a file whose own size already exceeds the cap stays in a bucket of
its own. A merged bucket's label keeps the first group's name and records
how many more folded in, for example `cg:handlers (+7 more groups)`.

Measured on two real trees with no call graph available, so grouping falls
back to depth 2 directories:

| Target | Pass | Buckets before | Buckets after |
|---|---|---|---|
| This repository (Rust, 274 files, 48 groups) | catch-all | 73 | 50 |
| This repository (Rust, 274 files, 48 groups) | specialist | 53 | 21 |
| `visa-vulnerability-agentic-harness` (Python, 553 files, 119 groups) | catch-all | 137 | 33 |
| `visa-vulnerability-agentic-harness` (Python, 553 files, 119 groups) | specialist | 124 | 13 |

Set `step3.pack_merge_underfilled: false` to restore the previous
one-bucket-per-group packing exactly. It is the escape hatch if detection
quality regresses on a specific target, since a merged bucket puts more,
less related code in front of a single call.

### The GitHub Action manifest loads, and its paths point inside the container

`uses: BinChicken-AppSec/bc-sast@v1` did not work. Not "worked badly":
the action failed before the image was built, for every consumer, every
time. Anyone who wired this scanner in as a `uses:` step got a hard
failure and no scan, which makes this the most operator-visible item in
this release.

Two independent defects, either of which alone was fatal, both measured
on a real runner rather than reasoned about.

**An action manifest cannot use the `github` context.** Only `inputs`
exists there, and every `${{ github.* }}` expression in `action.yml`
failed the manifest to load outright with
`Unrecognized named-value: 'github'`. A probe reported five such errors,
one of them inside the `git-sha` input's `description:` string, because
the runner evaluates expressions in descriptions too.

**`runs.args` is not path-translated, though `runs.env` is.** The
runner's `ContainerActionHandler.cs` calls `TranslateToContainerPath` on
every environment value but assembles `ContainerEntryPointArgs` verbatim.
`--repo` and both `--out-*-json` paths were written as
`${{ github.workspace }}`, so had the manifest loaded, they would have
arrived as the runner's host path, which does not exist inside the
container. The probe confirmed both halves: one host path passed through
`env` arrived as `/github/workspace`, and the same path through `args`
arrived unchanged.

Both are fixed by naming the mount point directly. The runner starts the
container with `-v "<host workspace>":"/github/workspace"` and
`--workdir /github/workspace`, so that literal is what exists inside, and
the corrected manifest was verified on a real runner: it loads, and the
scanner receives `--repo /github/workspace` with both output paths under
the same mount. The `git-sha` input's description now names the context
values in prose and says to write them as expressions in the calling
workflow, which is the only place they resolve. The `safe.directory`
git-ownership entry drops from two spellings to one; it was written twice
to hedge on whether `runs.env` was translated, and that is now measured.

### `.tsx` is parsed with the TSX grammar, not TypeScript's

tree-sitter ships a separate TSX grammar because the TypeScript one reads
`<div>` as a type assertion and errors on JSX. Both grammar selection
sites picked the TypeScript grammar for every file labeled `typescript`,
so a React component in a `.tsx` file parsed with errors, and error
recovery then dropped the subtrees holding its handlers and calls.

Three things were lost, and the third is the expensive one. S0's seeds
and S1's tree-sitter call graph both missed anything declared inside a
JSX-bearing component. And S10's syntax gate parses a touched file after
the agent's edits with no before baseline to compare against, so it read
that parse error as the fix having broken the file: every remediation
touching a `.tsx` file with JSX in it was rolled back and downgraded to
`Needs Review`, whether or not the patch was any good.

The grammar is now selected by file suffix, the way the C/C++ family key
already was. `normalize_lang_for_queries` (`bc-repo-analysis`) and the new
`normalize_lang_for_grammar` (`bc-callgraph`) map the label `typescript`
plus a `.tsx` suffix onto a `tsx` grammar key that only the grammar tables
know. The language label stays `typescript` everywhere it is reported or
used for lens selection, hint lookup and rule matching; only the parser
changes. `.ts` keeps the TypeScript grammar, where an angle-bracket type
assertion is legal and JSX is not, and `.jsx` is unaffected.

What an operator notices: React TypeScript is scannable and remediable at
all.

### Corpus entry-point kinds resolve, and the taint pair filter switches on

The bundled source corpus tagged 20 of its 21 rules `http`, `stdin` or
`env`. The seed stage's own kind conversion matched canonical spellings
only, so all 20 collapsed to `EntryPointKind::Other`: S2 rendered "other"
for every Flask, Express and Spring source, and S3's `File`/`Cli`
specialist selection never fired for an environment-variable source.

The same strings feed a second, independent consumer.
`bc_callgraph::graph::source_kind_compat` keys its allowed-sink rows on
the raw source kind and had no row for `http` or `stdin`, and a spelling
with no row admits every sink kind. The taint pair filter was therefore
inert for 18 of the 21 rules rather than filtering anything.

The corpus now spells `network` and `cli`; `EntryPointKind::parse` exposes
the same alias table the JSON deserializer applies, and the seed stage
uses it, so a future corpus cannot drift the same way; and `http`, `stdin`
and `file` resolve in `source_kind_compat`.

Two traps were handled on the way, and each would otherwise have cost
findings at the moment the filter started working:

- **`crypto` had to join the pair filter's rows.** It was the one corpus
  sink kind absent from the table. Switching the filter on without it
  would have silently dropped every request-to-weak-hash pair, which the
  corpus only ever reported because `http` bypassed the table. It carries
  `semantic_family: other`, so there is no protected-family bypass to
  save it.
- **`env` was deliberately not respelled.** The entry-point model aliases
  `env` onto `file`, but the pair filter gives `env` a row of its own with
  a broader sink list than `file`: an environment variable can name an
  open-redirect target, and a file's bytes are not treated that way.
  Writing `file` in the corpus would have narrowed what
  `os.getenv`/`os.Getenv` can pair with.

Measured on a demo repository, before to after: its 43 entry points go
from 41 `Other` plus 2 `Cli` to 39 `Network`, 3 `Cli` and 1 `File`, while
its 83 taint paths and 114 evidence records are unchanged. A synthetic
fixture carrying network-to-crypto, env-to-redirect and stdin-to-command
pairs reports the same 5 paths on both sides. The accepted spellings are
now documented in `configuration.md` under `step0`.

### The S3 taint search keeps two classes of path it used to drop

`bfs_to_sinks` inherited two recall bugs from the Python original, both
fixed upstream in v1.3.0 and both reproduced here before being fixed.

**Sanitizers were universal when they should have been per weakness.** One
flat name set folded `validate`, `clean`, `sanitize`, `encode` and the
numeric coercions in with the real escaping and parameterization
primitives, and any hit neutralized the path for every sink class. A
repository function named `validate` anywhere on a path killed that path
for every weakness beyond it. The set is now split. `SANITIZER_UNIVERSAL`
(escaping and parameterization) is still decided per hop, because it
neutralizes every class. `SANITIZER_BY_CWE` is carried along the path as a
set of names and decided at sink arrival against that sink's own CWEs,
because a numeric coercion that stops a SQL-injection payload does nothing
for a command-injection payload built from the same string.
`sanitize`/`clean`/`validate` are now in neither set: there is no weakness
class for which the name alone is proof.

**A sanitized arrival buried a later clean path.** The visited set was
marked before the sink check, so the first path to reach a sink claimed
it; if that path crossed a sanitizer, a genuinely clean path to the same
sink was never reported. That is exactly the validation-bypass shape, one
sink reachable both through and around a guard, and which arrival came
first depended on callee iteration order, so the loss was
nondeterministic as well as wrong. Traversal state is now keyed on
`(node, universal_hit, class_hits)`, and a sanitized sink arrival is not
recorded as reached at all.

Measured on a real 582-file Python corpus (pip 26.1.2, pydantic 2.13.4,
PyYAML 6.0.3, typing_extensions 4.16.0) with 51 sink nodes and 1534
in-degree-zero entry proxies: 13000 taint paths before, 13784 after, so
784 more (up 6.0%) with none lost. Of that, 623 comes from the visited-set
fix and 161 from the per-weakness split. An operator sees more S4
deep-dive work, and pays for it, which is the intended direction.

One deliberate deviation from upstream: a clean sink arrival is still
expanded past. Upstream's rewrite made it terminal, which drops any sink
reachable only through another sink, a recall regression inside a recall
fix. The full rule is now written up in `architecture.md`.

### The deep-dive flags a missing authorization check it cannot verify

S4's quality bar, and the access-control specialist hint, told the
deep-dive to open the file that REGISTERS a route before reporting a
missing authorization or authentication check. It has no way to do that:
`single_run` sends `tools: Vec::new()`, so the model sees its chunk plus
caller and callee excerpts and nothing else, and for the frameworks the
rule named, the registration site is rarely a caller of the handler and so
rarely in the slice. A gate phrased as "report this only if you can show
X", where X cannot be shown, reads as near-total suppression of CWE-284,
285, 287, 306, 862 and 863 at the only stage that generates findings.

The verb is now flag, not decide. The framework guard list stays as
recognition material for the case where the registration IS in the slice.
Where it is not, the model says so in `preconditions` and reports at
`confidence` 0.6, and adjudication is left to S5's deterministic route
gates and to S6, both of which have repository access.

That 0.6 is not an arbitrary "reduced" number.
`bc_stage_s5::gates::apply_gates`
drops a finding whose confidence is strictly below `min_pre_confidence`
(default `0.6`) before `route_gates` or S6 ever run, so any lower floor
would have moved the suppression one stage downstream and made it harder
to see. A dev-dependency from `bc-stage-s4` on `bc-stage-s5` holds the
prompt's number to the gate's, so moving the gate's default now fails a
test instead of silently deleting these findings. `configuration.md` says
what raising the key yourself does.

Two smaller prompt corrections travel with it:

- **S6's `[UNAUTH-REACHABLE]` marker is earned, not assumed.**
  `auth_marker` stamped it on any entry point with `reachable_from_unauth`
  set, and the prompt tells the verifier that marker means the seed plane
  found no guard on that route. But `reachable_from_unauth` is a free
  field in S1's reply schema and only S0's framework plane sets it from
  evidence, so on any other kind that `true` was a survey model's guess
  presented as a static-analysis fact. Only a `Framework` entry point
  earns the marker now, matching what `bc_stage_s5::route_gates` already
  enforces and what `architecture.md` already describes. The block's
  closing sentence, that an entry point with neither marker settles
  nothing, covers the newly bare rows.
- **S6's prompt no longer calls the call graph SQLite-backed.** It said so
  in four places. That was true of the Python original, which read the
  graph back out of a SQLite artifact store; here the only SQLite is
  `bc_checkpoint`'s resume store, and the call graph is `bc_callgraph`'s
  tree-sitter output held in memory. The header now names what actually
  produced the edges.

### A fix score fails closed when the panel never reached consensus

The v1.2.0-faithful port kept the consensus status rule but discarded how
strongly the panel agreed on it, so a single non-abstaining persona vote
could decide a whole fix verdict: one persona's response failing to parse
left the survivor grading the fix alone, and it scored a clean `Fixed`.

Synthesis now labels every merged gate `High`, `Split` or `Flagged`, and
`score_fix` reads that label in a new consensus precheck: any `Flagged`
gate makes the whole result `Unverifiable` at raw score 0.0, with
`UNVERIFIABLE: Insufficient persona consensus for gate(s): <names>`. The
gate's own status, summary and evidence are still reported untouched; only
the aggregate verdict is withheld. A gate set that never went through
synthesis, which is what the 627-case scoring parity sweep against the
Python oracle carries, is not labeled at all and never trips the check.

**The line is drawn at a contradiction about whether the fix works, not
at any disagreement.** `High` is two or more personas independently
reporting the same non-skip status. `Split` is a two-way tie one step
apart on the severity scale, `partial` against `pass` or `fail` against
`partial`: the personas agree the change does something and differ only
on how complete it is. The conservative status stands and is scored
normally, exactly as a `High` gate is. `Flagged`, the one label that
withholds the verdict, is everything else: `pass` against `fail`, any tie
involving a garbled `invalid` report, a three-way tie, a lone non-skip
vote, and a gate every persona skipped. `validation.md` has the full
rule.

That narrowing is the correction to a rule that was failing closed on the
wrong thing. Live A/B measurement when the precheck first landed, across
the same two applications: three `Fixed` and one `Partial` with zero
`Unverifiable`, becoming zero `Fixed` and four `Unverifiable`, so roughly
four in five remediations were discarded where most had previously stayed
on disk. Tabulating all 96 synthesized gates from fourteen runs'
`remediation.json` artifacts then showed why: not one gate was flagged
for the lone-vote or all-abstained cases the rule was written for. Every
flag was a `pass`-against-`partial` split over completeness, with
summaries like "no tests to verify the fix" and "retains an unused block
of code". The scoring engine already knows how to express that: `partial`
earns half credit, and a partial critical gate is capped out of `Fixed`
regardless of the score.

**What still fails closed.** A panel that contradicts itself about
whether the fix works, one whose personas cannot agree three ways, one
where a report arrived garbled, and one where a single persona is the
only voice on a gate, which includes a persona whose reply failed to
parse twice and so contributed no report at all. `Unverifiable` and
`Not Fixed` are the two verdicts that roll a patch back
(`revert_if_validation_failed`); a `PartiallyFixed` fix, which is what a
doubted critical gate now produces, stays on disk to be reviewed.
`step_remediate.keep_unverified` still keeps everything.

S11 also logs one `[s11]` line per gate after synthesis, naming each
persona's vote, the merged status and the label, for example `root_cause:
security-architect=pass penetration-tester=partial -> partial (SPLIT)`.
The exported `confidence` alone cannot separate a lone unseconded vote
from two personas contradicting each other, since both arrive as
`FLAGGED`; establishing which was happening previously meant inferring it
statistically across a run's artifacts. A `Split` or `Flagged` gate logs
at `warn`, the default verbosity, since it is the explanation for the
score and, when flagged, for the rollback. A `High` gate logs at `info`,
so the full per-gate tabulation is what `-v` buys. Every vote line at
default verbosity therefore marks a gate the panel did not agree on, and
the volume falls as the disagreement does.

### A persona gets one vote per gate, however often it names it

`synthesize_n` folded a persona's repeated mentions of one gate with
`Iterator::find`, so every entry after the first was silently dropped.
That was a latent conservative-merge skew until the consensus precheck
above made the vote tally load-bearing. `MIN_CONSENSUS_VOTES` is 2 and the
usual panel is two personas, so the discarded half is exactly what
decides whether the survivors read as agreement: a persona reporting
`no_new_vulnerabilities` `pass` and then `fail`, alongside a second
persona's `pass`, produced a two-vote `pass` majority at `High` confidence
and scored the fix `Fixed`. Folding first makes it one `fail` against one
`pass`, which is a tie, which is `Flagged`, which the consensus precheck
fails closed. Every entry is still reported; only the tally changes.

`severity_rank` now ranks `Invalid` below `Skip` rather than tying them,
matching Python's `_STATUS_CONSERVATIVE_RANK`. The tie went unnoticed
because the panel tie-break filters abstentions out before it looks; the
per-persona fold does see a `Skip`, and has to resolve a persona's own
skip/pass pair to the `pass` it actually evaluated. No panel-level
behavior changes.

Each gate's synthesis confidence is also exported as an optional
`confidence` field (`HIGH` or `FLAGGED`) on `GateResultExport`, so an
operator triaging a withheld fix can see which gate lacked consensus
without reading the justification prose. It is absent rather than null for
an unsynthesized gate and defaulted on read, so `--post-fixes-from` still
loads a `remediation.json` written before it existed.

### A validator reply carrying no usable gates is retried once

`gates_from` ran `bc_json_repair::extract_json` over a persona's final
text and turned a failure into an empty gate list, silently. Empty is
indistinguishable from "this persona had no opinion", and since the
consensus precheck landed that costs an operator a working fix: the
surviving persona's gates carry a lone vote, every gate comes back
`Flagged`, `score_fix` returns `Unverifiable`, and `Unverifiable` is one
of the two verdicts that roll the patch back. One model
emitting bad JSON was being read as a lack of panel consensus, which is a
different thing.

`run_persona` now wraps each arm of both `tokio::join!` blocks: it runs the
persona, and if the reply yielded no gates at all it runs it once more and
takes whatever the second attempt gave. The panel stays concurrent, and
the retry of one persona never serializes or re-runs the others. "No
gates" covers both nothing-extracted and JSON that named no known gate,
since a persona reporting zero gates is useless either way when its prompt
demands a verdict on all four criteria. Exactly one retry, not a loop and
not configurable: `bc-json-repair` already repairs malformed JSON before
this point, so reaching the retry is the rare residual case, and a second
failure is far likelier to be a model that cannot answer this prompt than
a formatting slip. A persona that parses first time is still called once.

Both the retry and a retry that also failed now log at `warn` naming the
persona. That silence was the larger half of the bug: an operator could
not tell a fix discarded by panel disagreement from one discarded because
a model emitted bad JSON.

### Changed defaults

| Setting | Was | Now |
|---|---|---|
| PR comment posting | implied by `--github-token`/`--github-repo`/`--pr-number` | requires `--pr-comments`, which requires `--diff-scope` |
| `step_remediate.max_files_touched` | `3` | **`1`**, so a cross-file fix is reported but never applied |
| `findings.json` | written only with `--out-findings-json` | written by every scan, into `--out-dir` (default `<repo>/security-scan`) |

### Earlier work, from the initial port to functional completeness

Everything below landed after the initial port
reached functional completeness across all three phases (scan pipeline,
remediation, validation) and represents the work of turning that into
something that behaves correctly on real repositories rather than on test
fixtures.

Nothing here is a breaking change against a previously tagged release,
because there is no previously tagged release. Several **defaults** changed,
though. See "Changed defaults" at the end.

### Seed plane (step 0)

The deterministic, LLM-free tree-sitter stage that runs before S1 went from
a barely-reachable experiment to the foundation several later stages read.

- Ported S0's framework-route and structured-taint-evidence engine, and
  merged its taint evidence and taint paths into the context package.
- **Turned the seed plane on by default** (`step0.enabled: true`) and made
  the deterministic framework plane, not the S1 agent, the owner of
  framework entry points.
- Made the seed plane walk **step 1's scope**: the orchestrator copies
  `step1`'s walk/exclusion settings onto step 0, because S1 reuses the
  seed's file inventory. Without this a step-0 walk that ignored
  `step1.exclude_dirs` silently widened the whole scan. One live run went
  from 199 files to 744 and spent its entire budget before verification.
- Made S0 taint evidence actually work on real Python, Java and C#:
  composed string values, the sanitized call boundary, C# fluent chains,
  grounding taint through the parameter it was passed to rather than a
  positional coincidence, and keeping an ungrounded-but-reachable path.
- Answered `reachable_from_unauth` from real auth evidence rather than
  leaving it at its serde default.
- Let a script's top level be a caller, so `$_GET`-style scripts produce
  edges at all.
- Exposed S0's LLM detection mode (`callgraph_detection: llm`) and wired
  the framework-route plane through to it.

### Language and framework coverage

- **Framework routes and auth guards for PHP, Ruby, Kotlin and Rust**:
  Laravel, Symfony, Rails, Sinatra, Ktor, Spring-Kotlin, axum, actix-web,
  rocket, none of which the Python original covers at all.
- **Go, Koa, Fastify, hapi, NestJS and Next.js** wired into the route
  plane, alongside the existing Flask/Django/FastAPI/Spring/JAX-RS/ASP.NET/
  Express detectors.
- Read the route shapes real applications are actually written in: Rails'
  hash-key route binding (`get '/p' => 'c#a'`), and axum's build-in-a-local
  pattern where the guarded section is assembled behind a `let` and merged
  in later.
- **C/C++ given an extractor**, and Kotlin's request surface wired up.
- Expanded the Java extractor, resolved imported route handlers, and bound
  handler parameters as taint sources.
- Gave C#, Go, JavaScript/TypeScript, PHP, Ruby and Rust a real source/sink
  corpus, and pinned that the Java corpus answers for Kotlin too. A
  property read that is neither a callee nor an assignment target is now a
  call site in its own right, which is what makes `Request.Query` and
  `req.query` expressible.
- A language with routes but no taint corpus still surfaces its entry
  points.
- Taught S4 and S6 the C/C++, Swift and Scala security knowledge they
  lacked.

### Known-limitation fixes

Six items previously documented as limitations, closed after checking each
against the code rather than against its own description.

- **`--diff-scope` no longer widens to the whole repository when a diff
  matches nothing.** A PR of only renames, deletions, mode changes or
  binary files carries no changed lines, and the empty result was the same
  value that means "the flag was never passed". Every consumer read it as
  the latter, so the scan silently swept the entire repository at full
  spend and the report omitted its scope line. Diff scope is now carried
  as an explicit flag beside the changed-file set: an empty set with the
  flag active scopes to nothing, the run completes green, a warning names
  the likely cause, and the report prints `Scope: PR diff (0 of N files)`.
  The limitation as previously written also had its cause backwards: the
  PR diff is GitHub's merge-base comparison, so a branch that merges its
  base in narrows the diff rather than widening it.
- **Ktor findings now match their guard by handler name.** A Ktor route
  body is a lambda that calls a top-level function, and the entry point
  was named after the URL path instead, so S5's route gate could only
  reach a Ktor finding through its weakest whole-file rule. The extractor
  now reads the delegate call's name out of the lambda. Anything
  ambiguous, an inline body, several statements, or a nested lambda, keeps
  the old synthetic name. Two routes in one file resolving to the same
  delegate also keep it, because entry points deduplicate by file and
  function and fold their guard flags together, so a shared name would let
  an unguarded route inherit a guarded one's status and suppress a real
  finding.
- **Temporal C/C++ findings are re-anchored, not just told where to
  anchor.** A use-after-free reported at the `free` rather than at the
  later use lands outside the range everything downstream expects, which
  moves the SARIF v2 fingerprint, costs an inline PR comment, and can stop
  two runs' findings from merging. S4's reply schema, which ships on every
  request, now states the rule for use-after-free, double-free and TOCTOU,
  and the C hint repeats it in C's own terms. That instruction is also
  enforced rather than trusted: a deterministic pass
  (`bc-stage-s4::reanchor`) parses the file, finds the release site
  covering the reported line, walks forward for the first genuine use of
  that pointer, and rewrites the range to span both. It declines on every
  ambiguity: an unreadable file, a cast or field expression rather than a
  bare pointer, two release sites on one line, a reassignment or a null
  check before the next use, or a use the control flow cannot reach. A
  wrong anchor is worse than none, so the pass only ever narrows what it
  will act on. Findings record which line fields it rewrote, in a new
  `reanchored` key alongside `backfilled_refs`. The prompt rule still
  covers what the pass deliberately cannot: every other language, a
  release through a project's own wrapper, and the TOCTOU check-site
  shape, which has no release site to key on at all.
- **Integer-overflow allocation is expressible after all.** The corpus
  comment claimed an arithmetic predicate over an argument could not be
  written, but the format-string rules already carry the same kind of
  predicate. `malloc`, `realloc` and `alloca` are now sinks when their
  size argument is computed rather than a plain identifier, literal or
  `sizeof`. `calloc` is excluded on purpose: splitting the factors is the
  fix a reviewer recommends, so flagging it would send remediation in a
  circle.
- **C++ array-new is visible to the seed plane.** The extractor walked only
  call expressions, so `new T[n * m]` was invisible to the integer-overflow
  allocation rule. It now reads array-new's size expression as argument
  zero, which distinguishes it from `new T[n]` and from a plain
  `new T(args)`.
- **A hand-multiplied `calloc` is caught.** `calloc` stays out of the
  general rule, because splitting the factors is the fix a reviewer
  recommends. But `calloc(n * size, 1)` throws that protection away, and
  now has its own narrow rule requiring arithmetic in the first argument
  and the literal `1` in the second. Idiomatic `calloc(n, size)` and
  `calloc(len + 1, sizeof(char))` remain unflagged.

### Accuracy gates

Three classes of false positive that a model reliably produces, a human
rejects in seconds, and no prompt wording fully stops, are now settled
mechanically before a verification session is spent on them. All three are
one-directional: they only ever drop a finding whose language or framework
wiring makes it impossible, and every ambiguity keeps the finding for S6.

- **Synchronous JS/TS cannot race.** Node runs one JavaScript thread to
  completion between suspension points, so a `++` or a check-then-act with
  no `await`/`.then`/callback/timer between the halves is not a race.
- **Template auto-escaping.** An XSS finding on a default-escaped construct
  in a Handlebars/Mustache, Pug/Jade, EJS, Jinja/Twig, ERB, Razor, Blade or
  Vue template is dropped, unless a raw construct or a non-HTML context
  (`<script>`, an `on*=` handler, a `javascript:`-capable URL, a CSS value)
  is anywhere near it.
- **Framework-guarded routes.** A "missing authorization" finding on a
  handler every framework entry point reaching it says is
  `reachable_from_unauth: false` is dropped. Only S0's framework-kind entry
  points may gate a drop, since only they set that field from evidence; a
  finding claiming the guard is bypassable is never dropped, and one open
  route among the matches vetoes the drop.
- The same knowledge is in the S6 verifier prompt as a LANGUAGE FACTS
  block, which additionally covers parameterized SQL, safe Rust's memory
  guarantees, Go's real goroutine parallelism, Java atomicity, bounded vs
  unbounded C copies, and what the Python/Ruby GIL does *not* prevent. A
  route guard refutes the authorization claim and never the flaw itself.
  Injection on a guarded route is still a true positive.
- **Hallucinated-directory repair.** A path that resolves to exactly one
  inventory file at a directory boundary is rewritten rather than dropped;
  anything ambiguous is still excluded. One live scan lost five real
  findings to `src/server.ts` where the file was `server.ts`.
- Reading a query assembled into a local as the bound query it is.

### Deduplication and determinism

- **One flow reported from two ends is one finding.** Two findings sharing
  a `source_ref` *and* a `sink_ref` collapse even when their anchor files
  differ.
- **One sink under one CWE is one finding**, whichever hop reported it
  (`step7_dedup.merge_same_sink`). The model labels the "source" at
  whichever hop it is looking at, so the full `(source, sink)` pair differs
  for what is one flow with one fix site.
- **One code range seen through several CWE lenses collapses**
  (`step7_dedup.merge_same_range_cwes`), on exactly equal line ranges only.
  One live scan produced 11 findings for 3 near-identical functions this
  way, each costing its own verification call, report entry and remediation
  attempt.
- Dedup keys on the **CWE**, not on the label the model happened to pick.
- **A stable, content-derived survivor rule** for a dedup cluster:
  sink-anchored end first, then earliest position, then most severe, then
  the most specific CWE lens, then best-evidenced. Previously network
  timing decided which duplicate survived, and therefore what line,
  snippet, CVSS vector and SARIF fingerprint a run reported. A same-range
  CWE merge is now decided by the CWE itself rather than by model
  confidence, which moves between runs.
- S6 emits results in **input order**, not completion order, for the same
  reason.
- Per-role sampling, `top_p`, per-call timeouts and an explicit seed are
  sent on every LLM call; S4 votes are clustered by line tolerance and S8
  report ties ordered by position.
- A content-derived **v2 finding fingerprint** alongside v1, plus SARIF
  `baselineState`.

### Provider and quota handling

- **A provider saying the account is out of credits stops the scan.**
  OpenAI reports it as a 429 (the same status as an ordinary rate limit)
  and Anthropic as a 400; both now map to a distinct, never-retried
  `QuotaExhausted` error that trips the run's budget gate from inside the
  stage that learned it. A CI run against an empty account previously spent
  80 minutes on ~250 verification sessions × 6 retries and produced nothing
  but a timeout.
- Prose spend/usage-limit wording is recognized as quota exhaustion too.
- **The token and time budgets bite inside S4, S6 and the dedup call**, not
  only at stage boundaries. A stage boundary alone is not a budget: one
  scan given a 3M-token cap spent 4.9M because S6 started under the cap and
  then ran 1,881 sessions with nothing left to consult.
- **A budget stop leaves nothing "verified".** Candidates the verifier
  never examined are reported as unconfirmed drops with the budget reason,
  never as findings. One run rendered 160 unverified candidates as 160
  true positives at "100% precision".
- **Preflight retries a burst 429** (three attempts, 1 s then 2 s backoff)
  and blocks only on real failures; a persistent rate limit is a warning,
  since the scan's own retry loop handles it.
- Self-correction when a model rejects `max_tokens` as too large;
  opt-in streaming for large responses (`--stream-large-responses`).

### Reporting and outputs

- An **executive summary** section, with a `Not examined` line whenever a
  budget stop left candidates unverified.
- Verification precision is measured over the findings actually
  **examined**, not over every candidate: a capped scan read 33.8% by the
  old arithmetic and 74.8% by the honest one.
- A `## Scan Health` **BUDGET REACHED** line naming which budget ran out
  and how far the scan got; budget-skipped chunks recorded as `skipped`
  rather than `failed`.
- Remediation and S11 validation rendered into `report.md`, with the S11
  justification sanitized; `--remediate-from` augments the prior run's
  reports in place rather than leaving them stale.
- SARIF absent results for findings-JSON baselines too, so a resolved alert
  can be closed either way.
- Fixed two Markdown-injection vulnerabilities in report rendering.
- PR comments keyed on the code rather than on the snippet the model
  quoted, and matched by position when the content hash has moved.
- A flat CSV findings export.

### Features

- `--baseline`: classify findings as new / unchanged / resolved against a
  prior findings JSON or SARIF, with per-entry baselines in batch mode.
- `--remediate-from`: remediate a prior export without rescanning.
- `--diff-scope`: scope the scan itself to a PR's changed files, with the
  rest of the repo still available as call-graph context.
- Batch mode (`--repo-file`) with `.txt`/`.csv` manifests and remote
  git-URL cloning; `--doctor`, `--setup`, `--estimate`, and an automatic
  pre-scan preflight gate.
- Structured logging to `--log-file`, a scan-progress event stream, and a
  live terminal progress bar.
- Third-party ingestion for Checkmarx, Snyk, Semgrep, Aikido and Sonatype
  (both exported report files and live REST fetches), re-verified through
  S6 and deduplicated through S7 alongside the LLM's own findings.
- Compliance policies and presets, and a CVE-feed / design-controls
  injection plane.
- S4 function slicing (`taint_chunk_slice: function`), and S11's five
  deterministic fact tools.

### Remediation safety

- A write journal, so a rollback is byte-exact on a non-git target too.
- Syntax, diff-size, file-count, verify-command, dry-run and
  unverified-patch gates; anything that does not earn the right to stay is
  rolled back.
- **Worktree isolation by default**: for a git `--repo`, S10 runs against a
  throwaway detached checkout and the fix comes back as a patch file; the
  user's own tree is never edited unless `--remediate-in-place` says so.
- An S11-rejected fix is rolled back from its own pre-remediation baseline,
  without needing `git`; a fix the write journal says was never written is
  retried once.

### Review closure

- A 15-item gap review and every outlier it surfaced, closed the same day.
- Five config-key mappings the Python original acts on and this port
  ignored, corrected; `step_remediate.retry_unapplied_fix` read from the
  config file.
- All five third-party vendor integrations corrected against live API
  documentation: Checkmarx One's field names, triage filtering and XML
  dataflow; Aikido's nullable line numbers and open-code-issue filter;
  Snyk's relative `links.next`, real locations and array/SARIF exports;
  Sonatype's `reportDataUrl`-derived report id; Semgrep's response
  envelope and severity/CWE handling. A shared HTTP retry helper and
  chronological timestamp ordering across all five.
- Parity gaps closed: CVE/control loaders, the seed-taint merge, S11 panel
  inputs, S4 code-loading fidelity, remediation report sections.
- JSON dialects models actually emit are parsed, and the failure is
  reported when they cannot be.
- Documentation corrected where it denied the scan pipeline has
  checkpoints, claimed a cosign/SLSA publish workflow that does not exist,
  or pointed at a stale path.

### Tooling and infrastructure

- A container build (`Dockerfile`, distroless `cc-debian12:nonroot`
  runtime, `cargo-chef`-cached dependency layer) and a GitHub container
  action.
- CI: format, clippy, test, a 100%-line/function coverage gate with
  individually documented per-crate exceptions, `cargo-deny`
  (advisories/bans/licenses/sources) on every PR and weekly against an
  unchanged lockfile, and a parity job that runs the Python
  cross-validation harness against a pinned upstream commit.
- Terraform for an example private image registry with OIDC-based CI
  auth: an internal example of one half of the deployment story, not the
  deployment story itself.

### Changed defaults

Worth reading before upgrading a pinned configuration:

| Setting | Was | Now |
|---|---|---|
| `step0.enabled` | `false` | **`true`**, so the seed plane runs by default |
| step 0's walk scope | its own | copied from `step1`'s walk/exclusion settings; there is no `step0.exclude_*` config key |
| `step7_dedup.merge_same_range_cwes` | n/a | `true` |
| `step7_dedup.merge_same_sink` | n/a | `true` |
| `step_remediate.syntax_check` | n/a | `true` |
| `step_remediate.max_diff_lines` / `max_files_touched` | n/a | `200` / `3` |
| `step_remediate.retry_unapplied_fix` | n/a | `true` |
| `--remediate` target | the user's checkout | a throwaway worktree, for a git `--repo` |

### Known gaps

`max_budget_usd` is no longer shipped as a default, because in Python it
only ever reached backends this port does not have; a config that still
sets it loads and warns. The spend caps that are enforced here are
`--max-tokens` and `--max-scan-seconds`, and neither has a default value,
so an operator who never sets one runs unbounded. The re-anchor pass is
C/C++ only and keys on a `free`/`delete` at the reported line, so a
temporal finding in another language, one released through a project's own
wrapper, or a TOCTOU check site still reaches the report anchored wherever
the model put it. Deliberately unported Python features and the current
known limitations are listed in [`README.md`](README.md).
