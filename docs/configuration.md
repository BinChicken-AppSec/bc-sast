# Configuration

`bc-sast` runs entirely off command-line flags by default. `--config` layers an
optional YAML file on top to override individual stage tunables and pick a
different model per pipeline stage, without needing a flag for every knob.

**This port ships no stage-configuration YAML profiles.** The Python original
(`visa-vulnerability-agentic-harness`) shipped three pre-built profiles
(`default.yaml`/`sdk.yaml`/`full.yaml`) selecting between CLI/SDK/OpenAI
*backends* per role (`via: cli|sdk|openai`). `bc-sast` has none of that: there
is no shipped profile to copy, and no per-role backend selection. The wire
dialect (`--dialect openai|anthropic`) and gateway (`--gateway-base-url`,
`--gateway-api-key`) are single global flags for the whole run, not something
`config.yaml` chooses per stage. `models.<role>` only ever picks a *model id*;
it is documented in code as a deliberate scope decision, not an oversight (see
`crates/bc-cli/src/config_overrides.rs`'s module doc comment). You write your
own `config.yaml` from scratch. There is nothing to `cp` into place first.

Security-framework policies and target-testing profiles are compiled into
the binary and selected with `--scan-framework <NAME>` and
`--target-tests [LEVEL]` (alias `--testing-level`). Testing levels are
`discover`, `unit`, `integration` and `comprehensive`; a bare flag, `e2e` or
`generate` selects comprehensive scope. They are not loaded from this
stage-configuration file. Shipped levels do not authorize target execution.
The API specification step and its allowances (a 1 MiB specification cap,
two repair rounds, at most eight generator sessions per run, the
standards it may assess (OpenAPI, GraphQL, AsyncAPI, OpenRPC, Protocol
Buffers, RAML, API Blueprint, WSDL and OData CSDL) with a per-standard
document cap, and the
documentation and framework-configuration file patterns a relocation may
update) are part of the same compiled profiles; `--api-spec off` can
switch the step off, `--api-spec-formats` can narrow it to some
standards, and nothing in this file can switch it on or widen it. To change profile content, edit the
embedded source and rebuild; see
[Built-in policies and rule sources](built-in-policies.md).

Delivery is selected separately with `--remediation-delivery patch|branch|zip`.
Branch and ZIP modes require full-scan isolated remediation. Branch delivery
also requires `--delivery-remote` and `--delivery-branch`; ZIP delivery works
without Git. These flags choose how accepted code and tests leave the
workspace, not whether tests execute. See [remediation delivery](remediation-delivery.md).

## Pointing at a config file

```
bc-sast --repo ./target --config ./config.yaml ...
```

`--config` (declared on the `Cli` struct in `crates/bc-cli/src/args.rs`)
is `Option<PathBuf>`, applied
identically for a scan (`build_scan_config`) and for `--remediate`
(`build_remediate_settings`). Both independently re-read and re-parse the
same file. Omitting `--config` entirely is fully supported and changes
nothing else: every stage runs with exactly the constructed defaults its own
`Step*Config::new()` sets, the same as if `--config` didn't exist as a flag at
all.

## Resolution and merge order

`bc_config::load(path, getenv)` (`crates/bc-config/src/lib.rs`) does, in
order:

1. **Read and parse `--config`'s file** as a YAML mapping (a non-mapping top
   level, e.g. a bare list, is a hard error; an empty file is treated as `{}`).
2. **Deep-merge the built-in `step_defaults()` underneath it**: your file's
   keys win, but every scalar key `step_defaults()` knows about is present in
   the result even if your file never mentions it.
3. **If a sibling `config.local.yaml` exists next to your `--config` file**
   (same directory, literal filename `config.local.yaml`), deep-merge it
   **on top** of the result, unless `BC_NO_LOCAL_CONFIG` is set to a
   non-empty value, in which case it's skipped entirely (an empty value
   does **not** count as set). Meant for a local, gitignored override
   (e.g. a developer's own `min_confidence` while iterating) layered on
   top of a checked-in `config.yaml`. The overlay must pass a trust check
   first and its merge is announced on stderr; see
   [`config.local.yaml`: local overlay](#configlocalyaml-local-overlay).
4. **Expand `${VAR}`/`${VAR:-default}` placeholders** across the *entire*
   already-merged tree, refusing a secret-named variable (see below).

The merge primitive throughout is `deep_merge`
(`crates/bc-config/src/merge.rs`): two nested objects present on both sides
recurse; everything else, including arrays, is **replaced outright**, not
appended. So if your `config.yaml` sets `step1.exclude_dirs: [vendor]` and
`config.local.yaml` also sets `step1.exclude_dirs: [generated]`, the merged
result is `[generated]`, not the union of both.

`load()` returns a `LoadedConfig` with two parallel trees:
- `data`: the fully merged-and-expanded tree (built-in defaults + your file +
  local overlay). This is what actually configures each stage.
- `user_provided`: the same merge *without* `step_defaults()` underneath, so
  a caller can tell "the user's file never mentioned this key" apart from
  "the key is present only because a built-in default filled it in." One
  real key reads from this instead of `data`: see **`step_validate.enabled`**
  below.

### Important: passing `--config` at all changes some effective defaults

Because `step_defaults()` is *always* deep-merged under any loaded file (even
one that's syntactically valid but empty), a handful of `step_defaults.rs`
values do not match the constructed default each stage falls back to when
`--config` is omitted entirely. Grounded by comparing
`crates/bc-config/src/step_defaults.rs` against each `Step*Config::new()`:

| Key | No `--config` at all | `--config` given (even an empty file) |
|---|---|---|
| `step4.neighbor_context_lines` | `20` (`Step4Config::new`) | `25` (`step_defaults.rs`) |
| `step4.neighbor_context_max` | `40` (`Step4Config::new`) | `50` (`step_defaults.rs`) |
| `step6_verify.min_confidence` | `6` (`Step6Config::new`) | `7` (`step_defaults.rs`) |

These three, and only these three, are the divergences `step_defaults.rs`'s
own module doc comment names: the file ports Python's `_STEP_DEFAULTS` (the
deep-merge base), while each `Step*Config::new()` ports
`config/profiles/default.yaml` (the profile Python actually loads when no
`--config` is passed), and `default.yaml` explicitly overrides exactly
these three keys downwards.

Every other scalar key that appears in both places agrees (verified field by
field against `Step1Config`/`Step2Config`/`Step3Config`/`Step6Config`/
`Step7Config`/`Step8Config`/`Step10Config`/`Step11Config`'s own `::new()`;
`step1.max_turns` is `40` on both sides).
This isn't presented anywhere in the code as a bug. Just be aware that
`--config path/to/an-almost-empty.yaml` is not a strict no-op relative to no
`--config` at all.

The same effect applies to `--remediate`'s top-N cap:
`step_defaults.rs`'s `step_remediate.top_n_findings: 20` means passing
`--config` (without setting `top_n_findings` yourself, and without `--top`)
caps remediation at the top 20 findings by CVSS; omitting `--config`
altogether leaves it uncapped (every verified finding is remediated) unless
`--top`/`-i` says otherwise.

**`step_validate.enabled` is the one deliberate exception** to "any
`--config` changes the default": `step_defaults.rs` bakes it to `false`, but
`build_remediate_settings` reads it from `user_provided`, not `data`, and
only overrides its own `true` baseline when *your own file* (or the local
overlay) explicitly sets `step_validate.enabled`. Merely passing `--config`
does not silently turn S11 fix-validation off. See the doc comment on
`config_overrides::step_validate_enabled_override` for the reasoning.

## The trust boundary: refusing an in-target config

`bc_config::check_config_trust(config_path, scan_target_root, getenv)` refuses
to proceed if `--config`'s path resolves *inside* `--repo` itself. This
blocks the attack where a malicious `config.yaml` is checked into the
scanned repo and a CI job `cd`s into it before scanning. It runs after the
file is loaded but before any of its settings are applied; a refusal is a
hard error, the same as a YAML parse error.

Override with:

```
BC_ALLOW_CWD_CONFIG=1 bc-sast --repo . --config ./config.yaml ...
```

An empty-string value does **not** count as set (same `is_set_and_nonempty`
rule as `BC_NO_LOCAL_CONFIG`).

## `models.<role>`: per-stage model overrides

A top-level `models:` block picks a different model id (and the sampling,
effort and transport knobs) per pipeline role. There is no per-role
`via:`/`provider:` backend selection in this port: `--dialect` is a single
global flag, so those two keys are read by nothing.

```yaml
models:
  deepdive:
    id: claude-opus-4-6
    temperature: 0.0          # optional
    top_p: 0.9                # optional
    seed: 42                  # optional
    effort: high              # optional
    use_responses_api: true   # optional, OpenAI dialect only
```

| Per-role key | Type | Wired to |
|---|---|---|
| `id` | string | that stage's `model` |
| `temperature` | float | `ChatRequest.temperature`. Unset sends none, leaving the provider default, which is `1.0` on both dialects. Not sent (with a once-per-model warning) to a model that rejects it: GPT-5.x unless its effort is `none`, the o-series, Claude Opus 4.7 and later, and any Claude request with extended thinking on. See [`llm-transport.md`](llm-transport.md#model-capabilities). |
| `top_p` | float | `ChatRequest.top_p`. The Anthropic dialect drops it whenever `temperature` is also set (the Messages API rejects the pair), and it is dropped for the same models as `temperature`. |
| `seed` | integer | `ChatRequest.seed`. **OpenAI Chat Completions only**. The Anthropic Messages API and the OpenAI Responses API have no seed parameter, so it is inert there; it is also dropped for the OpenAI models that reject sampling. |
| `effort` | string | `ChatRequest.reasoning_effort` (and `AgenticConfig.reasoning_effort` on the agentic stages): `none`, `minimal`, `low`, `medium`, `high`, `xhigh` or `max`, case-insensitive. Unset sends none, leaving the provider's default tier (S11 excepted, see `step_validate.effort`). A tier the model does not support is clamped to the nearest one it does, and a model that takes no effort gets none. **A value that names no tier fails the run at startup**, where the Python original silently ran the role at the provider default. See [`llm-transport.md`](llm-transport.md#reasoning-effort). |
| `use_responses_api` | bool | `ChatRequest.openai_api`, the Python original's per-role transport pin: `true` sends this role's calls to the OpenAI Responses API, `false` to Chat Completions, whatever `--openai-api` says, and neither falls back. Absent leaves the role on the client-wide `--openai-api` / `llm.openai_api`. Ignored on the Anthropic dialect. A non-boolean value fails the run at startup. |

The CLI's `--temperature`/`--top-p`/`--seed`/`--reasoning-effort` apply
the same value to *every* role; a per-role key here **wins** over them.
`--step-timeout` is the exception. It OVERRIDES every `stepN.timeout`
rather than deferring to it, because it exists for an operator whose
gateway is slower than the profile's author assumed.

**Reasoning models drop sampling.** On GPT-5.x (including the default
`--model`, `gpt-5.6-luna`) `temperature`, `top_p` and `seed` are accepted
only at effort `none`; at any other effort, including the model's own
default when no effort is set, they are dropped with a once-per-model
warning rather than sent to be rejected. The o-series and Claude Opus 4.7
and later never take them, and a Claude request that thinks drops
`temperature`/`top_p` too. So on those models `effort` is the knob, not
`temperature`.

**Which roles an effort reaches.** Every role in the table below,
including `models.autoexclude` (which inherits S1's resolved effort and
transport pin when it sets none of its own) and
`models.validate.orchestrator` (panel-wide: the S11 personas read `.id`
only, as for sampling). The target-testing agents started by
`--target-tests` are the one exception: they run at the provider's
default effort on the client-wide transport.

### Model lifecycle gate

Before any token is spent (the preflight probe included), every
configured model, meaning `--model` and each `models.<role>.id` (the S11
personas included), is looked up in the capability table
(`bc_llm_client::capabilities`, see
[`llm-transport.md`](llm-transport.md#model-capabilities)):

- **Retired** (no longer served: every `claude-2*` and `claude-3*`
  model, `o1-preview`, `o1-mini`, `gpt-4.5`, and any deprecated model
  whose retirement date has passed, such as `claude-opus-4-1` after
  2026-08-05): the run stops with an error naming the model and a
  suggested replacement. `--allow-unsupported-model` turns the error
  into a warning, for a private gateway that serves its own model under
  a retired name.
- **Deprecated or legacy** (for example `gpt-4o`, `gpt-4.1`, the original
  `gpt-4` and `gpt-3.5` until they retire on 2026-10-23, `o1`, `o3`,
  `o4-mini`, the original `gpt-5`, Claude Opus and Sonnet 4.0 and 4.5):
  one warning per model on stderr, and the run continues. The table in
  `crates/bc-llm-client/src/capabilities.rs` is the authoritative
  list.
- **Current, or a name the table does not know** (a gateway alias): no
  output at all. An unknown name is never refused.

The gate applies to a scan, a `--repo-file` batch and
`--remediate-from`. `--doctor` and `--setup` show the same verdict as a
check instead (a retired model is a blocking check), and `--doctor` also
prints each model's full capability row.

### Role to stage map

The roles are named by what they do; the pipeline is documented by stage
number (`docs/architecture.md`, `docs/diagrams/pipeline.md`). This is the
lookup between the two, so putting a cheap model on S3 and an expensive
one on S6 does not mean reading the source first. Rows are in pipeline
order. **When unset** lists what supplies the model id instead, in the
order each is tried.

| Config key | Stage | What that stage does | When unset |
|---|---|---|---|
| `models.graph_annotate` | **S0** seed, and only under `step0.callgraph_detection: llm` | Turns the tree-sitter scan's call-graph candidates into source/sink specs. S0's default `rules` mode spends no tokens and never consults this role. `models.callgraph_creation`, the legacy alias `taint.yaml` still ships, and only when `models.graph_annotate` is absent entirely: whichever spelling is present wins outright rather than the two being merged field by field. Then `models.preprocess`, then `--model`. |
| `models.autoexclude` | before **S1**, and only under `--auto-step1` / `step1.auto_exclude` | One survey call that proposes extra `step1` exclusions before the S1 walk starts. S1's already-resolved model (so `models.preprocess` if set, else `--model`) and S1's already-resolved sampling knobs. This is the one role that inherits another role's sampling, not just its model. |
| `models.preprocess` | **S1** preprocess | Agentic Read/Glob/Grep survey of the repo, checked against `bc-repo-analysis`'s deterministic call graph, producing the `ContextPackage` every later stage reads. Sets `step1.model`. | `--model` |
| `models.threatmodel` | **S2** threatmodel | One non-agentic call over deterministically gathered evidence, producing the `ThreatModel`. Skipped entirely under `--no-threat-model` or `step2.enabled: false`. Sets `step2.model`. | `--model` |
| `models.decompose` | **S3** decompose | One call producing the risk-ranked review manifest, which a deterministic sweep then tops up to 100% file coverage. Sets `step3.model`. | `--model` |
| `models.deepdive` | **S4** deepdive | The vulnerability hunt itself: N calls per chunk, majority-voted, producing every candidate finding. Normally the largest share of a scan's spend. Sets `step4.model`. | `--model` |
| `models.verify` | **S6** verify | One adversarial agentic session per surviving candidate, trying to prove the finding wrong, and emitting the verdict, confidence and CVSS 3.1 vector. Sets `step6.model`. | `--model` |
| `models.dedup` | **S7** dedup, and the same pass run inline inside **S5** | Semantic dedup of findings the deterministic pre-filter could not collapse. S5's pre-verify pass calls S7's code rather than duplicating it, so this one role sets `step7.model` **and** `step5.dedup.model` together. | `--model` |
| `models.chain` | **S8** chain | One call over every verified finding: exploit chains, severity re-rank against design controls, combination with known unpatched CVEs. Sets `step8.model`. | `--model` |
| `models.remediate` | **S10** remediate, `--remediate` only | The agentic fix loop that edits source and produces the diff. Sets `Step10Config.model`, applied through `build_remediate_settings`. | `--model` |
| `models.validate.orchestrator` | **S11** validate, `--remediate` only | The validator panel's shared default: the model every persona below uses unless it names its own, and the only place the panel-wide `temperature`/`top_p`/`seed` are read. Sets `Step11Config.model`. | the flat `models.validate.id` spelling, then `--model` |
| `models.validate.security_architect` | **S11**, one persona of the panel | Grades the fix on design and coverage: data-flow through the fix, control placement, encoding bypasses, architectural fit. `.id` only. | the shared `validate` role above |
| `models.validate.penetration_tester` | **S11**, one persona of the panel | Grades the fix on real-world exploitability: sink reachability, attack vectors beyond the reported one, defects the fix itself introduces. `.id` only. | the shared `validate` role above |
| `models.validate.cross_repo_analyzer` | **S11**, third persona, only under `step_validate.cross_repo_analyzer: true` | Grades the fix on cross-repository consistency: API contracts, shared-library versions, deploy ordering. `.id` only. | the shared `validate` role above |

There is no `models.step5`/`models.prefilter` role: S5 has no LLM call of
its own (deterministic gates, then S7's dedup, covered by `dedup` above).
There is no S9 model role: S9 renders reports deterministically without an LLM; see
`docs/architecture.md`. A role absent from `models:` leaves that stage's
model at whatever `--model` (the global default) already set. This is a
no-op, not an error.

Four of the keys above are not flat `models.<role>` entries and are easy
to miss when skimming a config. `models.validate.orchestrator` and the
three S11 personas all nest one level deeper, and only `.id` is read on a
persona; the section below covers that shape in full.

Don't confuse `step7_dedup`/`models.dedup` (S7's LLM-backed *semantic finding*
dedup) with `step1.config_dedup` (a deterministic, non-LLM file/config
similarity cluster used only during S1's preprocessing). Same word, two
unrelated mechanisms.

## `models.validate.<persona>`: S11's per-persona model overrides

S11's validator panel (`--remediate` only, see `docs/validation.md`) is the
one role where a single `models.<role>.id` isn't the whole story: each
persona in the panel can be pinned to its own model, nested one level
deeper under the shared `validate` role:

```yaml
models:
  validate:
    orchestrator:                  # shared/default for any persona below without its own override
      id: claude-sonnet-4-6
      temperature: 0.0
    security_architect:
      id: claude-opus-4-6
    penetration_tester:
      id: claude-sonnet-4-6
    cross_repo_analyzer:           # only consulted when step_validate.cross_repo_analyzer: true
      id: claude-sonnet-4-6
```

A persona without its own nested entry inherits the shared/default role
(or the global `--model` if that's absent too). Only `.id` is read on a
*persona*: `temperature`/`top_p`/`seed`/`effort`/`use_responses_api` are
panel-wide and come from the shared role, matching Python, where
`via`/`provider` are likewise read from `orchestrator` only ("ONE VENDOR
PER PANEL", `default.yaml`).

**Two accepted spellings for the shared role.** Python's is the nested
`models.validate.orchestrator` shown above (`validation/cli/_model.py:39-47`;
every shipped profile uses it). The flat `models.validate.id` this port
documented first is still accepted as a fallback, so an existing config
keeps working. If both are present the nested one wins.

## Reproducible ("stable") runs

Two consecutive scans of the same commit will not produce identical reports
out of the box: every request goes out at the provider's default
temperature of `1.0`. This is the profile to start from when you need a
diffable report for a PR gate, a baseline comparison, or a parity harness,
**on a model that accepts sampling** (see the reasoning-model note
below):

```yaml
models:
  preprocess:  {id: <your model>, temperature: 0.0}
  threatmodel: {id: <your model>, temperature: 0.0}
  decompose:   {id: <your model>, temperature: 0.0}
  deepdive:    {id: <your model>, temperature: 0.0}
  dedup:       {id: <your model>, temperature: 0.0}
  chain:       {id: <your model>, temperature: 0.0}

step4:
  runs: 1            # see the S4 note below
  vote_threshold: 1
```

or, for a single run without a config file, `--temperature 0`.

**On a reasoning model this profile does nothing unless effort is
`none`.** GPT-5.x (the default `--model` included) rejects `temperature`,
`top_p` and `seed` at any effort but `none`, so the scanner drops them
with a once-per-model warning rather than sending them. To use the
profile there, add `effort: none` to each role (or pass
`--reasoning-effort none`), which gives up the model's reasoning; the
o-series and Claude Opus 4.7 and later reject sampling at every effort,
so on them the only stability levers are a fixed effort and S4's voting.
Pick a model that accepts sampling (a `*-chat-latest` alias, `gpt-4.1`)
if reproducibility matters more than reasoning.

**S1/S2/S3/S7/S8 want `temperature: 0` unconditionally.** They each make
one call whose output is structural (a repo map, a threat list, a chunk
plan, a dedup decision, a report assembly); sampling variety buys nothing
there and costs a stable report.

**S4 is the one real choice**, because it is the stage with majority
voting:

- `temperature: 0` with `runs: 1` is cheapest and most stable: one
  deterministic pass per chunk.
- `temperature: 1` with `runs: 3, vote_threshold: 2` deliberately
  *samples* for recall: three divergent passes, and only findings two of
  them agree on survive. More expensive, less repeatable, better at
  catching a finding one pass happens to miss.

Anything in between is a trap: `runs > 1` at `temperature: 0` cannot
produce divergent samples to vote over, so S4 detects it, warns, and
clamps to `runs: 1, vote_threshold: 1` rather than paying N× for N
identical answers (`_effective_runs`, ported from `s4_deepdive.py`).

**Caveats.** `seed` is sent on the OpenAI dialect only, and providers
document seeded sampling as best-effort, not guaranteed. The same prompt
can still diverge across a model revision, a fleet change, or a fingerprint
change. `temperature: 0` is not the same as determinism either; it is
greedy decoding, which is stable in practice but not contractually.
Everything downstream of the model IS deterministic in this port: S4's vote
clustering, S6's input-order results, S7's canonical-member pre-sort and
S8's report ordering were all made order-stable so that the same findings
always render the same way (see the determinism work in
`crates/bc-stage-s4/src/vote.rs` and `crates/bc-stage-s8/src/severity.rs`).

## `step_validate.cross_repo_analyzer`: opt-in 3rd validator persona

Off by default. When `true`, S11's `cross-repo-analyzer` persona runs
alongside `security-architect`/`penetration-tester` on every validated
finding, judging `root_cause`/`instance_coverage` from a cross-repository/
cross-component consistency angle (always reporting the other 2 gates as
`skip`). See `docs/validation.md` for why this port makes it an explicit
operator opt-in rather than auto-triggered like the Python original.

## `${VAR}` / `${VAR:-default}` expansion

Every string leaf in the fully-merged tree is scanned
(`crates/bc-config/src/env.rs`) for `${VAR_NAME}` or `${VAR_NAME:-default}`
(name must match `[A-Z_][A-Z0-9_]*`). Rules:

- `${FOO}` with `FOO` set and non-empty expands to that value.
- `${FOO}` with `FOO` unset or set-but-empty expands to `""` (not an error).
- `${FOO:-default}` with `FOO` unset **or** set-but-empty expands to
  `default` (POSIX `:-` semantics: empty counts as unset, not just missing).
- `${FOO:-default}` with `FOO` set and non-empty expands to `FOO`'s value
  (the default is ignored).
- Multiple placeholders in one string all expand independently.
- The default text can't itself contain a literal `}`. The matcher's
  `[^}]*` group stops at the first `}` it sees, same as the Python original.
  `${FOO:-a{b}c}` with `FOO` unset expands to `a{bc}` (a known, deliberate
  limitation, not a bug).

Expansion applies to *any* string leaf in the file, not a fixed set of keys.
For example, picking a model id from an env var with a fallback:

```yaml
models:
  deepdive:
    id: ${BC_DEEPDIVE_MODEL:-gpt-5.6-luna}
```

(Note: the gateway credential itself is supplied via `--gateway-api-key`/its
`BC_GATEWAY_API_KEY` env binding directly on the CLI. There is no
`config.yaml` section for it; `${VAR}` expansion here is a general-purpose
string-substitution pass over the merged tree, useful for anything you put in
the file, not a credentials-specific mechanism. The same goes for the TLS
material: `--ca-cert`, and the mutual-TLS client identity
`--client-cert`/`--client-key` (env `BC_GATEWAY_CLIENT_CERT` /
`BC_GATEWAY_CLIENT_KEY`), are CLI-only. See
[Gateway TLS and credentials](#gateway-tls-and-credentials) below.)

### Secret-named variables are refused

A variable whose **name** looks like a secret may not be interpolated
into the config at all (`crates/bc-config/src/policy.rs`, ported from
upstream v1.3.0). A name counts as secret-bearing when, uppercased, it
contains `API_KEY`, `APIKEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`,
`CREDENTIAL` or `PRIVATE_KEY`, or when any `_`-separated segment ends in
`AUTH` (so `GH_OAUTH` and `X_AUTH_HEADER` count, `AUTHOR_NAME` does not).

```yaml
step_remediate:
  verify_command: make test GH=${GITHUB_TOKEN}   # refused
```

fails the load with:

```
config key 'step_remediate.verify_command' interpolates environment
variable 'GITHUB_TOKEN', whose name matches a secret pattern; ...
```

The reason is where the value would end up. `verify_command` is a shell
command line, so a token expanded into it lands in process listings and
in any log that echoes the command. The check is on the name alone,
whether or not the variable is set and whether or not it has a
`:-default`, so a shared profile fails the same way on every machine
instead of only on the ones that happen to hold the secret. The message
names the key and the variable, never the value. It is a hard error like
a YAML parse error: `bc-sast` exits non-zero before any stage runs, and
`--doctor` reports it on its `--config` line.

Python allows a secret-named variable into four credential keys
(`sdk.api_key`, `openai.api_key`, `batch.git_token`,
`output.ingest_token`). This port reads **no** credential from
`config.yaml`: the gateway key comes from `--gateway-api-key` (or
`BC_GATEWAY_API_KEY`) and the git token from `--git-token`, and none of
those four keys is read by anything. So the allowed set is empty and a
secret-named variable is refused in every key, including those four. A
profile copied from the Python harness that still carries
`api_key: ${ANTHROPIC_SDK_API_KEY}` needs that line deleted; it never did
anything here. To keep a non-secret value that merely has an unlucky
name, rename the variable or write the value literally.

The same rule applies to the `--step1-config` overlay
(`apply_step1_overlay`), where each key is checked at its final
`step1.<key>` path.

## Gateway TLS and credentials

These are CLI flags, not `config.yaml` keys, because they are properties
of the one gateway connection every stage shares.

| Flag | Env | Notes |
|---|---|---|
| `--ca-cert <PEM>` | | Trust this CA bundle instead of the system store. A missing or malformed file stops the run. |
| `--client-cert <PEM>` | `BC_GATEWAY_CLIENT_CERT` | Present this client certificate for mutual TLS. The file may also hold the private key. |
| `--client-key <PEM>` | `BC_GATEWAY_CLIENT_KEY` | The private key, when it is a separate file. Refused without `--client-cert`. |

**mTLS fails closed.** A client certificate or key that is missing,
unreadable, on a network (UNC) path, not a certificate plus private key,
or a key that does not match its certificate stops the run at startup
(and blocks `--doctor`/`--setup` and the preflight gate) instead of
connecting without it. This deliberately differs from the Python
original, which warns and falls back to server-authenticated TLS: an
operator who configured mTLS expects the gateway to see a certificate,
and a silent fall-back either fails later with a harder-to-read
handshake error or, worse, succeeds against an endpoint that was meant
to demand one. `--doctor` shows an `mTLS client certificate` line naming
the file(s) whenever either flag is set.

**Anthropic OAuth tokens.** With `--dialect anthropic`, a
`--gateway-api-key` that starts with `sk-ant-oat` is an Anthropic OAuth
token, not an API key. It is sent as `Authorization: Bearer <token>`
with `anthropic-beta: oauth-2025-04-20` added to any other betas the
request carries, instead of as `x-api-key` (which the API rejects for a
token). Any other key is sent as `x-api-key`, as before. Surrounding
whitespace is trimmed from the key either way.

## Full key reference

Every key below comes from one of two authoritative sources: the built-in
scalar defaults in `crates/bc-config/src/step_defaults.rs`, and the mapping
of loaded YAML onto typed stage configs in
`crates/bc-cli/src/config_overrides.rs`. Structural keys (lists/nested
objects) are deliberately **not** given a `step_defaults.rs` entry. The
stage's own `Config::new()` supplies that default instead, and the key only
appears in the merged tree at all if you (or `config.local.yaml`) set it.

A **"dead"** key is one present in `step_defaults.rs` but never read by
`config_overrides.rs` or any `Step*Config` field. Setting it in your own
`config.yaml` has no effect on current behavior. These are carried over
verbatim from the Python original's own config surface for schema/parity
reasons but were explicitly not wired to anything during the port (see the
`crates/bc-stage-s6`, `bc-stage-s3`/`s8`, and `bc-stage-s11` module doc
comments, which call this out by name for `effort`).

### `step0`: static AST/call-graph seed

The seed plane walks the **same scope as `step1`**: the orchestrator copies `step1`'s walk settings (`exclude_dirs`, `exclude_exts`, `exclude_globs`, `max_file_kb`) onto `step0` at scan time, because S1 reuses the seed's file inventory when one is present. There is no separate `step0.exclude_*`; configure exclusions once under `step1`.

S0's *implementation* is Rust-only, but Python **does** have a `step0`
config namespace (`_STEP_DEFAULTS["step0"]`: `enabled`,
`callgraph_detection`, `sources_yaml`, `sinks_yaml`, `languages`). The
CLI accepts execution/language settings but rejects non-null
`sources_yaml` and `sinks_yaml`: rule content is compiled from source.
The lower-level schema retains those keys for library compatibility.

| Key | Default | Notes |
|---|---|---|
| `enabled` | `true` (Python: `false`) | Sets BOTH `ScanConfig.step0_enabled` (whether S0 runs at all) and `Step0Config.enabled` (S0's own internal gate) from the same key. |
| `callgraph_detection` | `"rules"` | `rules` (deterministic, zero-token) or `llm`. An unrecognized value **warns and keeps the default** rather than resolving to `rules`. A typo must not silently buy a cheaper scan. |
| `sources_yaml` | `null` | Legacy schema field; non-null values are rejected by the CLI. Edit the embedded source corpus and rebuild. |
| `sinks_yaml` | `null` | Legacy schema field; non-null values are rejected by the CLI. Edit the embedded sink corpus and rebuild. |
| `call_graph_max_targets` | *(falls back to `step1.call_graph_max_targets`, `3`)* | Cap on how many same-named definitions one call may resolve to in S0's graph. A zero or absent value falls back to `step1`'s, so both stages share one cap unless you set this. Before upstream v1.3 S0 read neither key here. |
| `languages` | `null` | Language allowlist; absent/empty means no filter. Recognized entries are `python`, `java`, `javascript`, `typescript`, `go`, `csharp`, `php`, `ruby`, `kotlin`, `rust` and `c-cpp` (plus the usual aliases: `py`/`python3`, `js`/`node`, `ts`, `golang`, `c#`/`cs`/`dotnet`, `rb`, `kt`, `rs`, and `c`/`cpp`/`c++`/`cxx` for the shared C/C++ key). See `bc_callgraph::families::lang_alias`. |

`callgraph.llm.*` (nested under `step0`) configures the annotator used by
`callgraph_detection: llm`. Setting `callgraph_detection: llm` alone is a
complete configuration (the block is populated with these defaults), and
any subset of the keys overrides them:

| Key | Default | Notes |
|---|---|---|
| `max_tokens` | `16000` | |
| `max_candidates` | `400` | Total candidate symbols offered to the model. |
| `max_batch_candidates` | `150` | Per-request batch size. |
| `min_source_confidence` | `0.75` | Model-reported confidence floor for a source spec. |
| `min_sink_confidence` | `0.75` | Same, for sinks. |
| `heuristic_supplement` | `true` | Top up the model's specs with heuristic ones when it returns few. |
| `min_sources` | `1` | Below this, the whole LLM result is discarded and `rules` runs instead. |
| `min_sinks` | `1` | Same. |
| `max_heuristic_specs` | `10` | Cap on the supplement above. |
| `failure_mode` | *(not ported)* | Python's `empty`/`fail`. This port only implements `empty`. A failed classification batch is skipped and the other batches' specs are kept (upstream v1.3); a quota or guardrail failure stops the remaining batches. If nothing survives, detection degrades to `rules` rather than aborting the scan. Both shipped Python profiles set `empty`. |
| `self_consistency` | *(not ported)* | Upstream v1.3's majority vote over N samples per batch. Opt-in upstream (default 1, a single pass, which is what this port runs). |

The model for that call comes from `models.graph_annotate` (or its legacy
alias `models.callgraph_creation`), falling back to `models.preprocess`
and then `--model`, the same chain as `_annotator.py:375-379`. Its
`temperature`/`top_p`/`seed` come from the same role.

When `step0.enabled: true`, S0 uses a starter rule corpus bundled into the
binary (`crates/bc-stage-s0/corpus/{sources,sinks}.yaml`, embedded via
`include_str!`) instead of running with an empty rule set. It is
intentionally "starter-sized" (21 source rules and 87 sink rules over
real stdlib/framework APIs), not an exhaustive port of the Python
original's `generic_pack.py`-produced corpus, which was never vendored
into this repo. Coverage today:

- **Languages**: all eleven keys in `VVAH_LANGUAGES`. `python`, `java`
  (its JVM rules also claim `kotlin`, which additionally has a Ktor
  request-surface rule of its own), `javascript`/`typescript`, `go`,
  `csharp`, `php`, `ruby`, `rust`, and `c`/`cpp` (the shared `c-cpp`
  key).
- **Sink kinds**: `sql`, `cmd`, `path`, `ssrf`, `deserialize`,
  `dyn-eval`, `crypto`, `redirect`, `xxe`, `format`, `memory`, `xss`.
- **Sources**: request/route surfaces (Flask/Django, Express, Servlet,
  gin/echo, ASP.NET `Request.Query`) plus env vars and CLI args. C#'s and
  JS/TS's property-read sources (`Request.Query`, `req.query`) depend on
  the extractor recording a non-callee property read as a call site.
- **Argument predicates**: a rule can require a shape at one named
  argument, and a rule naming two of them requires both.
  `requires_dynamic_arg`/`dynamic_arg_index` asks whether an argument is
  something other than a static string literal (a parameterized query is
  not an injection sink), `requires_any_arg` whether the call passes any
  argument at all, `requires_arithmetic_arg`/`arithmetic_arg_index`
  whether it is a `*`/`+` expression rather than a bare name, literal or
  `sizeof`, and `requires_unit_arg`/`unit_arg_index` whether it is the
  integer literal `1`. The last two are what make the C/C++ allocation
  rules precise: `c.alloc-size-overflow` (`malloc`, `alloca`, and C++'s
  `new T[n]`, recorded as `operator_new_array`),
  `c.alloc-size-overflow-second-arg` (`realloc`), and
  `c.calloc-hand-multiplied-size`, which carries both predicates so it
  matches `calloc(n * size, 1)` and leaves the idiomatic
  `calloc(n, size)` alone. Both are positive requirements rather than
  vetoes, so a rule carrying one goes dark on a language whose extractor
  computes no argument shapes; today only C/C++ answers them.
- **Deliberately absent**, and documented as such in the corpus header:
  C/C++ use-after-free, a temporal property of one pointer across two
  statements rather than a source-to-sink pair, which is left to S4/S6's
  own reasoning (and, once reported, to `bc-stage-s4::reanchor`'s
  deterministic re-anchoring). Integer-overflow allocation used to be on
  this list too; the argument predicates above are what made it
  expressible.

To change this corpus, edit `crates/bc-stage-s0/corpus/sources.yaml`
and/or `sinks.yaml`, run the relevant rule tests, and rebuild. Runtime
file overrides are rejected, including when S0 is disabled.

#### `ep_kind` and `sink_kind`: the spellings a custom corpus has to use

A source rule's `metadata.ep_kind` is read by two independent consumers,
and a spelling neither of them knows costs findings without producing an
error anywhere. When editing the embedded corpus, use these vocabularies.

**Consumer 1: the entry-point model.** `bc_model::EntryPointKind::parse`
(`crates/bc-model/src/context.rs`) resolves the label case- and
whitespace-insensitively, through the same alias table the JSON
deserializer applies:

| Kind | Also accepted as |
|---|---|
| `network` | `rpc`, `grpc`, `http`, `https`, `rest`, `api`, `graphql`, `websocket`, `ws`, `soap`, `tcp`, `udp`, `socket`, `webhook`, `endpoint` |
| `ipc` | `queue`, `message`, `mq`, `kafka`, `amqp`, `jms`, `pubsub`, `event`, `signal`, `pipe`, `bus` |
| `file` | `config`, `env`, `filesystem`, `fs` |
| `cli` | `stdin`, `argv`, `command`, `arg` |
| `deserialization` | `deserialize`, `serde`, `unmarshal`, `parse`, `pickle`, `json` |
| `framework` | `spring`, `django`, `aspnet` |
| `other` | anything the table does not know |

`framework` is what S0's framework-marker plane emits, rather than
something a source rule normally spells, and it is the only kind
`bc_stage_s5::route_gates` and S6's guarded/unauth-reachable entry-point
markers act on: on any other kind, `reachable_from_unauth` is a free field
nothing set from evidence, so it is ignored.

**Anything unrecognized becomes `other`, silently, and `other` is not
inert.** S3's specialist gating reads these kinds
(`crates/bc-stage-s3/src/specialist.rs`): `has_batch_surface` keeps the
`batch-etl` lens for a `file` or `cli` entry point, and
`has_authz_surface` keeps the `access-control` lens for a `network` or
`ipc` one. A corpus written in some other vocabulary turns both signals
off for every one of its sources. S2 also renders the kind verbatim into
its evidence block and reads `network` to decide whether the application
is a `web-api`, so an unresolved kind shows up as "other" in the threat
model too.

**Consumer 2: the taint pair filter.**
`bc_callgraph::graph::source_kind_compat` reads the same raw string,
before any alias resolution, and keys its allowed-sink rows on `network`,
`ipc`, `http`, `cli`, `stdin`, `filesystem`, `file` and `env`. A source
kind with no row admits **every** sink kind, so an unknown spelling
switches the filter off rather than failing. A source or sink kind that is
`other` or empty also admits everything, as does any sink in a protected
semantic family (`bc_callgraph::families::PROTECTED_SEMANTIC_FAMILIES`).

Both readings have to be satisfied at once, which is why the bundled
corpus spells `network` and `cli` but keeps `env`: `env` resolves to
`file` in the entry-point model, and it has a row of its own in the pair
filter with a broader sink list than `file`, so respelling it would narrow
what an environment-variable source can pair with. The header comment in
`crates/bc-stage-s0/corpus/sources.yaml` carries the same warning next to
the rules themselves.

A sink rule's `metadata.sink_kind` is the other half of the pair filter's
key. The bundled corpus uses `cmd`, `crypto`, `deserialize`, `dyn-eval`,
`format`, `memory`, `path`, `redirect`, `sql`, `ssrf`, `xss` and `xxe`;
the filter's rows additionally recognize `credentials`, `el-injection`,
`header`, `intent-redirection`, `jndi`, `ldap`, `log-injection`,
`pending-intent`, `regex`, `template` and `xpath`. The failure mode is the
opposite way around on this side: a sink kind outside those rows, and not
spelled `other`, is *dropped* by every source kind that does have a row,
so an invented sink kind loses pairs rather than admitting them.

### `step1`: preprocessing / repo mapping

| Key | Default (`step_defaults.rs`) | Notes |
|---|---|---|
| `max_budget_usd` | *(not shipped)* | **Removed.** In Python this is forwarded to the Claude CLI and Claude Agent SDK backends, which enforce it themselves; the two backends this port's dialects correspond to ignore it. Neither of the enforcing backends is ported, so the key is no longer shipped as a default. Setting it warns. |
| `max_turns` | `40` | Agentic turn cap. Agrees with `Step1Config::new()` (no drift). |
| `mode` | `"full"` | `full` always runs S1's own agentic exploration; `gap_fill` skips it when the S0 seed is already strong enough. An unrecognized value warns and keeps the default. |
| `call_graph` | `"regex"` | Which call-graph backend S1 uses: `regex` (Python's shipped default) or `tree_sitter`. **This port defaults to `tree_sitter`** when you don't set the key, deliberately: it yields real `def_spans` and exact end lines, which several downstream stages in this port were built against. Set `regex` explicitly for Python's backend. |
| `auto_exclude` | `false` | Run the AI survey pass that proposes extra step1 exclusions before S1. `--auto-step1` forces it on; `--no-auto-step1` forces it off and wins over both. |
| `auto_exclude_max_tokens` | `8000` | Caps that survey's prompt. |
| `timeout` | *(none)* | Per-call deadline in seconds for S1's agentic turns. No Python `step1.timeout` key exists; `--step-timeout` overrides it. |
| `max_file_kb` | `1024` | Read via `apply_walk`; maps to `WalkConfig.max_file_kb`. Files larger than this are skipped during the walk. |
| `call_graph_validate` | `true` | Maps to `CallGraphConfig.validate`. |
| `call_graph_supplement` | `true` | Maps to `CallGraphConfig.supplement`. |
| `call_graph_rounds` | `4` | Maps to `CallGraphConfig.rounds`. |
| `call_graph_max_targets` | `3` | Maps to `CallGraphConfig.max_targets`. |
| `max_tokens` | *(none)* | Only takes effect if you set it yourself; no `step_defaults.rs` entry. Falls back to `Step1Config::new()`'s `16000`. |
| `max_transient_retries` | *(none)* | Same as above; falls back to `4`. |
| `max_context_shrinks` | *(none)* | Same as above; falls back to `16`. |
| `allowed_tools` | *(structural)* | List; falls back to `["Read", "Glob", "Grep"]`. |
| `exclude_dirs` | *(structural)* | List; falls back to `[]`. |
| `exclude_exts` | *(structural)* | List; falls back to `[]`. |
| `exclude_globs` | *(structural)* | List; falls back to `[]`. |
| `config_dedup` | *(structural, nested)* | See below; deterministic, non-LLM. |

`config_dedup` (nested under `step1`, maps to `Step1Config.dedup: DedupConfig`):

| Key | Falls back to (`DedupConfig::new`) |
|---|---|
| `enabled` | `true` |
| `exts` | `[".yml", ".yaml", ".json", ".toml", ".ini", ".properties", ".conf", ".cfg", ".env"]` |
| `min_cluster_size` | `3` |
| `keep_per_top_dir` | `true` |
| `promote_on_secret_hit` | `true` |
| `promote_on_insecure_value` | `true` |
| `max_file_kb` | `512` |

**The auto-exclude overlay is model-authored, so it is guarded**
(upstream v1.3). The survey model reads repository content, and a model
must not be able to silently remove a whole language, or the whole
repository, from a security scan:

- Any proposed `exclude_exts` or `exclude_globs` entry that would erase an
  entire scanner-known language (`.pug`, `*.hbs`, `**/*.py`) is vetoed.
  Compound suffixes (`.pb.go`, `.min.js`) and path-scoped globs
  (`gen/**`) pass. Only the model's overlay is policed: an operator can
  still exclude a language in `step1` directly.
- The overlay's effect is then measured with the same walk S1 runs,
  including `max_file_kb`. An overlay that would leave zero files in a
  non-empty scope is discarded (its `config_dedup` tuning is kept), and
  the scan runs as with `--no-auto-step1`. One that keeps under 10% of
  the files is applied but logged as aggressive.

`bc_stage_s1::run_autoexclude_with_diagnostics` returns both decisions
(`AutoExcludeDiagnostics`: vetoed entries, files before and after,
discarded, aggressive).

**The call-graph supplement has a backstop.** When the agent produced no
seeds at all (no call graph, entry points or sinks, for example a refusal
parsed down to an empty map), the regex supplement now seeds from the
function definitions found on disk instead of doing nothing, so the scan
still gets a call graph. `CallGraphReport.backstop_seeds` records it.

### `step2`: threat modeling

| Key | Default | Notes |
|---|---|---|
| `enabled` | `true` | Also togglable via `--no-threat-model`, which always wins over `config.yaml` (ANDed on top, never re-enables it). |
| `max_tokens` | `64000` | |
| `max_threats` | `50` | |
| `baseline` | `"auto"` | |
| `max_doc_chars` | `20000` | |
| `max_manifest_chars` | `4000` | |
| `max_config_reps` | `80` | |
| `max_api_artefacts` | `100` | |
| `max_function_sites` | `80` | Truncation cap on `Evidence::function_sites`. |
| `max_config_rep_chars` | `2000` | Per-body cap on representative configuration contents, applied after the whole file is redacted. `0` lists every representative by path only. |
| `max_config_rep_bodies` | `12` | How many representatives carry a body (security-relevant names such as `web.xml` or `application.yml` first); the rest are listed by path only. |
| `max_manifest_depth` | `3` | How many directories below the root the manifest search descends. |
| `max_manifests` | `12` | Cap on manifests packed, across all kinds. |
| `max_manifests_per_kind` | `2` | Cap on manifests of any one kind (floored at `1`), so twelve `package.json` files cannot crowd out a lone `pom.xml`. |
| `max_manifest_total_chars` | `24000` | Aggregate cap across the whole manifests block, after each file's own `max_manifest_chars`. |
| `max_assets` | `40` | Assets kept, most sensitive first (name as the tiebreak). |
| `max_trust_boundaries` | `60` | Trust boundaries kept, widest asset reach first (entry point as the tiebreak). |
| `agentic` | `false` | Swap the single-shot call for a read-only tool session. Needs the orchestrator to hand S2 a tool executor (`Stage2::with_tools`); without one the stage warns and stays single-shot. |
| `allowed_tools` | `["Read", "Glob", "Grep"]` | Tools the agentic session may use. Anything outside those three fails the stage closed. |
| `max_turns` | `12` | Turn bound for the agentic session, its only real bound. |
| `timeout` | *(none)* | No Python `step2.timeout` key; readable here, and overridden by `--step-timeout`. |

Every cap here treats `0` as a real value ("emit none of this"), not as
"use the default". A negative or non-numeric value keeps the default.

**Evidence, v1.4.0.** Ported from upstream `s2_threatmodel.py`
(`crates/bc-stage-s2/src/{docs,manifests,config_reps,repo_read}.rs`):

- *Two views of the repository.* Blocks about the call graph (modules,
  entry points, function sites, call edges) read the AST frontier. Blocks
  about repository shape (language breakdown, components, configuration
  representatives, API artifacts, design documents) read the full
  in-scope file list, so a 220-file frontier no longer hides most of a
  monorepo's configuration.
- *Contained reads.* Every read goes through `bc_pathjail::confine`, so a
  committed symlink that resolves outside the repository (a
  `README.md` pointing at a host file, say) is never read into the prompt.
  Reads are also bounded to `4 * cap + 4` bytes; the truncation notice
  then reports the file's byte length (for ASCII, its character count).
- *Documents.* `THREAT_MODEL.md`, `SECURITY.md` and `ARCHITECTURE.md` come
  before the READMEs and the changelog. Each present document first gets
  a third of what remains of `max_doc_chars`; a second pass grows the
  truncated ones with what is left, so one large README cannot starve the
  threat model and a lone README still gets the whole budget.
- *Manifests.* A walk up to `max_manifest_depth` deep, skipping the
  default excluded directories (`node_modules`, `vendor`, tests, ...) and
  never descending a symlink, keeping `max_manifests_per_kind` per kind
  and taking kinds round-robin up to `max_manifests`. `package.json` and
  `composer.json` keep only their name, version, dependency and script
  keys. `pyproject.toml` keeps its `[project]` name, version and
  dependency keys and the `[project.optional-dependencies]` and
  `[tool.poetry.dependencies]` tables, extracted line by line (upstream
  parses with `tomllib`; no TOML parser is a dependency here, and the
  kept lines stay TOML rather than becoming JSON).
- *Configuration representatives.* One per immediate parent directory per
  round, breadth-first, security-relevant names first, and selectable even
  when the extension (`.xml`, `.config`, `.plist`) is not a config
  extension. The first `max_config_rep_bodies` carry their contents,
  **redacted in full with `bc_redact` before being capped**: capping first
  could cut a secret in half so that neither half matches a redaction
  pattern. A file over 500,000 characters goes path-only rather than being
  cut before redaction.

**Reply handling, v1.4.0.** A reply that fails to extract or validate
(most often a bare string where an asset object is required) gets one
repair call with the same budget, since it must re-emit the whole model.
A second failure fails the stage, and the orchestrator continues with no
threat model. A non-empty object sharing no key with the schema is refused
rather than read as an empty model. Threats are then ranked
deterministically (impact, the sensitivity of the asset threatened,
likelihood, actor reach, uncontrolled before controlled, id) and capped at
`max_threats`; a dropped threat that was the only one covering a trust
boundary is promoted back in place of the lowest-ranked threat whose
removal uncovers nothing. The baseline checklist items now carry ids
(`BL-WEB-A01`, `BL-NAT-416`, ...) and the prompt requires a disposition
for each: a threat whose `evidence` starts `baseline: <ID>`, or an
`open_questions` entry starting `<ID>:`. Items disposed of neither way are
logged (audited before the cap) and reported in
`ThreatModelDiagnostics.baseline_undisposed` from `Stage2::run_detailed`.

**The nine narrowing caps.** S2 narrows twice: once to build the AST
*frontier* it reasons over (`ctx.ast_context_view(...)`), and again to
truncate what is actually printed into the prompt. The key names do not
say which is which, and Python's own `default.yaml` comment on
`max_modules` ("ctx.modules[] lines in the prompt") describes the wrong
one. `_gather_evidence` (`s2_threatmodel.py:229-251`) is authoritative:

| Key | Default | Narrows |
|---|---|---|
| `max_graph_files` | `220` | **Frontier**: files |
| `max_entry_points` | `400` | **Frontier**: entry points |
| `max_graph_sinks` | `80` | **Frontier**: sinks |
| `max_modules` | `100` | **Frontier**: modules |
| `max_graph_edges` | `100` | **Frontier**: call-graph edges |
| `max_notes_chars` | `2500` | **Frontier**: notes text |
| `max_prompt_modules` | `100` | **Prompt**: module lines |
| `max_prompt_entry_points` | `400` | **Prompt**: entry-point lines |
| `max_function_sites` | `80` | Prompt-side; read alongside the frontier caps but never passed to `ast_context_view` |

This port previously mapped the unprefixed `max_modules`/`max_entry_points`
onto the PROMPT caps and left every frontier cap unreachable from a config
file. Both halves are correct now, and `Step2Config::new()`'s frontier
defaults were corrected from `40`/`80` (Python's `_cap_int` *fallbacks*,
which never apply because `_STEP_DEFAULTS` always supplies the key) to
`100`/`400` (what Python actually runs).

### `step3`: decomposition / chunking

| Key | Default | Notes |
|---|---|---|
| `max_tokens` | `64000` | |
| `timeout` | `3600` | Per-call wall-clock deadline in seconds, mapped to `ChatRequest.timeout`. Was dead; now wired. `--step-timeout` overrides it. |
| `taint_chunks` | `true` | |
| `taint_max_hops` | `10` | |
| `taint_max_chunks` | `60` | |
| `taint_files_per_hop` | `5` | |
| `pack_by` | `"loc"` | |
| `pack_merge_underfilled` | `true` | Coalesce adjacent under-filled buckets after packing. Off restores the previous one-bucket-per-cohesion-group behavior. See below. |
| `chunk_token_budget` | `180000` | |
| `chunk_overhead_tokens` | `80000` | |
| `risk_chunk_loc` | `10000` | |
| `catchall_enabled` | `true` | |
| `catchall_chunk_loc` | `4000` | |
| `catchall_max_files` | `100` | |
| `catchall_mode` | `"all"` | `all` or `reachable_only`. See "Catch-all coverage" below; upstream's `default.yaml` ships `reachable_only`, this port deliberately does not. |
| `catchall_reachable_min_ratio` | `0.0` | Under `reachable_only`, fall back to `all` when fewer than this fraction of eligible files are reachable. `0` disables the check. |
| `catchall_reachable_min_files` | `0` | The same fail-open guard as an absolute reachable-file floor. |
| `catchall_deduct_lens_coverage` | `false` | Run catch-all last, and do not count a specialist lens's claim on a file as coverage. See below. |
| `max_cohesion_groups` | `64` | Cap on directory-fallback cohesion groups; past it the smallest directory folds into its parent. `0` means the default. |
| `max_files_per_chunk` | `80` | |
| `specialist_chunk_loc` | `10000` | |
| `specialists` | *(structural)* | List; falls back to the eleven lenses listed under "Specialist lenses" below. |
| `threat_surface_fallbacks` | `true` | Give every threat no other chunk cites a deterministic fallback chunk. |
| `threat_fallback_max_files` | `12` | Candidate-file cap per fallback chunk. `0` means the default. |
| `max_threat_fallback_chunks` | `50` | Ceiling on fallback chunks. Suppressed candidates are counted in the S3 diagnostics. `0` means the default. |
| `max_prompt_threats` | `50` | Ranked threats the strategist prompt carries. `0` means the default. |
| `max_prompt_assets` | `20` | Threat-model assets in the strategist prompt. `0` means the default. |
| `max_prompt_boundaries` | `30` | Trust boundaries in the strategist prompt. `0` means the default. |
| `max_prompt_threat_context_chars` | `2500` | Characters of threat-model system context in the strategist prompt. `0` means the default. |
| `taint_chunk_slice` | `"file"` | **Read by S4, not S3**. See the `step4` table below. It is declared here because that is where every shipped Python profile sets it. |

Every non-structural key here agrees with `Step3Config::new()`, except
`taint_chunk_slice`, which has no `Step3Config` field at all: it is
resolved at config load onto `Step4Config::taint_chunk_slice`.

Unlike S2, where a `0` cap means "emit none of this block", the S3 caps
marked above read `0` as "use the default", as upstream's `_cap` does.
`risk_chunk_loc: 0` is the exception: it switches oversize splitting and
the threat-fallback LOC trim off.

#### The strategist's file inventory

The decompose prompt opens with a FILE INVENTORY that gives every file,
entry point and sink in the (frontier-narrowed) context a deterministic
id (`F001`, `E001`, `K001`, numbered in sorted order so the prompt is
byte-identical across runs), and the system prompt tells the model to
cite ids only. Ids are resolved against that same inventory, so an
unknown id is simply dropped and no model-authored path can name a file
outside the repository. A model that sends paths anyway gets them
suffix-matched at a `/` boundary against the ground truth: a unique match
is kept (`core/utils.py` for `app/core/utils.py`), anything else is
dropped. A chunk left with no files is dropped rather than sent to S4, and
one off-schema chunk no longer discards the rest of the ranking. When S2
produced no ranked threats, a variant system prompt without the
must-cite-a-threat rule is used, so the model neither refuses nor invents
threat ids.

#### Catch-all coverage

Catch-all sweeps every eligible file no risk, taint or threat-fallback
chunk claimed. Two modes:

- `all` (this port's default) sweeps every eligible file.
- `reachable_only` drops eligible *source* files that are neither
  forward-reachable from an entry point nor backward-reachable to a sink
  on the file-level call graph, and lists them on
  `TaskManifest.unreachable_files`. Non-source files (`.env`, `Makefile`,
  `conf/app.conf`) it would drop are re-added instead, since no specialist
  lens reviews a non-source file, and counted as forced coverage in the S3
  diagnostics. A file in a language the call graph has no node for at all
  is treated as reachable, and that coverage check reads only call-graph
  files, never entry-point or sink files, so one entry point in a
  language the graph engine cannot parse no longer strips the fail-safe
  from every other file in it. The sparsity guards measure over every
  eligible file in the repository, not just the ones still uncovered.

Upstream's `default.yaml` runs `reachable_only` with
`catchall_reachable_min_ratio: 0.5`. This port keeps `all`: it is a
superset of what `reachable_only` reviews, and a security scan should not
make coverage depend on a call graph that is blind to reflection and
dependency injection. Set both keys to reproduce upstream.

`catchall_deduct_lens_coverage: true` (upstream's `sdk`, `full` and
`taint` profiles) runs catch-all after the specialists and the threat
fallback, and does not count a specialist's claim as coverage: a lens is
scoped guidance, not a generic review, so every source file still gets an
unscoped pass unless a risk, taint or threat-fallback chunk claimed it.

#### Specialist lenses

The default list mirrors upstream v1.4's `default.yaml`: `crypto`,
`logic-bug`, `access-control`, `batch-etl`, `iac`, `deserialization`,
`csrf`, `sensitive-data`, `hardcoded-creds`, `log-injection` and
`injection`. Every lens is gated on evidence that its surface exists, so a
lens with nothing to review costs nothing:

| Lens | Runs when |
|---|---|
| `access-control` | an authorization surface exists: externally facing app profile, a network/IPC or unauthenticated entry point, an auth design control, or a remote-actor threat |
| `crypto`, `deserialization` | a source file mentions a crypto or deserializer API |
| `batch-etl` | a file/CLI entry point, COBOL or JCL, or a batch-I/O pattern in source |
| `iac` | any IaC file exists (it reviews only IaC files) |
| `hardcoded-creds` | a literal credential assignment, comparison or dict key appears (a `${...}` placeholder does not count) |
| `csrf` | an authorization surface exists, or a CSRF marker or state-changing route annotation appears |
| `injection` | any injection-family sink appears (SQL/NoSQL, command, LDAP/XPath/XML, HTTP client, file path or archive, template, redirect or header, regex compile) |
| `sensitive-data`, `log-injection` | the repository has entry points |
| `logic-bug` | always |

The content gates read each source file once for all lenses. Lenses that
share the default source buckets are emitted shard-major (every lens for
shard 1, then shard 2), each chunk stamped with `Chunk.shard_id`
(`shard-NN`, or `iac-shard-NN` for the IaC buckets), so consecutive S4
calls for one shard send the same source prefix and can reuse a provider
prompt cache. S4 injects every lens body, the five newest from
`bc_stage_s4::lens_hints`; the `csrf`, `hardcoded-creds`,
`sensitive-data` and `log-injection` findings they produce survive S5's
`require_evidence` gate through its point-of-occurrence exemption (see
`step5_prefilter`).

#### Cohesion groups

Files with no module membership and no call-graph edge are grouped by
their immediate parent directory (upstream v1.3; earlier builds used the
first two path segments, which lumped whole subtrees together). When that
yields more than `max_cohesion_groups` groups, the smallest directory
folds into its parent, one level at a time, until the count fits. Oversize
LLM chunks are split with the same grouping, but `taint-` chunks are never
split: their source, sink and path metadata name one entry-to-sink pair,
and S4's own loaders handle their size.

#### `pack_merge_underfilled`: pack by code volume, not by group count

`pack_merge_underfilled` (default `true`) controls how chunk packing
turns cohesion groups into buckets. The packing pass emits at least one
bucket per cohesion group and never back-fills, so on its own the bucket
count tracks *group* count rather than code volume. A repository whose
groups are mostly small directories yields dozens of buckets filled to a
small fraction of the line cap, and **every bucket costs one S4 model
call per enabled lens**.

With the key on, adjacent under-filled buckets are coalesced afterwards,
still respecting the line, character, and file caps. Merging is
adjacent-only, so cohesive grouping keeps deciding which files sit
together and the caps alone decide how many buckets that takes. The
flattened file sequence is unchanged, so the selected file set is
identical either way, and a file whose own size already exceeds the cap
stays in a bucket of its own. A merged bucket's label keeps the first
group's name and records how many more folded in, for example
`cg:handlers (+7 more groups)`.

Measured on two real trees with no call graph available, so grouping
fell back to directories (these figures predate the move from depth 2 to
immediate-parent grouping, which yields more, smaller groups before
coalescing):

| Target | Pass | Buckets before | Buckets after |
|---|---|---|---|
| This repository (Rust, 274 files, 48 groups) | catch-all | 73 | 50 |
| This repository (Rust, 274 files, 48 groups) | specialist | 53 | 21 |
| `visa-vulnerability-agentic-harness` (Python, 553 files, 119 groups) | catch-all | 137 | 33 |
| `visa-vulnerability-agentic-harness` (Python, 553 files, 119 groups) | specialist | 124 | 13 |

Set it to `false` to restore the previous one-bucket-per-group packing
exactly. It is the escape hatch if detection quality regresses on a
specific target, since a merged bucket puts more, less related code in
front of a single call.

### `step4`: deep-dive finding generation

| Key | Default | Notes |
|---|---|---|
| `parallel` | `5` | |
| `max_tokens` | `64000` | |
| `max_findings_per_run` | `10` | |
| `neighbor_context_lines` | `25` | With no `--config` at all it is `20` (drift; see above). |
| `neighbor_context_max` | `50` | With no `--config` at all it is `40` (drift; see above). |
| `runs` | `1` | |
| `vote_threshold` | `1` | |
| `specialist_runs` | `1` | |
| `line_bucket` | `10` | Line tolerance for clustering votes across runs, a tolerance rather than a fixed grid (see `crates/bc-stage-s4/src/vote.rs`). |
| `timeout` | `1800` | Per-call deadline in seconds. Was dead; now wired. `--step-timeout` overrides it. |
| `taint_prompt_mode` | *(none)* | `discover` (default) or `confirm_refute`. |
| `taint_runs` | *(none)* | Per-kind run override for taint chunks; falls back to `runs`. |
| `taint_chunk_slice` | *(none, falls back to `step3`'s `"file"`)* | `file` or `function`. Optional override of `step3.taint_chunk_slice`; no shipped Python profile sets this half. See below. |
| `frontier_max_funcs_per_file` | `24` | Per-file cap on def-spans the `function`-mode graph slice may take before shipping that file whole instead. Only consulted when slicing is on. |
| `shard_cache_gating` | `true` | Hold each specialist lens on a shard until the shard's first lens (its leader) has returned, so the rest read the shard's cached prompt prefix instead of each writing it again. See "Shard cache gating" below. |

`runs > 1` at `temperature: 0` is clamped to `runs: 1, vote_threshold: 1`
with a warning. See "Reproducible runs" above.

**Reply handling with no key of its own** (ported from upstream v1.4.0):

- *Shape check and one repair.* A reply must carry a findings list: an
  object whose `findings` is an array (`{"findings": []}` is the
  legitimate "found nothing"), or a non-empty bare array. `{}`, `[]`,
  `{"findings": null}` and a misspelled key are refused rather than read
  as zero findings (`crates/bc-stage-s4/src/findings_shape.rs`). A
  refused or unparseable reply gets exactly one repair call, worded for
  the failure (restore the `findings` key for a shape error, fix the
  syntax only for a syntax error) and capped at
  `min(max_tokens, 12000)` output tokens. If the repaired reply still
  fails, that run fails, so the coverage loss is recorded instead of
  hidden.
- *Vote threshold follows the runs that succeeded.* With `runs: 3` and
  `vote_threshold: 2`, two failed runs used to leave every surviving
  finding one vote short, and the chunk completed with nothing. The
  threshold is now `min(vote_threshold, runs that succeeded)`.
- *Empty chunks are skipped.* A chunk with no files is recorded as
  `skipped` before any model call, never as `completed`.
- *Binary and data-URI elision.* Before redaction, a file whose first
  8192 characters contain a NUL or more than 10% U+FFFD collapses to a
  one-line `[binary content elided: <path> is not text]` marker, and
  every `data:<type>;base64,...` URI is replaced in place (no line
  shifts) with `[data-uri <type> elided: N chars]`. A gateway was seen
  rejecting whole requests over an embedded data-URI.
- *Findings cut by `max_findings_per_run`* are counted, not silently
  dropped. The counts (`json_repairs_attempted`,
  `json_repairs_succeeded`, `findings_truncated`,
  `vote_threshold_clamped`, `empty_chunks_skipped`) land in
  `DeepdiveOutput.diagnostics`.

#### Shard cache gating

Every deep-dive call carries a scan-constant context block (CMDB profile,
compact threat model, entry-point inventory, trust rule) as its cache
prefix, and every specialist lens on one S3 shard adds that shard's
source to it, byte-identical across the lenses (see "Prompt caching" in
[`llm-transport.md`](llm-transport.md)). A cache entry becomes readable
only when the call that writes it returns, so lenses dispatched back to
back would each write the same prefix at the cache-write rate. With
`shard_cache_gating: true` (upstream v1.4.0's `_shard_gates`) the first
lens of each shard runs at once and the others wait for its call to
return:

- A waiting lens gives its `parallel` slot back while it waits, so other
  chunks keep running and `parallel: 1` cannot stall. The cost is
  latency for the waiting lenses, never throughput.
- The waits are bounded: 15 s for the leader to start, 240 s for it to
  finish. Past either, the lens runs anyway and the prefix may be written
  twice. A leader that fails, is stopped by the budget or is aborted
  releases its lenses at once.
- Confirm/refute taint chunks carry no prefix and are never held.
- The counters `leader_start_cap_expired`, `gate_cap_expired` and
  `sibling_parked_ms` land in `DeepdiveOutput.diagnostics`.

Set it `false` when the provider or gateway has no prompt cache, where
waiting buys nothing. Upstream switches it off itself on such a route;
S4 cannot see the route here, so it is an operator choice.

#### `taint_chunk_slice`: ship the path, not the files

`file` (the default) puts every byte of every chunk file in the prompt:
whole files for a SMALL/MEDIUM chunk, sliding windows for a LARGE one.
`function` puts only the code the chunk is actually about:

- A chunk carrying a static taint path (`path_funcs`, from S0/S3) gets the
  **def-span of every hop on the path**, plus 8 context lines either side
  and the sink line itself. Overlapping hops in one file merge into a
  single contiguous block, and files come out in `chunk.files` order
  (entry to sink), so the model reads the path in flow order.
- Any other chunk gets a **graph slice**: the chunk's def-spans ranked by
  call-graph / entry-point / sink / focus relevance, capped at
  `frontier_max_funcs_per_file` per file, ±6 context lines.

**Fallbacks are per file, never per chunk.** A hop whose file has no AST
span and no call-graph def-site anchor is shipped WHOLE rather than
dropped; so is a file whose functions were clipped at the cap, and one
the graph resolved nothing for at all. If nothing anywhere in a chunk
resolves (no `def_spans`, e.g. `step1.call_graph: regex`), slicing
silently no-ops back to the `file` loaders, with one warning per process.
So turning this on can only ever *reduce* prompt size; it cannot drop
code the `file` mode would have shown.

Slicing also decides which of two sentences the confirm/refute prompt
carries: with it on, "the SOURCE CODE below contains ONLY the functions
on this path"; with it off, the honest description of a whole-file load.
(Python hardcodes the first even under its own `"file"` default. That is
a bug: the REFUTED rule "the path is not actually connected in the code
shown" is judged against that claim. This port fixes it rather than
reproducing it.)

The key is spelled `step3.taint_chunk_slice` in Python's defaults and in
`profiles/taint.yaml`, the only shipped profile that turns it on;
`step4.taint_chunk_slice` overrides it when present. This port resolves
both onto one `Step4Config` field at config load, so either spelling
works and `step4` wins.

### `step5_prefilter`: deterministic pre-filter + pre-verify semantic dedup

| Key | Default | Notes |
|---|---|---|
| `min_pre_confidence` | `0.6` | |
| `require_evidence` | `true` | |
| `ast_backfill_evidence` | `true` | Whether the AST/call-graph pass backfills missing source/sink refs on surviving findings. Was unread; now wired to `Step5Config.ast_backfill`. |

**`require_evidence` exempts point-of-occurrence findings** (upstream
v1.3). A finding is exempt when its `vuln_class` is information leak, its
CWE is a hardcoded-credential class (798, 259, 321, 256) or a
missing-control class (352, 1004, 614, 307, 778, 311, 312, 532, 209), or
its text carries credential evidence. For these the committed value, the
missing decorator or the log call IS the evidence; there is no
source-to-sink flow to cite, so requiring one silently dropped every CSRF,
hardcoded-credential and log-injection finding. The exemption is from the
flow requirement only: every other gate still applies. The same predicate
keeps such a finding when it sits under a test or fixture path, as
upstream does. Exempted findings are counted in
`PrefilterDiagnostics::evidence_exempted`.

**S4's prompt names `min_pre_confidence`'s number as a floor of its own.**
When the deep-dive sees a handler with no visible authentication or
authorization check, and the file that registers the route is not in the
slice it was given, it cannot tell whether framework middleware, a filter
or an annotation already guards it. It is told to report the finding
anyway, to say so in `preconditions`, and to set `confidence` to exactly
`0.6` and never lower. `bc_stage_s5::gates::apply_gates` drops a finding
whose confidence is strictly below `min_pre_confidence` (equal is kept),
and it runs before `route_gates` and before S6, which are the two stages
that do have the repository access to settle the question. A finding filed
under the gate is therefore deleted before anything that could adjudicate
it ever sees it.

The prompt's number and this default are pinned together by a cross-crate
test (`the_missing_auth_confidence_floor_clears_the_s5_pre_verify_gate` in
`bc-stage-s4`, which is why `bc-stage-s4` carries a dev-dependency on
`bc-stage-s5`), so the default cannot move without the prompt moving with
it. **Your own override is not pinned to anything.** Raising this key
above `0.6` silently deletes every unverifiable route-guard finding,
CWE-284, 285, 287, 306, 862 and 863 among them, before any verifier
runs. There is no config key for the prompt's floor, so raising the gate
is a decision to discard that class of finding, not a way to see fewer
weak ones.

**`pre_verify_threshold` lives under `step7_dedup`, not here.** Python
reads it off the S7 section (`s5_prefilter.py:219`,
`getattr(s7d, "pre_verify_threshold", 25)`) because the pass it gates *is*
S7's semantic dedup, run early. This port read it under `step5_prefilter`,
the intuitive place and the wrong one, so a config written against
Python silently got the hard-coded `25`. Both spellings are accepted now;
the `step5_prefilter` one warns that it is deprecated, and `step7_dedup`
wins if both are present.

`step5`'s dedup sub-config is shared with `step7_dedup` (see below): setting
`step7_dedup.*` also updates `step5.dedup.*` in the same call.

**Three context-aware gates run last in the chain, with no config key of
their own** (`bc_stage_s5::lang_gates` and `::route_gates`; all net-new,
Python has no language or framework awareness in S5). Each only ever drops
a finding whose language or framework wiring makes it impossible, and
every ambiguity keeps the finding for S6:

- *`synchronous JS/TS code cannot race`*: a CWE-362/366/367 or
  `race-condition` finding in a `.js`/`.ts` family file whose lines contain
  no asynchronous boundary at all. Node runs one JavaScript thread to
  completion between suspension points, so a `++` or an `if (x) { x = ... }`
  with no `await`/`.then`/callback/timer between the read and the write
  cannot race.
- *`template engine escapes this construct by default (<engine>)`*: a
  CWE-79/80 finding on a default-escaped construct in a Handlebars, Pug,
  EJS, Jinja/Twig, ERB, Razor, Blade or Vue template, with no raw construct
  and no non-HTML context (`<script>`/`<style>`, an `on*=` handler, a
  `href`/`src` that could be `javascript:`, a CSS value) anywhere near it.
  JSX/TSX and plain `.html` name no engine and are never gated here.
- *`route is guarded by the framework (<guard>): authorization findings on
  it need a bypass, none claimed`*: a CWE-284/285/287/306/862/863 finding
  (or the same claim in words under any CWE) on a handler every framework
  entry point reaching it says is `reachable_from_unauth: false`. Only
  `EntryPointKind::Framework` entry points count, since only S0 sets that
  field from evidence. A finding claiming the guard is bypassable or
  mis-registered is never dropped, one open route among the matches vetoes
  the drop, and a file no route names is never gated.

The first two read the finding's real lines (plus two either side) from the
repo, and the third reads the handler's file and its route table; all fall
back to the model's own `code_snippet`, or to no source at all, when a file
cannot be read. All three claims are also in the S4 hints and the S6
verifier prompt, which is what catches the cases the gates deliberately
leave alone, along with six more language facts the gates have no
mechanical half for (parameterized SQL, Rust's safe-code memory guarantees,
Go's real goroutine parallelism, Java atomicity, bounded vs unbounded C
copies, and what the Python/Ruby GIL does *not* prevent). See
[architecture.md: Language knowledge in the prompts](architecture.md#language-knowledge-in-the-prompts).

### `step6_verify`: adversarial verification

| Key | Default | Notes |
|---|---|---|
| `parallel` | `5` | |
| `min_confidence` | `7` | With no `--config` at all it is `6` (drift; see above). Only `TRUE_POSITIVE` findings scoring at or above this survive to the report. |
| `max_budget_usd` | *(not shipped)* | **Removed.** The `bc-stage-s6` module doc comment traces the whole story: Python forwards it only to the Claude CLI and Claude Agent SDK backends, and `sdk.py`/`oai.py`, the two this port's dialects correspond to, accept but never enforce it. Setting it warns. |
| `max_turns` | `30` | |
| `allowed_tools` | *(structural)* | List; falls back to `["Read", "Glob", "Grep"]`. |
| `timeout` | *(none)* | Per-turn deadline in seconds; no Python key. `--step-timeout` overrides it. |
| `progress_file` | `false` | Keep `<state-dir>/s6_progress/<run_id>/s6_progress.json` up to date while S6 verifies (status, total, completed, remaining, a count per outcome, `updated_at`), rewritten atomically after each finding. `--s6-progress-file` turns it on too. Ported from Python's `_S6Progress`; see `docs/outputs.md`. |

**One verdict-format repair, no key.** A verifier reply with no parseable
`VERDICT:` line used to become `VERIFY_ERROR` straight away. Now, when
the reply still names `TRUE_POSITIVE` or `FALSE_POSITIVE` somewhere, S6
makes exactly one repair call asking the model to restate (not
reconsider) its conclusion in the two-line format
(`crates/bc-stage-s6/src/repair.rs`, ported from upstream v1.4.0). The
restated verdict is adopted only if it agrees with the one token the
first reply named, or if the first reply named both. Otherwise, and
whenever the repair call fails or the budget gate has tripped, the
finding stays `VERIFY_ERROR`, and the unparseable text is logged
redacted in full before being cut to 200 characters. A reply naming
neither token gets no repair call, since there is nothing to restate and
the model would have to invent a verdict. A failed repair never counts
toward the guardrail-abort gate. Unlike upstream, the repair session is
offered no tools: it must not reopen the analysis. The counts land in
`VerifyOutput.diagnostics` (`verdict_repairs_attempted`,
`verdict_repairs_adopted`).

### `step7_dedup`: semantic finding dedup

| Key | Default | Notes |
|---|---|---|
| `line_tolerance` | `3` | |
| `semantic` | `true` | Whether the LLM-backed semantic pass runs at all (vs. line/rule matching only). |
| `max_tokens` | `64000` | |
| `merge_same_range_cwes` | `true` | Merge two findings on the **exactly** equal `(line_start, line_end)` range of one file that were reported under **different** CWEs, one code range seen through several lenses (a live Juice Shop scan produced 11 findings for 3 near-identical functions this way). The surviving entry keeps the most severe member's CWE, class and CVSS; the others are listed in the report's `**Also flagged as:**` line and as extra SARIF `taxa`, so nothing is lost. Exact range equality only, never the `line_tolerance` window, and never for `logic-flaw` findings. Set `false` to keep every lens as its own finding. No Python equivalent. There, a CWE mismatch vetoes any collapse. |
| `merge_same_sink` | `true` | Merge two findings that share a normalized `sink_ref` under an explicit, equal CWE even when their `source_ref`s or anchor files differ, one fix site reported from two hops of one flow (a 2026-09-07 polyglot run reported one command injection from the handler and again from the service it calls). The merged copy keeps its own `source_ref` in the survivor's duplicate list. `false` restores "same source AND sink, or nothing". |
| `pre_verify_threshold` | *(none in `step_defaults.rs`; falls back to `25`)* | S5 runs S7's semantic dedup ahead of S6 once this many findings survive the deterministic gates. `0` disables that early pass. Read HERE, matching Python. |
| `timeout` | *(none)* | Per-call deadline in seconds; no Python key. |

Setting any of these under `step7_dedup` applies identically to
`config.step7` (the standalone S7 dedup stage) and `config.step5.dedup`
(S5's inline pre-verify dedup pass): one YAML key, two configs updated.

### `step8`: finding chain/report assembly

| Key | Default | Notes |
|---|---|---|
| `max_tokens` | `64000` | |
| `timeout` | `3600` | Per-call deadline in seconds, mapped to `ChatRequest.timeout`. Was dead; now wired. `--step-timeout` overrides it. |

S8 never fails the run; it degrades (see `crates/bc-stage-s8/src/
degrade.rs`). Three behaviors ported from upstream v1.4.0:

- A scan with no findings **and** `total_files_in_scope == 0` gets the
  summary "0 files analyzed: no conclusion can be drawn about this
  repository..." with `degraded: true`, rather than the clean "No
  findings survived adversarial verification." Reading nothing and
  finding nothing are opposite claims.
- Provider, parse and hydration error text embedded in the delivered
  summary is redacted in full with `bc_redact` and only then capped at
  400 characters, so a secret straddling the cap cannot survive half
  redacted. The unparseable-reply log excerpts (first 500, last 200
  characters) follow the same order.
- When a parseable reply ranks fewer findings than it was given (every
  entry discarded as a string index, out of range or a repeat), S8 logs a
  warning naming how many findings ship unranked at their CVSS band. A
  salvaged top-level chains array, which has no ranked entries by
  design, does not warn.
### `scan_progress`: text progress lines

Not a stage: the plain-text `[progress]` lines `bc-sast` prints to
stderr for logs nothing redraws in place (CI, `tee`, a container's
captured output), ported from the Python original's `scan_progress`
section.

| Key | Default | Notes |
|---|---|---|
| `enabled` | `false` | Print the lines, and switch the terminal progress bar off (both write to stderr). `BC_SCAN_PROGRESS_ENABLED=1` (or `true`/`yes`) and `--progress-style` also turn them on; any one of the three is enough. |
| `style` | `compact` | `compact` (stage start/done lines with their counters, S4 chunk progress, the S4 summary), `verbose` (compact plus running findings counts and per-stage tokens and cost), `summary_only` (the S4 summary alone) or `stage_only` (numbered `▶`/`✓` stage lines only). An unrecognized value falls back to `compact`, as in Python. `--progress-style` wins over it. |

The Python default profiles ship `enabled: true`; this port keeps the
bar as its default on a terminal and leaves the lines off unless asked
for. Python's `llm_debug` style, which prints every prompt's text, is
deliberately not ported: prompts carry source code that does not belong
in a CI log. See `USER_GUIDE.md` §7 for sample output.

```yaml
scan_progress:
  enabled: true
  style: stage_only
```

### `llm`: transport-level model-call settings

Not a stage: a top-level section for settings that belong to the HTTP
transport every stage shares rather than to any one of them. Net-new
versus Python, which has no `llm:` section at all.

| Key | Default | Notes |
|---|---|---|
| `openai_api` | `"auto"` | Which OpenAI API shape the OpenAI dialect speaks: `chat` (Chat Completions), `responses` (the Responses API) or `auto` (Responses first for known reasoning models, Chat Completions for everything else, learning per model). `--openai-api` and `BC_OPENAI_API` win over it. The per-role pin is `models.<role>.use_responses_api`. Ignored on the Anthropic dialect. A value that is none of the three fails the run. See [`llm-transport.md`](llm-transport.md#openai-chat-completions-or-the-responses-api). |
| `cache_markers` | `true` | The prompt-cache kill switch (Python's top-level `cache_markers: "on"`/`"off"`). `false` sends no Anthropic `cache_control` and no OpenAI `prompt_cache_key`. `--no-cache-markers` can only turn it off. |
| `cache_min_block_tokens` | `null` | Force the Anthropic minimum cacheable prefix, in tokens, instead of the per-model table (Python's top-level `cache_min_block_tokens`). A positive whole number or `null`. |
| `cache_ttl` | `"5m"` | Anthropic cache lifetime: `5m` or `1h`. One-hour writes cost twice the base input rate instead of 1.25x and pay off only when the same prefix is re-read after more than five minutes; the run's cost report prices them at that rate. Inert on the OpenAI dialect. |
| `stream_large_responses` | `false` | Send any model call asking for at least **21,333** output tokens as a server-sent-event stream instead of one JSON response body. `--stream-large-responses` is the CLI equivalent; the flag can only turn it ON (a bare boolean flag has no "explicitly off" spelling), so a config that already enabled it always wins over the flag's absence. |

**What it changes, and what it does not.** The streamed pieces are
reassembled into exactly the response body a non-streaming call would
have returned, and that body is parsed by the same parser, so the text,
the tool calls, the token usage and the stop reason are identical either
way, and no stage can tell which mode ran. Per-call timeouts
(`stepN.timeout` / `--step-timeout`) still bound the whole stream, not
just its first byte, and the same-call parameter corrections
(`temperature` drop, `max_tokens` rename/clamp, and the rest listed in
[`llm-transport.md`](llm-transport.md#quirk-memory-learned-rejections))
still apply. Those corrections are now remembered per model for the
life of the process, so a rejection is paid once per model rather than
once per call.

**When to turn it on.** A 64,000-token generation sends nothing at all
until it finishes, which a gateway or proxy with its own idle timeout in
front of the provider may read as a dead connection. Streaming keeps
bytes flowing for the whole call. This port's per-call timeouts already
handle the client's own deadline (which is why streaming was not ported
initially), but they can do nothing about an intermediary's.

**Where 21,333 comes from.** It is the ceiling the official Anthropic SDK
itself refuses to send a non-streaming request above, derived from its own
10-minute default deadline. The Python original streams *unconditionally*
(`backends/sdk.py:288-289`, "Stream so large max_tokens (64k) doesn't trip
the HTTP timeout") and has no threshold of its own; adopting the SDK's
avoids streaming every small call for no benefit. In practice the stages
that clear it on default settings are the single-shot ones S2, S3, S4 and
S8 (all `max_tokens: 64000`); S1 (`16000`) stays on the single-response
path, and so do the agentic stages S6/S10/S11: an agentic turn is bounded
by `AgenticConfig`'s own 16,000-token ceiling, and `step6_verify` has no
`max_tokens` key at all.

```yaml
llm:
  stream_large_responses: true
  openai_api: auto        # chat | responses | auto
  cache_markers: true
  cache_min_block_tokens: null
  cache_ttl: 5m           # 5m | 1h
```

Every `llm.*` key is validated when the client is built: an unknown
`openai_api` or `cache_ttl`, a non-boolean `cache_markers` or a
non-positive `cache_min_block_tokens` fails the run rather than falling
back to a default, since each one changes what reaches the wire or what
the run costs. **Divergence from Python:** the two cache keys live under
`llm:` here, where Python reads them at the top level; a Python profile's
top-level `cache_markers: "off"` is not read by this port, so move it to
`llm.cache_markers: false`.

**Truncated replies (VVAH-E005).** Not a key, but transport behavior
every stage shares. A reply that stops because it hit its `max_tokens`
budget (OpenAI `finish_reason: length`, Anthropic `stop_reason:
max_tokens`) is sent once more at double the budget. If that reply is
cut off too, or the provider refuses the doubled budget with a 400
naming `max_tokens`, the call fails with a `[VVAH-E005] truncated LLM
response` error that carries the partial reply, rather than handing a
half-written JSON document to the parsers. It is not retried further and
does not stop the scan: the one chunk or session fails and is reported
as such. The doubled budget is uncapped on the single-shot stages (the
provider's own 400 marks the cap, as on the Python original's OpenAI
route); an agentic session can cap it with
`AgenticConfig::max_tokens_ceiling`, which has no config key yet. Before
this, the port passed a truncated reply through as if it were complete.

### `inject`: external context feeds

Not a stage: a top-level section naming two optional files whose contents
are stamped into the context package and rendered into S1/S2/S3's prompts
("Known CVEs already filed", the threat-model CVE block, "DO NOT
REDISCOVER", `DESIGN CONTROLS`). Ported from Python's own `inject:`
block; `--cve-file`/`--controls-file` override the keys.

| Key | Default | Notes |
|---|---|---|
| `cve_file` | *(none)* | JSON, either a bare `[...]` list or a `{"cves": [...]}` wrapper. A **relative** path resolves against the `--config` file's directory (`orchestrator/scan.py:210-211`), never the CWD or the scan target, because a profile ships its own `./inputs/known_cves.json` next to itself. |
| `controls_file` | *(none)* | YAML, either a bare list of mappings or a `{controls: [...]}` wrapper. Same resolution. |

A missing file injects nothing. A structurally broken one **warns and
injects nothing** rather than failing the scan, matching Python's
`[inject] WARN`-and-continue. This is deliberately unlike
a `--compliance-preset` selection, which fails hard on an unknown name
or malformed embedded policy, because a compliance policy can
DROP findings from the report while injected context can only cost the
model some prior knowledge.

Python's third `inject` key, `cmdb_csv`, has no equivalent here. This
port takes the CMDB export via `--cmdb-csv`/`--app-id` on the CLI
instead.

### `step_remediate`: Phase 2 (`--remediate`), S10

| Key | Default | Notes |
|---|---|---|
| `max_budget_usd` | *(not shipped)* | **Removed.** No `Step10Config` field; same reasoning as S6. Setting it warns. |
| `max_turns` | `40` | Agrees with `Step10Config::new()` (no drift). |
| `top_n_findings` | `20` | Fallback default for `--top` when `--top` isn't passed (see the "important" callout above re: this becoming an implicit cap the moment `--config` is used). Accepts an integer or the string `"all"`/`"*"`. |
| `enforce_policy` | *(none in `step_defaults.rs`)* | Only takes effect if you set it yourself; ORed with `--enforce-remediation-policy` (either one turns the policy gate on). |
| `policy_file` | *(none)* | The deny/allow-CWE + `deny_paths` + kill-switch YAML. A **relative** path resolves against the `--config` file's directory (`remediation_agent/policy/context.py:94-95`), never the CWD or the scan target. `--remediation-policy` wins when given. |
| `playbook_file` | *(none)* | Per-CWE fix-strategy YAML, same resolution. `--remediation-playbook` wins when given. |
| `syntax_check` | `true` | Roll the whole patch back if any touched file no longer parses. `--no-syntax-check` turns it off. |
| `keep_unverified` | `false` | Leave a patch applied even without a clean `Fixed` verdict. `--keep-unverified`. |
| `max_diff_lines` | `200` | Roll back a patch bigger than this (added+removed); `0` disables. `--max-diff-lines`. |
| `max_files_touched` | `1` | Roll back a patch touching more files than this; `0` disables. `--max-files-touched`. At the shipped `1`, a cross-file fix is never applied: the finding is reported and the refusal reason rendered with it, on the grounds that spanning files is a design decision a reviewer should make. |
| `dry_run` | `false` | Run every gate, roll everything back, keep the diff. `--remediate-dry-run`. |
| `verify_command` | `null` | A build/lint/test command run through `sh -c` in the repo root; non-zero exit or timeout rolls the patch back. Nothing runs unless set. `--verify-command`. |
| `verify_timeout_secs` | `600` | Wall-clock cap for the above. `--verify-timeout`. |
| `timeout` | *(none)* | Per-turn LLM deadline in seconds; no Python key. |
| `allowed_tools` | *(structural)* | List; falls back to `["Read", "Glob", "Grep", "Edit", "Write"]`. |

The seven safety-gate keys (`syntax_check`..`verify_timeout_secs`) have no
Python counterpart. S10's rollback gates are a Rust-side addition. See
`docs/remediation.md`.

`models.remediate` sets S10's model and sampling; see the roles table above.

### `step_validate`: Phase 3 (`--remediate`'s post-fix validation), S11

| Key | Default | Notes |
|---|---|---|
| `enabled` | `false` in `step_defaults.rs`, but effectively **`true`** unless *your own file* explicitly sets it. See the dedicated callout above. | `--validate`/`--no-validate` win over it. Deliberately ON by default although vvaharness v1.4.0 ships it off: S11 is what rolls back a patch it grades `Not Fixed`/`UNVERIFIABLE`. See `docs/validation.md`. |
| `effort` | `"high"` | **Wired**: the S11 panel's reasoning-effort tier (Python's `DEFAULT_EFFORT`, also `high` with no `--config`). `--reasoning-effort` overrides it, as `--step-timeout` overrides a `stepN.timeout`, and `models.validate.orchestrator.effort` overrides both. A value that names no tier fails the run at startup. |
| `max_turns` | `50` | Agrees with `Step11Config::new()` (no drift). |
| `max_budget_usd` | *(not shipped)* | **Removed.** Same reasoning as S6 and S10. Setting it warns. |
| `max_findings` | `20` | **Wired** (this doc previously said "Dead"): caps in-scan validation to the top-N validatable findings by CVSS, via `Step11Config::max_findings` and `bc_orchestrator::remediate`. `0`/absent validates every validatable finding. |
| `cross_repo_analyzer` | *(none)* | Opt in to the third validator persona. See the section above. |
| `timeout` | *(none)* | Per-turn LLM deadline in seconds; no Python key. |
| `allowed_tools` | *(structural)* | List; falls back to `["Read", "Glob", "Grep", "DiffTouched", "ChangedLines", "DiffImpactMap", "PatternScan", "TestInventory"]`, the three readers plus the five deterministic fact tools, matching Python's `DEFAULT_FACT_TOOLS`. Read-only by construction: S11 is never given `Edit`/`Write`/`Bash`. Setting this **replaces** the list, it does not merge. |
| `split_ties_score` | `true` | Whether a two-way persona tie one step apart (`pass`/`partial`, `partial`/`fail`) is scored as `SPLIT`, the conservative status standing (`true`, this port's behavior), or flagged so the whole fix is `UNVERIFIABLE`, as vvaharness does for every tie (`false`). Part of the S11 `--resume` checkpoint key. See `docs/validation.md` § Synthesis. |
| `fact_tools` | `true` | Whether the five deterministic fact tools are offered at all. No Python counterpart (Python hardwires them on); this is an escape hatch for a model that handles an 8-tool schema badly. Setting it `false` also strips the five names back out of `allowed_tools` before the panel runs, so it stays a one-key change. See `docs/validation.md`. |

`models.validate.orchestrator` (or the flat `models.validate`) sets S11's
model and panel-wide sampling; see the roles table above.

## `config.local.yaml`: local overlay

Place a `config.local.yaml` next to your `--config` file (same directory,
exact filename) to layer developer-local overrides on top without editing
the checked-in file, for example a looser `min_confidence` or a different
`models.deepdive.id` while iterating. It's picked up automatically;
there's no separate flag to point at it. Set `BC_NO_LOCAL_CONFIG`
(non-empty) to ignore it for one run. This is useful for CI, where a
stray local file shouldn't silently change behavior.

Remember `deep_merge` replaces arrays and non-object scalars outright: a list
key set in both `config.yaml` and `config.local.yaml` ends up as whichever
one `config.local.yaml` set, not their union.

### Trust check

Because the overlay is implicit and can change security-relevant keys
(model routing, `allowed_tools`, `step_remediate.verify_command`), it is
merged only when it could not have been planted by someone else
(`crates/bc-config/src/overlay.rs`, ported from upstream v1.3.0). On
Linux and macOS it must be:

- a **regular file**, not a symbolic link (a link could point at a file
  another user controls; Python follows links, this port refuses them),
- **owned by the invoking user** (the effective uid) **or root**, and
- **not group- or world-writable** (`chmod go-w config.local.yaml`).

Anything else fails the load with `config overlay ... is not trusted:
<reason>`, the same kind of hard error as a YAML parse error. The trust
facts are read from the open file handle that is then read, and checked
against the directory entry, so the file cannot be swapped between the
check and the read. `BC_NO_LOCAL_CONFIG` is honored *before* the check,
so it always gets you past an overlay you cannot fix right now. Watch
for a `umask` of `002` (common on distributions with per-user groups):
it creates files group-writable, which this check refuses.

On Windows there are no POSIX owner and mode bits to check. The overlay
is merged unchecked, as in Python, and the banner below says `ownership
unverified`.

### The overlay banner

When an overlay is merged, `bc-sast` prints one line to stderr naming it
and every leaf key it overrides, once per overlay file per run however
many times `--config` is re-read (a batch run announces it once, not per
repository):

```
  [config] config overlay: /cfg/config.local.yaml applied (overrides:
  models.deepdive.id=claude-opus-4-6, step1.max_turns,
  step_remediate.verify_command (set))
```

How much of each value appears depends on what the key could hold:

| Key | Shown as |
|---|---|
| a credential-like name (`*api_key*`, `*token*`, `*password*`, `*auth`, ...) or a `*command` key such as `step_remediate.verify_command` | `key (set)` or `key (unset)` only |
| a URL value, or a key ending in `url`/`endpoint` | `key -> host[:port]`: never the userinfo, path or query, and `(no host)` when the URL is ambiguous |
| `models.<role>.id` (or a flat `models.<role>: <id>`), `pricing.provider`, `step_remediate.enforce_policy`, any `allowed_tools`, and the TLS keys `verify_ssl`/`ca_cert`/`client_cert`/`no_proxy`/`cache_route` | `key=value` (cut at 120 characters) |
| everything else | the key name only, as in Python |

Python shows only the key name for its model and tool keys; this port
shows their values because the point of the banner is to make a changed
model or tool permission visible. A skipped overlay is announced too
(`present but SKIPPED (BC_NO_LOCAL_CONFIG set)`). The line is printed with
`eprintln!` rather than through `tracing`, like the other pre-scan config
notices, so it appears on an interactive terminal without `--log-stderr`.

## Minimal worked example

```yaml
# config.yaml: keep this file OUTSIDE the directory you pass to --repo,
# or set BC_ALLOW_CWD_CONFIG=1 (see "trust boundary" above).

models:
  # Spend more on the deep-dive finding-generation pass than the global
  # --model default gives every other stage.
  deepdive:
    id: claude-opus-4-6

step1:
  exclude_dirs:
    - vendor
    - generated
  max_turns: 60          # large repo; the built-in 40 wasn't enough turns

step6_verify:
  min_confidence: 8       # stricter than the built-in 7; only very
                           # confident TRUE_POSITIVEs make it into the report
```

Run it with:

```
bc-sast --repo ./target --config ./config.yaml --model gpt-5.6-luna \
  --gateway-base-url "$BC_GATEWAY_BASE_URL" --gateway-api-key "$BC_GATEWAY_API_KEY"
```

Every field this file doesn't mention keeps its `step_defaults.rs` value (or,
for structural keys, each stage's own built-in default). You never need to
restate settings you're happy with.

## Adjacent mechanism not currently exposed via any flag

`bc_config::apply_step1_overlay` (`crates/bc-config/src/lib.rs`) implements a
separate, `append_merge`-based per-scan overlay onto `step1` specifically
(list keys like `exclude_dirs` *append* rather than replace, and it refuses a
network/UNC path outright). It's fully implemented and unit-tested inside
`bc-config`, but as of this codebase there is no `--step1-config` (or any
other) CLI flag in `crates/bc-cli` that calls it. Grep confirms
`apply_step1_overlay` has no callers outside `bc-config`'s own tests. Treat it
as dead/unreachable from the `bc-sast` binary today, not a documented user
feature; if a future CLI flag wires it up, it uses different merge semantics
(append, not replace) than everything described above.
