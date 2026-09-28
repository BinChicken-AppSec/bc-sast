# LLM transport: APIs, model capabilities and prompt caching

This page describes what the two dialect crates (`bc-llm-openai`,
`bc-llm-anthropic`) put on the wire, and why. It covers the OpenAI
Responses API and the learned fallback to Chat Completions, the
per-model capability table that decides which parameters are sent, the
reactive "quirk memory" behind it, prompt caching on both providers, and
how cached tokens are priced. The next section says how to select each
behavior from the CLI; the full key reference is
[`configuration.md`](configuration.md), and the library APIs the flags
map onto are named throughout.

## Selecting it from the CLI

`bc-cli` builds ONE client for every stage (`build_llm_stack`): an
`OpenAiClient` or `AnthropicClient`, wrapped in `ApplyCachePolicy` and,
when streaming is on, `StreamLargeResponses`. Each setting resolves flag
first, then the `--config` key, then the default.

| What | Flag (env) | Config key | Default | Library API |
|---|---|---|---|---|
| OpenAI API shape, client-wide | `--openai-api chat\|responses\|auto` (`BC_OPENAI_API`) | `llm.openai_api` | `auto` | `OpenAiClient::with_api` |
| OpenAI API shape, one role | none | `models.<role>.use_responses_api` (bool) | client-wide | `ChatRequest::openai_api` via the stage config |
| Reasoning effort, every role | `--reasoning-effort <tier>` | none | provider default (S11: `high`) | `ChatRequest::reasoning_effort` / `AgenticConfig::reasoning_effort` |
| Reasoning effort, one role | none | `models.<role>.effort` (wins over the flag) | the flag | as above |
| S11 panel effort | `--reasoning-effort` (wins) | `step_validate.effort` | `high` | as above |
| Cache kill switch | `--no-cache-markers` (can only turn off) | `llm.cache_markers` | `true` | `CachePolicy::markers` |
| Anthropic cache minimum | none | `llm.cache_min_block_tokens` | per-model table | `CachePolicy::min_block_tokens` |
| Anthropic cache lifetime | none | `llm.cache_ttl` (`5m`\|`1h`) | `5m` | `CachePolicy::ttl`, and `PricingConfig::cache_ttl` for the cost report |

**The CLI default is `auto`, not the library's `chat`,** because the
default `--model` (`gpt-5.6-luna`) is a reasoning model, which on Chat
Completions keeps no reasoning across tool calls and is refused function
tools at a non-`none` effort. `auto` sends known reasoning families to
the Responses API and everything else (including `gpt-4o`) to Chat
Completions, so pinning `chat` is only needed for a gateway that
mishandles `/responses` in a way the fallback below cannot detect.

A malformed value in any of these (an unknown tier or API, a `cache_ttl`
of `2h`) fails the run at startup instead of silently falling back.

**Startup model gate.** Before any token is spent, every configured model
id is looked up with `capabilities::lifecycle`: a retired one stops the
run (unless `--allow-unsupported-model`), a deprecated or legacy one
warns once, and an unknown one passes silently. `--doctor` prints each
model's `ModelCapabilities::render` row, and `--doctor --cache-probe`
runs the live cache diagnostic described at the end of this page.

**Run manifest.** Each role's `transport` in `run_manifest.json` is its
pin, else the client-wide choice (`messages` on the Anthropic dialect),
and `counters.responses_fallbacks` is
`LearnedModels::responses_fallbacks()` at the end of the run. See
[`outputs.md`](outputs.md).

## OpenAI: Chat Completions or the Responses API

`bc-llm-openai::OpenAiClient` speaks either OpenAI API shape, chosen by
`bc_llm_client::OpenAiApi`:

| Value | Endpoint | Falls back? |
|---|---|---|
| `chat` (library default) | `POST {base}/chat/completions` | never |
| `responses` | `POST {base}/responses` | never |
| `auto` | per model, see below | yes, on shape evidence only |

The client-level choice is `OpenAiClient::with_api(api)`. A single
request can pin its own with `ChatRequest::openai_api` (the Python
original's per-role `use_responses_api`: `true` pins `responses`, `false`
pins `chat`, via `OpenAiApi::from_use_responses_api`). The request pin
always wins over the client setting.

**Why the Responses API matters.** On Chat Completions a reasoning model
keeps no chain of thought across tool calls, and newer ones reject
function tools with reasoning on at all ("Function tools with
reasoning_effort are not supported ... use /v1/responses"). The initial
port answered that rejection by setting `reasoning_effort: "none"`, so
every agentic stage on a GPT-5.x model ran with reasoning switched off.
The Responses API carries reasoning across turns as `reasoning` output
items, which this port keeps as `ContentBlock::Opaque` blocks and
replays on the next turn.

### What a Responses request looks like

```json
{
  "model": "gpt-5.6-luna",
  "instructions": "<system prompt>",
  "input": [
    {"role": "user", "content": "<cache prefix><first user turn>"},
    {"type": "reasoning", "id": "rs_...", "encrypted_content": "..."},
    {"type": "function_call", "call_id": "call_1", "name": "Read", "arguments": "{...}"},
    {"type": "function_call_output", "call_id": "call_1", "output": "..."}
  ],
  "tools": [{"type": "function", "name": "Read", "description": "...",
             "parameters": {...}, "strict": false}],
  "max_output_tokens": 16000,
  "reasoning": {"effort": "high"},
  "store": false,
  "include": ["reasoning.encrypted_content"],
  "prompt_cache_key": "<32 hex chars>"
}
```

`seed` and `stream_options` are never sent (the Responses API has
neither). `json_mode` becomes `text: {"format": {"type": "json_object"}}`,
and `max_output_tokens` is never below 16, the API's own floor.

**Security: `store: false`.** Every Responses request asks OpenAI to keep
nothing server-side, so no prompt and no scanned source outlives the call
there. The cost is that the server cannot look earlier reasoning up by
id, so the request asks for `reasoning.encrypted_content` and each
reasoning item is replayed verbatim (id included, as OpenAI's stateless
guidance does) with its ciphertext. A reasoning item that arrives without
`encrypted_content` (only possible through a gateway that strips it) is
dropped rather than replayed, since its bare id would make the next call
fail with "item not found".

The response's `output` items map back as: `message` / `output_text` to
text; `function_call` to a tool call keyed by `call_id`; `reasoning` to
an opaque block; a `refusal` with no other answer to
`LlmError::GuardrailBlocked` (the same error the Anthropic dialect raises
for a refusal, so S6's refusal gate counts both). `status: "incomplete"`
with reason `max_output_tokens` is `StopReason::MaxTokens`; any other
incomplete reason is `StopReason::Other`; `status: "failed"` is classified
through the same error classifier as an HTTP failure. Streamed calls read
the terminal `response.completed` / `response.incomplete` event (which
carries the whole response), fall back to the `response.output_item.done`
items when a gateway forwards the terminal event without its output, and
report a stream cut off before either as `incomplete`, never as a
complete answer.

### `auto`: which API first, and the learned fallback

`auto` resolves per model, per process:

1. A model this process has learned to be Chat-Completions-only goes to
   Chat Completions; one proven on the Responses API goes there.
2. Otherwise a known reasoning family (GPT-5.x, GPT-6, the o-series, per
   the capability table below) starts on the Responses API, and
   everything else (gpt-4o, gpt-4.1, `*-chat-latest`, and any name the
   table does not know) starts on Chat Completions.

Then, within one call:

- **Responses first, falls back to Chat Completions** only on evidence
  about the request SHAPE: HTTP 404, 405 or 501 from `/responses`; a 400
  saying an unknown or unsupported parameter and naming `input`,
  `instructions`, `store`, `include` or `max_output_tokens` (after the
  same-call corrections below had their chance); or a 2xx whose body has
  no `output` array. The model is then remembered as Chat-only, a warning
  is logged once per model, and `LearnedModels::responses_fallbacks()`
  counts it for the run manifest. A model already proven on the
  Responses API does not fall back on a missing `output` alone.
- **Chat Completions first, moves to Responses** when Chat Completions
  answers with the "use /v1/responses" rejection. A reasoning model
  behind a gateway alias therefore reaches the right endpoint after one
  rejected call, and is remembered as proven.
- **If the second API also fails**, whatever was learned is undone and
  the ORIGINAL error is returned: an outage on both endpoints proves
  nothing about either.

A pinned `chat` or `responses` never switches. Pinned `chat` keeps the
historical answer to the "use /v1/responses" rejection: it retries with
`reasoning_effort: "none"` and logs a warning suggesting `auto`.

**Divergence from Python, deliberate.** The Python original falls back on
ANY error from a model's first Responses call. A 429, a 5xx or a timeout
on that single call would then flip the model to Chat Completions for
the rest of the process, silently running a reasoning model without its
reasoning, on a transient fault. Here retries live above the client
(`bc-llm-agentic`), so transient errors reach them unchanged and never
trigger a fallback. Python also sends every OpenAI model to the Responses
API first; starting known non-reasoning models on Chat Completions avoids
a guaranteed wasted call through gateways that do not route `/responses`.

## Reasoning effort

`ChatRequest::reasoning_effort` takes `bc_llm_client::ReasoningEffort`:
`none`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`. It parses
from the config spelling (case-insensitively); an unknown value is an
error rather than the Python original's silent "provider default".

- OpenAI Chat Completions: `reasoning_effort: "<tier>"`.
- OpenAI Responses: `reasoning: {"effort": "<tier>"}`.
- Anthropic: `output_config: {"effort": "<tier>"}` together with
  adaptive thinking on models that support it; see below.

A tier the model does not support is clamped to the nearest supported
tier at or below it (or the lowest supported tier if none is below), and
the change is logged once per model. A model that takes no effort at all
gets none.

## Model capabilities

`bc_llm_client::capabilities` holds a per-family table of what each
model accepts, looked up by a normalized id: lower-cased, with gateway
path prefixes (`openrouter/anthropic/...`), Bedrock region, vendor and
version decorations (`us.anthropic....-v1:0`), Vertex snapshots
(`...@20250929`) and trailing dates removed, then matched by the longest
family prefix. A prefix followed by what reads as a newer minor version
does not match (`gpt-5` does not claim `gpt-5.1`), so an unreleased model
is treated as unknown rather than as its predecessor.

For each family the table records the lifecycle (current, legacy,
deprecated with a retirement date, retired), which sampling parameters
are accepted (all, `temperature` or `top_p` but not both, only when
effort is `none`, or none), the effort tiers and default tier, the
Anthropic thinking mode, the output-token ceiling, the minimum cacheable
prefix, and whether forced `tool_choice` and assistant prefill are
accepted. Every request builder consults it before sending:

- `temperature`, `top_p` and `seed` are dropped for models that reject
  them, including GPT-5.x at its default (non-`none`) effort. For
  example `--temperature 0` on `gpt-5.6-luna` without an effort is
  dropped with a warning, and kept with effort `none`.
- Effort is clamped as above; `max_tokens` is capped at the published
  ceiling.
- On Anthropic, `temperature`/`top_p` are also dropped whenever the model
  will think on the request (the Messages API rejects them alongside
  thinking), and sampling is dropped entirely on the models that reject
  it (Opus 4.7 and later), where `--temperature 0` used to be a 400.

**Unknown models are never refused.** A name the table does not know
(gateways routinely alias models) gets a permissive row: every parameter
the caller asked for is sent, and the quirk memory below learns what the
model rejects. OpenAI rows the research could not confirm (effort tiers
for GPT-5.2 and 5.3, `max` on GPT-5.6 and GPT-6) are marked as inferred
in the table.

`capabilities::lifecycle(model)` returns the date-adjusted lifecycle (a
deprecation whose retirement date has passed is `Retired`), and
`ModelCapabilities::render(model, today)` one line describing the row,
for a startup model gate and `--doctor` output.

### Anthropic thinking

| Model generation | Sent for a thinking or effort request |
|---|---|
| up to 4.5, and unknown models | `thinking: {"type": "enabled", "budget_tokens": N}` with N inside the API's bounds (1,024 or more, below `max_tokens`) |
| Opus 4.6, Sonnet 4.6 | `{"type": "adaptive"}` plus `output_config.effort` when an effort is set; a bare budget keeps the (deprecated, still accepted) budget form |
| Opus 4.7, 4.8 | `{"type": "adaptive"}` only (the budget form is a 400); a budget becomes adaptive with a warning |
| Opus 5, Sonnet 5, Fable 5.x, Mythos 5.x, Opus 5.5 | thinking is on by default (always on for the last three): `{"type": "adaptive"}` when effort or a budget is requested, nothing otherwise; effort `none`/`minimal` becomes `low` |

`stop_reason: "refusal"` is reported as `LlmError::GuardrailBlocked`.
`thinking` and `redacted_thinking` blocks are kept, signature included,
and replayed unchanged on the next turn of a tool loop, which the API
requires when thinking and tool use are combined.

## Quirk memory: learned rejections

Whatever the table gets wrong is corrected reactively, once per model per
process. On a 400 naming a parameter the model rejects, the client
corrects the body, resends, and applies the same correction to every
later request for that model, so a stage making hundreds of calls pays
for one rejection, not hundreds. Ported from the Python original's
`_NO_TEMP_MODELS`, `_USE_LEGACY_MAXTOK`, `_NO_CACHE_KEY_MODELS` and
`_NO_REASONING_EFFORT`.

- OpenAI (`bc_llm_openai::quirks`, per client, shareable across clients
  with `OpenAiClient::with_learned_models`): `temperature`, `top_p`,
  `seed` and `prompt_cache_key` dropped; `max_completion_tokens` swapped
  for the legacy `max_tokens` (and back); a reported output ceiling
  ("supports at most N completion tokens") clamped and remembered; a
  rejected effort tier stepped down one tier (`max` to `xhigh` and so on)
  rather than dropped, so a request for `max` still runs at the highest
  tier the model has.
- Anthropic: `temperature` (the existing per-client memo), plus `top_p`,
  `output_config` and `thinking` (a rejected budget becomes adaptive when
  the error says so, otherwise thinking is dropped).

Each call makes at most six OpenAI or four Anthropic corrections, each
removing or lowering the key it acts on, so a server that keeps
rejecting cannot drive a loop.

## Prompt caching

The operator policy is `bc_llm_client::CachePolicy`, stamped on every
request by the `bc_llm_client::ApplyCachePolicy` wrapper where the client
is built (stages never set it):

| Field | Default | Meaning |
|---|---|---|
| `markers` | `true` | The kill switch (Python's `cache_markers: off`). `false` sends no Anthropic `cache_control` and no OpenAI `prompt_cache_key`. |
| `min_block_tokens` | none | Force the Anthropic minimum cacheable prefix instead of the per-model table (Python's `cache_min_block_tokens`). |
| `ttl` | `5m` | Anthropic cache lifetime: `5m` or `1h` (`{"type": "ephemeral", "ttl": "1h"}`). |

Two per-request fields carry what only a stage knows:

- `ChatRequest::cache_prefix`: a large, stable leading prefix shared by
  many calls (S4's shared context plus one shard's source).
- `ChatRequest::cache_key`: stable routing material for OpenAI's
  `prompt_cache_key` (stage and repository name, say). It must not carry
  secrets, and it is never sent raw.

### What the stages send

Every LLM stage sets a constant `cache_key` naming itself: `s2`, `s3`,
`s6` (every turn of each verifier session), `s7` and `s8`. Only
constants go in, never a repository path or content; the transport
hashes the key with the model anyway.

S4 is the one stage that also sets `cache_prefix`, ported from upstream
v1.4.0 `s4_deepdive.py` (`crates/bc-stage-s4/src/prompt_layout.rs`):

| Chunk | `cache_prefix` | User text | `cache_key` |
|---|---|---|---|
| Risk, catch-all, taint (discover), threat fallback | shared context block, then a blank line | research lens, chunk header, CVEs, compliance guidance, SOURCE CODE | `s4:shared` |
| Specialist lens on a shard (`Chunk.shard_id`) | shared context block, a blank line, then `SOURCE CODE:` and the shard's code | the same, minus SOURCE CODE | `s4:<shard_id>` |
| Taint under `taint_prompt_mode: confirm_refute` | none | the confirm/refute prompt | `s4:shared` |

The shared context block
(`crates/bc-stage-s4/src/shared_context.rs`) is rendered once per scan and
is byte-identical for every chunk: the CMDB application profile, the
threat model capped at 4,000 characters of system context, 10 assets, 15
trust boundaries and 25 threats, an entry-point inventory sorted by file
and function and capped at 60 (with an omitted-count line), and the trust
rule. It replaces the older, shorter `TRUST CONTEXT` block in the
open-ended prompt; the confirm/refute prompt keeps that block (a
deliberate divergence: upstream dropped it there as a side effect of the
move). The non-shard prefix is a byte prefix of every shard prefix, so an
implicit prefix cache can share the context across both.

Every lens on one shard assembles the same code (loading reads only the
shard's files, size, focus entry points and taint fields, which S3 copies
to each lens), so their prefixes match byte for byte. To stop them all
writing that prefix at once, S4 holds each lens until the shard's first
lens has returned (`step4.shard_cache_gating`, see
[`configuration.md`](configuration.md)). The JSON repair re-ask drops the
prefix: it carries the broken reply, not the chunk.

Token counts for every gate are estimated at one token per four
characters, scaled by a 1.35 margin (Python's `CACHE_EST_MARGIN`) so a
block whose estimate is within the estimator's own error of a minimum is
still marked: refusing a cacheable block re-bills its whole prefix on
every later call, while an inert marker only wastes a free slot.

### Anthropic breakpoints

At most one breakpoint of each kind, in rendering order, so never more
than Anthropic's limit of four:

1. the last tool definition (identical on every turn of an agentic
   session);
2. the system prompt;
3. the cache prefix, sent as its own leading text block in the first
   user turn;
4. the last content block of the latest user turn, on multi-turn
   requests only (never a thinking block).

Each is placed only when the kill switch is on and the prefix up to that
point (tools, then system, then messages) clears the model's minimum
cacheable size: 512 tokens on Opus 5 and Fable 5, 1,024 on Sonnet 4.x,
Opus 4.8 and earlier Opus 4, 2,048 on Opus 4.7, 4,096 on Opus 4.5/4.6
and Haiku 4.5, and 4,096 for an unknown model. Below the minimum the API
caches nothing but still spends the slot. This is a change from the
initial port, which marked the system block unconditionally.

**Divergence from Python, deliberate.** `sdk.py` also withholds markers
from any base URL it cannot recognize as Anthropic, Vertex or Bedrock.
This port has no such host sniff: the operator already declares the
dialect (`--dialect anthropic`), and a gateway that is not
Messages-compatible fails on far more than a marker. The kill switch
covers a strict gateway that rejects `cache_control` specifically.

### OpenAI implicit caching

OpenAI caches any prompt of at least 1,024 tokens whose leading bytes
match a recent request's. So the cache prefix is prepended to the first
user turn (the stable part must come first), and `prompt_cache_key` is
sent only when the prompt is estimated above that floor. The key is the
first 32 hex characters of SHA-256 over the caller's `cache_key`, the
model, and a digest of the cache prefix when there is one, so calls that
can hit each other's cache share a key and nothing identifying leaves
the process. A gateway that rejects `prompt_cache_key` has it dropped
and remembered for the model.

**Divergence from Python, deliberate.** Python derives the key material
itself and spreads prefix-less traffic over an eight-way shard ring to
stay under OpenAI's per-key rate guidance. Here the caller supplies the
material, and a fan-out stage that wants sharding appends its own shard
suffix.

## Token accounting and pricing

`bc_llm_client::Usage` has one contract across both dialects and both
OpenAI shapes: `input_tokens`, `cache_read_input_tokens` and
`cache_creation_input_tokens` are disjoint slices of the prompt and add
up to its whole size. Anthropic reports exactly that
(`cache_creation_input_tokens` being both lifetimes together, summed from
the `cache_creation` split when a gateway forwards only that). OpenAI
reports the whole prompt (`prompt_tokens` or `input_tokens`) with the
cached subset (`*_tokens_details.cached_tokens`) and, on models that
bill one, a cache write (`cache_write_tokens`) underneath; both slices
are subtracted out.

`bc-pricing` rates each slice at its own rate from the vendored
models.dev table: cache reads at the published cached-input rate
(Anthropic 0.1x input, 0.025x on Fable 5.1; OpenAI 0.1x to 0.5x depending
on the model), five-minute cache writes at the published write rate
(Anthropic 1.25x input). One-hour writes bill at twice the input rate,
which the catalog does not carry, so `bc_pricing::Call` takes them
separately with `long_ttl_cache_writes(tokens)`; every marker in one
request carries the same TTL, so a request sent with `ttl: 1h` wrote all
its cache tokens at that lifetime. A model the table publishes no cache
rate for leaves cached tokens unrated (reported, not priced as free and
not priced at the input rate).

The scan's cost report applies this through
`bc_orchestrator::pricing::PricingConfig::cache_ttl`, which `bc-cli`
sets from `llm.cache_ttl` on the Anthropic dialect only (OpenAI has no
lifetime to choose), so a run with `cache_ttl: 1h` bills every cache
write at the one-hour rate.

## Cache probe

`bc_llm_client::classify_cache_probe` is the pure half of a live
prompt-cache diagnostic, ported from the Python original's
`doctor --cache-probe`, and `bc-sast --doctor --cache-probe` is the
live half: it sends, through the real configured client (cache policy
included) and against `--model` only, two calls sharing the deterministic
`cache_probe_filler(CACHE_PROBE_FILLER_MIN_TOKENS)` system prompt with
the distinct user turns `CACHE_PROBE_USER_A` and `CACHE_PROBE_USER_B`,
then classifies the pair's usage into one of the Python original's verdicts
(`anthropic_works`, `anthropic_write_ok_read_fails`,
`anthropic_marker_not_honoured`, `anthropic_works_prefix_already_cached`,
`openai_implicit_working`, `openai_below_minimum_or_unstable`,
`no_cache_fields_treat_as_implicit`, and
`anthropic_marker_withheld_by_gate` when this tool's own gate placed no
marker). Each verdict has an operator-facing explanation, which
`--doctor` prints with the two calls' cache write and read counts. The
probe runs only after the ordinary live probe reached the model, spends
real tokens (about 20,000 prompt tokens across the two calls, each
capped at 256 output tokens) and says so in its output. A probe that
cannot reach a verdict makes `--doctor` exit non-zero; any verdict,
"not caching" included, is a finding rather than a failure.

**Divergence from Python, deliberate.** Python probes every configured
role's model, with two filler shapes (the synthetic filler and the
deep-dive system prompt) and two thinking arms each. This port probes
`--model` once, with the synthetic filler and no thinking override:
one pair of calls answers the question the probe exists for (does this
route cache at all), at a quarter of the spend.
