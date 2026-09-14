# Remediation (`--remediate`, stage S10)

Stage S10 (crate `bc-stage-s10`) is BC Agentic SAST Harness's optional
write-capable step: given a scan's ranked findings, it walks a selected
subset one at a time and attempts an actual code fix via an agentic
Read/Glob/Grep/Edit/Write tool loop. It runs only as part of a
`bc-sast --remediate` **or** `--remediate-from` invocation (the two are
mutually exclusive). There is no standalone `remediate` subcommand.

For the full security posture of this stage (not just "what it does", but
where the gaps are), see
[`docs/compliance/AI_AGENT_SECURITY_REVIEW.md`](compliance/AI_AGENT_SECURITY_REVIEW.md)
and [`docs/compliance/CONTROL_MAPPING.md`](compliance/CONTROL_MAPPING.md)
§9. This doc describes the mechanism; that one grades it.

## Enabling it

Remediation is opt-in, per invocation, via a single CLI flag:

| Flag | Field | Default | Notes |
|---|---|---|---|
| `--remediate` | `remediate: bool` | `false` | Bare `--remediate` = `true`; also accepts an explicit value (`--remediate false`) so `action.yml` can always pass it. |

There is **no `step_remediate.enabled` key**. The config section tunes
an already-enabled run (its model, turn cap, allowed tools, every safety
gate below, `top_n_findings`, `enforce_policy`, and the policy/playbook
paths) but cannot start one. Only `--remediate` or `--remediate-from`
does that. A no-op if the scan doesn't reach a `FinalReport`.

Every finding is processed **strictly sequentially**, never
concurrently, a deliberate choice, since concurrent agents with
Edit/Write on the same working tree would race on file contents, git
state, and diff capture.

## Mode: always fix mode today

`Step10Config::new()` hardcodes `fix_mode: true`, and the prompt
(`bc-stage-s10/src/prompts.rs`) branches on it to render either "apply
the minimal safe fix" or "describe the minimal safe fix (do NOT edit
files)." Report-only mode is now **structural as well as textual**:
`effective_tools()` strips `Write`/`Edit` from the request itself when
`fix_mode` is false, so the model is not merely asked not to edit, it is
not given the means. But **no CLI flag or config key in this port ever
sets it to `false`** outside of unit tests. In practice, `bc-sast --remediate` gives S10 write access to the selected
remediation workspace, subject to the gates below. That workspace is an
isolated worktree or ZIP snapshot when those modes are active.

`step_remediate.dry_run` is the nearer-term answer for "show me the
patch without keeping it": the agent edits normally, every gate runs, and
then everything is rolled back while the diff is kept in the record (so
`--out-remediation-json` / `--post-fixes-from` still produce PR fix
suggestions).

The tool set offered to the agent is `[Read, Glob, Grep, Edit, Write]`
(`Step10Config::new()`'s default, overridable via
`step_remediate.allowed_tools` in a loaded config). Bash is never in
the default set. The session dispatcher rejects tools that were not advertised for that
session, even if the executor implements them. `Edit` and `Write` resolve
paths inside the repository jail and reject Git control paths, including
aliases. The journal captures the existing bytes under the actual canonical
repository-relative path before mutation and passes that resolved identity
to the tool. An unreadable baseline or ambiguous path refuses the write.
These controls apply independently of the optional remediation policy gate.

## Remediating without rescanning (`--remediate-from`)

`--remediate-from <findings.json>` reads a prior run's
`--out-findings-json` export and remediates those findings directly. No
pipeline stage runs at all. Everything below applies unchanged: finding
selection, the agentic loop, the safety gates, worktree isolation, the
policy gate, `--resume`, and S11 validation.

Two details worth stating:

- **Severity is reconstructed, not stored.** The export carries bare
  `Finding`s, and `--top N` ranks by CVSS with a severity-band fallback,
  so a wrong severity here remediates the wrong findings. It is rebuilt
  with `bc_stage_s8::final_severity`, the same function S8 used when it
  assigned the severity originally, reading the same
  `vsvs_rating`/`cvss_rating` bands the export carries.
- **The staleness refusal is not re-implemented.** The report's
  `git_sha` is set from the export's `commit_sha`, so
  `bc_orchestrator::remediate`'s existing check compares it against the
  repository's current HEAD exactly as it does after a live scan.
  `--force` overrides it the same way.

`report.md`/`report.sarif` **are** augmented in place in this mode when
they exist, looked for at `--out-md`/`--out-sarif` when given, else the
repo's own `security-scan/` defaults. They are appended to, never
re-rendered: `report.md` gains a `#### Remediation` block per remediated
finding, a `#### Validation` block per graded one, and a report-level
`## Remediation Summary`; `report.sarif` is re-stamped with
`remediationStatus`/`validationStatus` and friends, matched by
`bc/findingId/v1` rather than by position. A report that already carries
a remediation section is left alone rather than given a second,
contradicting one, and a missing prior report is reported on stdout, not
an error. `--out-remediation-json` and (in worktree mode)
`security-scan/remediation.patch` are this mode's other output. See
`USER_GUIDE.md` §1h.

This is the closest thing this port has to the Python original's
standalone `vvaharness remediate` command, without its mechanism: Python
re-parses its own rendered Markdown report to recover findings, which
this port never does (see `bc-stage-s10`'s crate doc comment). A typed
export round-trips exactly instead.

## Finding selection

| Flag | Field | Default | Effect |
|---|---|---|---|
| `--top <N\|all\|*>` | `top: Option<String>` | `None` | Caps remediation to the N highest-CVSS findings; `all`/`*` remediates every finding, overriding a config default. |
| `-i`, `--interactive` | `interactive: bool` | `false` | Arrow-key (or numbered-prompt fallback) picker instead of the automatic batch walk. Shows the full findings list, ignoring any profile `top_n_findings` default, unless `--top N` is *also* given explicitly on the same invocation. |

Config-side default: `step_remediate.top_n_findings` (numeric or
`"all"`/`"*"`), consulted only when `--top` is absent. **This port ships
no default profile at all**, so with neither `--top` nor `--config`,
remediation is uncapped: every finding gets attempted.

The corollary matters: passing **any** `--config` at all applies the
merged default `top_n_findings: 20`, even a file that never mentions
`step_remediate`, because `bc_config::load` always deep-merges
`step_defaults()` underneath whatever it loads. An uncapped run therefore
needs either no `--config` or an explicit `--top all`.

Ranking (`bc-stage-s10/src/select.rs`, `select_top_by_cvss`): a
max-heap keyed by each finding's numeric CVSS base score, falling back
to a severity-band score when no numeric score is available:

| Band | Score |
|---|---|
| CRITICAL | 9.0 |
| HIGH | 7.0 |
| MEDIUM | 4.0 |
| LOW | 1.0 |
| INFO / unrecognised | 0.0 |

Ties break by stable original (scan) order, smaller index first.

### The `--diff-scope` boundary

Selection ranks by severity and knows nothing about the pull request, so
it is not what keeps remediation inside the diff. S10 does, with a hard
refusal of its own.

When the run is diff-scoped, **any finding whose file is not among the
pull request's changed files is refused before the agent is called** and
before anything is snapshotted. The refusal is recorded, never silent: the
record carries the policy action `out_of_diff_scope`, the reason naming
the file and the flag, and a `Denied` verdict whose summary reads
`Out of diff scope (...)` rather than the policy gate's
`Denied by policy (...)`, so an audit can tell the two apart. Nothing is
written to disk, nothing is checkpointed (a refusal is not work done, so a
later run re-evaluates it), and S11 has no diff to validate.

The check lives on the S10 config every route into the loop has to build,
so it holds on all of them:

| Route | Where the boundary comes from |
|---|---|
| Batch `--top` walk (`--remediate` after a scan) | The pull request diff the scan itself fetched |
| `-i` / `--interactive` picker | The same, threaded through the same config |
| `--remediate-from` (prior-report remediation) | Its own `--diff-scope` fetch, with the same `--github-token`/`--github-repo`/`--pr-number` requirement and the same fail-hard-on-fetch-error posture. Previously the flag was accepted here and silently ignored |
| A direct `bc_stage_s10::remediate_finding` call | The config it is handed |

Two details worth stating:

- **An active diff scope with zero changed files remediates nothing.** A
  pull request of only renames, deletions, mode changes or binary files is
  legitimately scoped to nothing, so every candidate is refused. The flag
  is what decides, never the changed-file count.
- **Path matching fails closed.** Paths are compared exactly after
  normalization (leading `./` and `/` stripped, backslashes folded), with
  no suffix or basename matching, so a path that cannot be matched to a
  changed file is refused rather than allowed.

Without `--diff-scope` this is a complete no-op: every finding in the
report is a candidate, exactly as before.

## The agentic loop

Each finding is rendered into a user prompt (the finding's own
Markdown section, reused verbatim from the scan report renderer) plus
the repo root, mode, and, when the policy gate below allows a patch,
a "Required fix strategy" playbook block and a "do NOT edit" path-glob
list. The system prompt requires the model to assess three self-reported
**evidence gates** before fixing:

- **Gate A (Source)**: the attacker/user-controlled input, with file:line.
- **Gate B (Sink)**: the security-relevant sink reachable from that source, with file:line.
- **Gate C (Missing control)**: why existing validation doesn't constrain it.

These are distinct from, and much simpler than, the 4 weighted gates
S11 validation scores against later (see `docs/validation.md`); Gates
A/B/C are the *agent's own* triage self-report, defaulting to `Fail`
when omitted, and feed only the post-gate's ACCEPT/REJECT audit label.

The agent must respond with a single structured JSON verdict (`Fixed`,
`Partially Fixed`, `Not Fixed`, `False Positive`, `Needs Review`, or
`Denied`) plus a `changes[]` list, `remaining_risks`, `recommendations`,
and a required 2-4 sentence `summary`. An unparseable-but-successful
response degrades to `Needs Review` rather than erroring; an `LlmError`
(network/rate-limit/etc.) is the only thing that propagates as an
error, and even then it fails only that one finding: the sequential
walk records it as `RemediationOutcome::Failed` and continues.

Model/tunables: `models.remediate` config role (else `--model`),
`step_remediate.max_turns` (default `40`), `step_remediate.allowed_tools`.
`step_remediate.max_transient_retries` (`4`), `max_context_shrinks` (`16`)
and `timeout` are all readable from the config too; only
`retry_backoff_base` (`10s`) is a Rust-only knob with no config surface.

`step_remediate.max_budget_usd` is **not** a budget control here. In the
Python original it was forwarded to the Claude CLI and Claude Agent SDK
backends, which do the enforcing and which this port does not have. It is
no longer shipped in `bc_config::step_defaults()`, there is no
`Step10Config` field for it, and a config that still sets it loads with a
warning. The only real spend knobs are `--max-tokens` and
`--max-scan-seconds`, which bound the whole run rather than this stage.

## Safety gates

> The agent's edits are a **proposal**, not a result. Every `Edit`/`Write`
> lands on the real working tree the instant the model emits it, so the
> only question left is whether it is allowed to stay. These gates decide
> that. All are on by default except the policy post-gate (which needs
> `--enforce-remediation-policy` or `step_remediate.enforce_policy`), the
> verify command (which has no default value) and `dry_run`.

| Gate | Config key | Default | What it does |
|---|---|---|---|
| Write journal | *(automatic)* | on | Every `Write`/`Edit` records the file's pre-edit **bytes** the first time it is touched, so a rollback is exact, on a non-git target too, and for files the finding never named. |
| Policy post-gate | `enforce_policy` | off | Unchanged: reverts edits that hit a `deny_paths`/`forbid_patch_paths` glob and forces `REJECT`. Runs first, so its compliance audit trail is never pre-empted by a later gate. |
| Syntax gate | `syntax_check` | `true` | Re-parses every touched file with tree-sitter. Any file that no longer parses rolls back **the whole patch** and downgrades the verdict to `Needs Review`. |
| Verify command | `verify_command` / `verify_timeout_secs` | `null` / `600` | Runs an operator-supplied `sh -c` command (build/lint/tests) in the repo root. Non-zero exit or timeout rolls the patch back, with the last 40 lines of output in the note. **Fails closed when there is no `sh` at all** (see below). |
| Size caps | `max_diff_lines` / `max_files_touched` | `200` / `1` | A remediation is a targeted fix for one finding; a sprawling patch is a run that went wrong. At the shipped `max_files_touched: 1`, a fix reaching into a second file is refused outright: crossing a file boundary is a design decision about how two parts of the system talk to each other, and that is a reviewer's call. The finding is still reported, and the refusal and its reason are rendered on the finding's `Patch` line. Either cap at `0` disables that half. |
| Dry run | `dry_run` | `false` | Run every gate, then roll everything back regardless, but keep the diff in the record. |
| Unverified rollback | `keep_unverified` | `false` | Anything but a clean `Fixed` verdict rolls the patch back: `Not Fixed`, `Partially Fixed`, `Needs Review`, `False Positive` and `Denied` alike (the check is literally "not `Fixed`", so the list is exhaustive by construction). `true` restores the old leave-it-applied behavior. |
| LLM-error rollback | *(automatic)* | on | A network error / rate limit / provider failure mid-loop rolls back whatever had already been written before the error propagates. The outcome carries no diff, so an edit left behind would be invisible. |
| S11 rollback | `keep_unverified` | `false` | After Phase 3 validation scores a fix `Not Fixed` or `UNVERIFIABLE`, that finding's changes are rolled back from **its own pre-remediation baseline**, byte-exact, no `git` needed (see below). Applies to both the `--top` batch walk and the `-i` picker. |

Every configurable gate also has a CLI flag, which **always wins over
the config file**:

| Flag | Config key | Notes |
|---|---|---|
| `--no-syntax-check` | `step_remediate.syntax_check` | One-directional: the flag can only turn the gate OFF. Only worth reaching for on a language this workspace ships no tree-sitter grammar for. |
| `--keep-unverified` | `step_remediate.keep_unverified` | One-directional: can only turn the rollback OFF. |
| `--max-diff-lines <N>` | `step_remediate.max_diff_lines` | `0` disables. |
| `--max-files-touched <N>` | `step_remediate.max_files_touched` | Default `1`. Raise it to allow a cross-file patch; `0` disables the cap entirely. |
| `--remediate-dry-run` | `step_remediate.dry_run` | One-directional: can only turn dry run ON. |
| `--verify-command <CMD>` | `step_remediate.verify_command` | Runs through `sh -c` in the repo root. **Operator-supplied only**. Nothing the model or the scanned repo can influence reaches it, and there is no default, so nothing runs unless it is set. |
| `--verify-timeout <SECS>` | `step_remediate.verify_timeout_secs` | Default `600`. |

Two consequences worth stating plainly:

- **A rolled-back finding is never checkpointed.** The checkpoint means
  "done", and `--resume` skips anything it can load; saving one for a
  patch a gate just removed would turn a bad fix into a permanently
  skipped finding. Rolled-back records are marked in
  `verdict.remaining_risks` with the `bc_stage_s10::REVERT_NOTE_PREFIX`
  marker (`bc_stage_s10::was_reverted` reads it back).
- **The user's own uncommitted work is never touched.** The rollback set
  is the union of the write journal, `git status` *minus whatever was
  already dirty before the agent ran*, and the agent's self-reported
  `changes[]` restricted to files with a real captured baseline. A blanket
  "revert everything git reports as changed" would `git checkout` the
  user's in-progress edits, which is the exact failure these gates exist
  to prevent.

### How the S11 rollback restores

Every finding's **baseline** (the on-disk bytes of exactly the files its
agent touched, as of the moment before it ran) travels out of
`remediate_finding_with_baseline` alongside its record, in
`RemediationRun::baselines`. It is held **in memory only**: it never
enters a `RemediationRecord`, a `--resume` checkpoint,
`--out-remediation-json`, or a PR comment. `bc_orchestrator::remediate`
and the `-i` picker both hand it to
`bc_stage_s10::revert_after_failed_validation`, which restores from it
directly. No `git`, no shell, no VCS of any kind: the same mechanism
S10's own in-loop gates use.

Two consequences worth stating plainly:

- **A file a LATER finding's kept fix also edited is never restored.**
  S10 remediates every selected finding before S11 validates any of
  them, so this finding's baseline predates that later edit; restoring
  the file would destroy a good fix in order to undo a bad one. Those
  files are left applied, each is named in a
  `[s11] WARNING: not rolling back <file> for finding N: finding M's kept
  fix also touched it` line, and the record's summary says which. Leaving
  a bad patch applied and saying so is recoverable; silently destroying a
  good one is not. (The `-i` picker never hits this: it validates each
  pick immediately, so no later finding exists yet, and an *earlier*
  pick's fix is safe by construction; the baseline was captured after
  it.)
- **A rolled-back finding's record is marked and its `diff` cleared**
  (`bc_stage_s10::was_reverted` reads the marker), exactly as S10's own
  gates do, so `--out-remediation-json` carries no diff for it and
  `--post-fixes-from` posts no "Suggested fix" comment for a patch that
  is no longer on disk. The one exception is the case above: when
  *nothing* was restored because every file was held back, the diff stays,
  because it is then the only record of a change that really is applied.

`bc_stage_s10::revert_record` remains as the **fallback**, for a record
with no baseline, one loaded straight out of a `--resume` checkpoint,
whose snapshot lived only in the process that created it. That path is
git-only: `git checkout --` (tracked) / unlink (untracked). On a non-git
target it can do nothing and returns an error the caller prints as
`[s11] WARNING: ...`. The patch stays applied and the operator is told
so.

## The one retry: "described a fix but never wrote it"

> **`step_remediate.retry_unapplied_fix`, default `true`.** Not a gate:
> it runs *before* every gate, so a retry that does write is judged
> exactly like a first-attempt fix.

The most common live failure this stage has is an agent that narrates a
change it never made: 3 of ~12 real remediations across four field runs
produced a record reading *"The SQL injection vulnerability in db.py was
fixed by changing the query ... to use parameterised queries. Downgraded
from the agent's own reported verdict: it described a fix, but no
corresponding on-disk change was found."* The downgrade
(`reconcile_verdict_with_diff`) is correct and catches it every time,
but the finding is then simply left unfixed, having spent a full agentic
session.

When the verdict is `Fixed`/`Partially Fixed` and the retry check finds no
material diff for the claimed files, the session is re-run **once**. An
empty `changes[]` does not exempt a claimed fix from this check. The retry
includes:

- the original per-finding prompt replayed in full (the retry is a fresh
  session, so the finding, repo root, playbook strategy and policy path
  lists all have to be present again);
- the agent's own prior answer quoted back (the analysis was fine; the
  doing was not);
- a statement of ground truth: *"No Edit or Write tool call was recorded
  for any of those files ... Apply the change now using the Edit tool"*,
  together with an explicit invitation to answer `Not Fixed`/`Needs
  Review` instead, so the nudge cannot trade one false claim for another.

Capped at exactly one extra session, never a loop. If the second attempt
also writes nothing, today's downgrade lands unchanged. The retry is
recorded in the record's `summary` (`Retried once after an unapplied
fix: ... Retries used: 1`), so a two-session remediation is visible to both
a reviewer and a cost-watching operator.

`retry_unapplied_fix` is a field on `Step10Config`, has its default in
`bc_config::step_defaults()`'s `step_remediate` block alongside the gate
keys, and is read from a `--config` file's `step_remediate.
retry_unapplied_fix` by `bc-cli`'s override layer next to the seven gate
keys. There is no CLI flag for it; `step_remediate.retry_unapplied_fix:
false` in a config file turns it off.

## Worktree isolation (the default)

Every gate above is a mitigation for editing the user's own files. The
structural fix is to stop editing them, and that is now what happens by
default: when `--repo` is a git worktree, `bc-sast --remediate` checks
the **same commit** out into a throwaway detached worktree, roots the
write-capable executor there, runs S10 (and S11) against it, exports a
unified diff, and deletes the checkout.

**Your working tree is never modified in this mode.** The fix arrives as
`<repo>/security-scan/remediation.patch`, applicable from the repo root
with `git apply security-scan/remediation.patch`. The summary line names
the path; `--out-remediation-json`'s per-finding `diff` fields are
unchanged (they come from the record, not from the checkout).

| Flag | Default | Effect |
|---|---|---|
| *(none, the default)* | on for a git `--repo` | Detached worktree under `$BC_STATE_DIR/remediation-worktrees/` (or the system temp dir if the state dir can't be resolved), removed afterwards. |
| `--remediate-in-place` | `false` | Edit `--repo` itself, the pre-isolation behavior. Use it when you want the fix applied to your checkout directly. |
| `--keep-remediation-worktree` | `false` | Leave the checkout on disk to inspect. Remove it yourself with `git worktree remove --force <path>`; the path is printed. |

In default patch mode without target testing, a non-Git `--repo` or a
failed `git worktree add` falls back to in-place remediation with a warning.
Target testing in patch mode and branch delivery instead require a clean
Git checkout and successful isolation. ZIP delivery uses an isolated source
snapshot, so it supports targets without Git and never uses this fallback.
If combined-patch export fails, the worktree is retained for recovery; the
warning prints its location.

**The packaged container can get worktree isolation now, if the checkout
is owned by its uid.** The runtime image is Chainguard's `wolfi-base`
with `git` installed (see `Dockerfile`), so `is_git_worktree` gets a real
answer for a containerized run instead of always being false. Isolation
is decided by probing for `git` and a `.git`, never by assuming anything
about the environment, so a mounted checkout gets a detached worktree and
a mounted source tarball does not.

The catch is git's own ownership check: a bind-mounted checkout keeps the
CI runner's ownership, and git 2.35 and later refuse a repository owned
by another user (`fatal: detected dubious ownership`). `is_git_worktree`
then answers false. Default patch mode without target testing can fall back
to in-place; modes that require a Git worktree refuse instead. `docs/deployment.md` has the two fixes (`chown` the checkout to uid
65532, or set `safe.directory` for that one path), and `bc-sast --doctor`
now says which of the two states a given mount is in rather than leaving
you to infer it from a missing diff. The GitHub Action already applies
the second fix for its own workspace (`docs/github-action.md`). The image
deliberately does not ship a global `safe.directory=*`.

The previous runtime was `gcr.io/distroless/cc-debian12:nonroot`, which
shipped no shell, no package manager and no `git`. Every containerized
run therefore remediated in place, which was defensible (a CI checkout is
created for the job and destroyed with it, so there was nothing there to
protect, and every safety gate runs identically in place) but it also
silently disabled the verify-command gate and the git revert backstop.
Both now work.

The gates' dependencies are still worth being able to check, both
because a scanned tree that is not a checkout still hits the no-`git`
column and because an operator is free to run this binary on a base of
their own that has neither:

| Gate | Needs `git`? | Needs a shell? | Behavior with neither |
|---|---|---|---|
| Write journal | no | no | Unaffected. It reads and writes files directly, and is the reason everything below still has a baseline. |
| Policy post-gate | no | no | Its `git status` cross-check yields nothing, so the candidate set is the journal + the agent's `changes[]`; reverts restore from the journal's bytes. |
| Syntax gate | no | no | tree-sitter parses in-process; rollback is from the journal. |
| Verify command | no | **yes** | The packaged image ships a `sh`, so this gate runs there. Where there is no `sh` it **fails closed**: it cannot run the operator's build/test command, so it rolls the patch back, downgrades to `Needs Review`, and records `verify_command could not run: no shell. 'sh' is not present on this system`. "Could not check" is never reported as "checked and fine". Nothing runs at all unless `verify_command` is explicitly set, so this affects only operators who set it. |
| Size caps | no | no | `git diff` is unavailable, so the diff is synthesized from the journal baseline (`synth_unified_diff`) and measured the same way. |
| Dry run | no | no | Rollback is from the journal. |
| Unverified rollback | no | no | Rollback is from the journal. |
| LLM-error rollback | no | no | Rollback is from the journal. |
| S11 rollback | no | no | Restores from the finding's own in-memory baseline. It was previously git-only, so without `git` it did nothing at all and printed `[s11] WARNING: ... is not a git repository ... the patch is still applied`, observed in the field under the old distroless runtime on a path-traversal fix S11 had just graded `Not Fixed` (GitHub Actions run 34021176323). Only a `--resume`d record, which carries no baseline, still falls through to the git path. |

Where `git` is present and the working tree is yours, isolation is on by
default and does the thing it is for. That is now true in the container
as well as locally.

**The verify gate only helps a project whose toolchain is in the image.**
The packaged image ships a shell and `git`, and nothing else: no
compilers, no test runners, no package managers for any of the languages
it scans. `verify_command: cargo test` in a container with no `cargo`
fails, the gate fails closed, and every fix comes back `Needs Review`,
which is correct but useless. The practical pattern is to build your own
image from this one and add what your `verify_command` needs:

```dockerfile
FROM ghcr.io/<your-org>/bc-sast:<tag>
USER root
RUN apk add --no-cache python-3.12 py3.12-pip
USER nonroot
```

Wolfi's `apk` repositories are what make that a two-line change rather
than a rebuild.

The gates run inside the remediation workspace. In-place runs print a
warning that source files will be edited; isolated worktree runs print the
workspace location. Dry-run output states that edits will be rolled back.

`RemediationWorktree` cleans up temporary checkouts on ordinary completion
and failure. Successful patch export is followed by cleanup unless
`--keep-remediation-worktree` was selected. A failed patch export instead
retains the worktree and prints its location for recovery.

The file list the patch is built from comes from `git status` inside the
worktree, not from the agents' self-reported `changes[]`. A model
under-reporting what it edited is exactly the case an export must not
miss, and the throwaway checkout contains nothing but this run's own
edits, so (unlike the in-place gates) there is no pre-existing dirty
state to exclude.

## Diff capture and revert (`bc-diffcapture`)

Before the agent runs, `snapshot_files` captures the pre-edit content
(or "didn't exist yet") of the finding's own file, plus, only when
policy enforcement is on, every worktree file matching a
`forbid_patch_paths`/`deny_paths` glob (a bounded walk, capped at
20,000 files). Snapshots hold raw **bytes**, so restoring a non-text file
is exact rather than a lossy UTF-8 round-trip. Beyond that pre-agent
snapshot, `bc_sandbox_tools::WriteJournal` captures the original bytes of
every file the agent actually writes to, at the moment it writes. That is
what makes a file outside the finding's own scope recoverable at all.
Finding references may carry a trailing line suffix and are normalized
before path confinement. Actual tool writes use stricter canonical paths:
ambiguous names, escaping paths and Git control paths are refused. Rollback
uses canonical repository-relative identities, including for absolute path
aliases, and Git checkout errors propagate to the caller. These controls
avoid passing raw model-supplied paths directly to Git.

After the run, the actual on-disk diff is captured via `git diff`
(after `git add -N` so new files show up) with a `synth_unified_diff`
fallback for a non-git target, and, for the policy post-gate
specifically, cross-checked against `git status --porcelain -z
--untracked-files=all` (a zero-side-effect scan of literally everything
that changed) and the diff text's own file list. This union, not the
agent's self-reported `changes[]` alone, is what the post-gate inspects,
specifically to defeat an under-reporting bypass where a compromised
agent edits a file but omits it from its own JSON. The stored remediation
diff also uses the actual touched set, so S11 and exported records receive
edits omitted from the model's `changes[]`. A claimed fix without a material
diff becomes `NeedsReview`; a supplied policy context also records `REJECT`.

## The policy gate (`bc-policy-gate`)

> **`--enforce-remediation-policy` defaults to `false`.** In the
> default configuration this deterministic gate never runs at all.
> Repository path confinement, Git control-path protection, session tool
> allowlists and baseline journalling still apply. CWE/path policy rules
> require explicit opt-in. The earlier security review recorded the
> default-off policy gate as finding #1 (AARM R1/R4, OWASP LLM06); its claim
> that path confinement was the only control predates the current guards.

```rust
/// Enable S10's deterministic policy gate (deny-list-wins,
/// fail-closed), strictly opt-in, matching the Python original's own
/// default-off posture. Requires `--remediation-policy` and/or
/// `--remediation-playbook` to have any real effect; enabling this
/// with neither set means EVERY finding fails closed to
/// guidance-only (no patches at all)...
#[arg(long)]
pub enforce_remediation_policy: bool,
```

`enforce_remediation_policy` and a loaded config's
`step_remediate.enforce_policy: true` are **OR'd together** in
`build_remediate_settings`: either source turning it on is sufficient,
and once either has said yes, nothing can force it back off from the
other source on the same invocation.

| Flag | Field | Default | Effect |
|---|---|---|---|
| `--enforce-remediation-policy` | `enforce_remediation_policy: bool` | `false` | Turns the gate on for this run. |
| `--remediation-policy <path>` | `remediation_policy: Option<PathBuf>` | `None` | The deny/allow CWE + `deny_paths`/kill-switch YAML. Only consulted when the gate is on. |
| `--remediation-playbook <path>` | `remediation_playbook: Option<PathBuf>` | `None` | Per-CWE fix-strategy YAML, injected into the ALLOW-path prompt. Only consulted when the gate is on; a missing/unparseable file silently falls back to an empty playbook. |

Config-side equivalents, consulted only when the matching flag is
absent: `step_remediate.policy_file` and `step_remediate.playbook_file`.
A **relative** value resolves against the directory holding the
`--config` file, not the process CWD and not the scan target, matching
Python's `remediation_agent/policy/context.py:94-95`, which exists
because a profile ships its own `./inputs/...` next to itself. An
absolute value is used verbatim.

Unlike Python, a configured path that does not exist is **not** silently
discarded: Python falls back to a bundled default policy, this port
bundles none, so dropping the path would turn a typo into a run that
looks permissive from the outside. `RemediationGate::load` fails closed
on an unreadable file instead.

Enabling the gate with **neither** source of a policy or playbook path
now prints an explicit warning naming both keys, because "policy says
no" and "you never gave me a policy" produce byte-identical output
otherwise (see `AI_AGENT_SECURITY_REVIEW.md` finding #7). The
fail-closed behavior itself is unchanged: every finding is still
guidance-only.

**No shipped default policy file exists in this repo**, only test
fixtures (`crates/bc-yaml/tests/fixtures/remediation_policy.yaml.example`,
`.../remediation_playbook.yaml`). Passing `--enforce-remediation-policy`
without `--remediation-policy` runs `RemediationGate::new(None)`, which
fails closed to `GuidanceOnly` for *every* finding. An operator who
enables enforcement without also supplying a real policy file gets
silent no-op patching (guidance only, no edits), not an error
(`AI_AGENT_SECURITY_REVIEW.md` finding #7; flagged there as safe, but
worth knowing since it looks identical to a working strict policy from
the outside).

### `RemediationGate::decide`'s exact evaluation order

An earlier rule always wins over a later one:

1. **Missing/unparseable policy**: fail-closed to `GuidanceOnly` (`no_policy_loaded`).
2. **Kill-switch active** (checked on *every* call, never cached): `GuidanceOnly` (`kill_switch`).
3. **Unrecognised/unmapped CWE id**: `GuidanceOnly` (`unmapped_cwe`).
4. **CWE (or a declared descendant) is deny-listed**: `GuidanceOnly`, reason from the policy's own `deny` entry. This wins over an allow-list entry for the *same* CWE.
5. **File path matches a `deny_paths` glob**: `GuidanceOnly` (`sensitive_path:<pattern>`). This blocks even an allow-listed CWE.
6. **CWE is allow-listed**: `Patch` (`allow_list`).
7. **Otherwise**: the policy's own `default_action` (`default_action`).

`default_action: allow` is the only YAML value that parses to
`Action::Patch`; a missing key, `"deny"`, or any unrecognised value all
resolve to `GuidanceOnly`, fail-closed at the field level.

### Kill-switch

Two independent triggers, either sufficient, both defined in the
policy YAML's own `kill_switch:` block and checked fresh on every
`decide()` call:

- An **environment variable** (name from `kill_switch.env_var`, e.g.
  `BC_REMEDIATE_DISABLE` in the crate's own example schema) set to
  `1`/`true`/`yes`/`on`, case-insensitive.
- A **sentinel file** (path from `kill_switch.file`, e.g.
  `./.bc-remediate-off` in the example schema). Mere existence trips
  it, regardless of content.

### Post-gate revert: write-then-inspect, not prevent-then-write

The CWE/path *pre*-gate above (steps 1-7) runs before the agent ever
sees the finding, a genuine pre-execution block. The
`deny_paths`/`forbid_patch_paths` check that runs *after* the agent's
turn is different: it inspects what actually landed on disk (via the
union of git diff / git status / self-reported changes described
above), and only then reverts. A forbidden edit briefly exists on disk
before being undone (`AI_AGENT_SECURITY_REVIEW.md` finding #4; AARM
R1). Concretely, for each file the post-gate flags:

1. `bc_diffcapture::revert` restores the pre-edit snapshot (or deletes
   the file, if the snapshot recorded it as new).
2. That file is dropped from `verdict.changes`.
3. `Fixed`/`Partially Fixed` is downgraded to `Needs Review`.
4. `remaining_risks` gets an explanatory note naming the reverted files
   and the globs they matched.
5. `final_verdict` is forced to `"REJECT"`.

On the clean path (nothing forbidden touched), `final_verdict` is
`cap_verdict(decision.action, verdict.gates.all_pass())`, an
`ACCEPT`/`REJECT` audit label distinct from the agent's own `verdict`
enum.

## `--resume` / checkpointing

| Flag | Field | Default | Effect |
|---|---|---|---|
| `--resume` | `resume: bool` | `false` | Skip a finding whose checkpoint's stored identity still matches it exactly. |
| `--force` | `force: bool` | `false` | Overrides S10's git-HEAD-staleness safety refusal (remediation otherwise refuses to run if HEAD has moved since the scan, since stale line numbers would misdirect the agent's file:line evidence). |

A finding's identity (`finding_identity`) is a SHA-1 hex digest over
its `finding_index`, `title`, `file`, and rendered body,
NUL-separated. Rust uses SHA-1 rather than the Python original's
SHA-256 purely as a staleness-detection mechanism, not a security
control. Checkpoints are **always written** when a checkpoint store is
available, regardless of `--resume`; `--resume` only gates whether a
prior checkpoint is *consulted* before re-running a finding, so a later
`--resume` run always has something to load from an earlier non-resume
run.

## Output

`--out-remediation-json <path>` writes a `RemediationExport` (`{refused,
results[]}`); each result is either `Processed` (finding_index,
finding_id, verdict, policy_action/reason, final_verdict, changes,
summary, diff, and, if S11 validation ran, its score) or `Failed
{finding_index, error}`. `--post-fixes-from <path>` is a separate,
scan-skipping mode that reads this JSON back and posts/updates GitHub
fix-suggestion comments from it (needs `--github-token`/
`--github-repo`/`--pr-number`); see `docs/github-action.md`.

`report.md` and `report.sarif` are also re-written after remediation:

- Each remediated finding gains a `#### Remediation` block (status,
  summary, approach, whether a patch was produced, root cause, changed
  files, remaining risks, recommendations, and, when S11 ran, its
  validation status), and the report gains a `## Remediation Summary`
  section. When a gate rolled the patch back, the `Patch` line names the
  gate's own reason rather than reading `no patch produced`, so a fix that
  was attempted and refused (over the file cap, breaking the parse,
  failing the verify command) cannot be mistaken for a finding the agent
  had nothing to say about. This happens **whenever any finding was remediated**, not
  only when S11 validation also ran.
- Each SARIF result gains a `properties.remediationStatus` string: the
  S10 verdict (or the policy gate's capped `final_verdict` when it
  overrode it). It is deliberately distinct from
  `properties.validationStatus`, which is S11's independent grade *of*
  a fix: a consumer needs both to tell "no fix was attempted" (a work
  item) from "a fix was attempted and rejected" (a triage signal).

Records are matched back to findings by the stable content-based
`finding_id`, never by `finding_index`. That field is a 1-based
*selection* ordinal (`--top N` picks by CVSS, not report order), so
using it directly would file a fix under the wrong finding.

In default worktree-isolated patch mode,
`<repo>/security-scan/remediation.patch` contains all accepted edits,
including generated tests and extensions to existing suites. Individual
finding exports are not a substitute for this combined patch. Branch and
ZIP delivery carry the updated files directly, as described below.

## Target application tests

Use `--target-tests [LEVEL]` (alias `--testing-level`) with a full scan and
`--remediate`. The levels are `discover`, `unit`, `integration`, and
`comprehensive`. A bare flag selects `comprehensive`; `e2e` and `generate`
are compatible names for that scope. Discovery always precedes generation.
Existing tests are inspected and reused or extended where suitable; test
presence alone does not establish adequate coverage.

The built-in levels do not execute target code. Their content is embedded
in the binary, so adding approved before/after execution requires a source
change and rebuild with a vetted container image and explicit commands.
Generated, reviewed, executed, passed and blocked are separate states.
Security regression execution should demonstrate the configured failure
before the fix and success after it, alongside legitimate behavior checks.

This workflow rejects diff-scoped scans, prior-report remediation, resume,
in-place remediation and `--stop-after`. Default patch and branch modes
require a clean Git checkout; ZIP mode uses an isolated source snapshot.
Tests follow target conventions and remain ordinary source-controlled test
files after the combined patch is applied, the branch is merged, or the ZIP
is imported. The `target-tests.json` report records assurance and remaining
gaps; it is not the reusable suite itself.

See [target testing](target-testing.md) for validation states, limits and
execution restrictions, and [built-in policies](built-in-policies.md) for
source locations.

## Full-scan delivery

`--remediation-delivery patch` is the default. For a full scan with
`--remediate`, select `branch` to commit and push all accepted source and
test changes together, or `zip` to export the updated isolated source copy.
Both modes require non-interactive isolated remediation and enforce scan
completion, remediation and configured target-test gates before delivery.

Branch delivery requires `--delivery-remote <NAME>` and
`--delivery-branch <NEW-BRANCH>`. Selecting it explicitly authorizes one
commit and push; an existing branch is never replaced. A run with no changes
records `no_changes` without creating a branch. ZIP delivery works without
Git and writes `security-scan/remediated-source.zip`; CI must upload that
file itself. Recognized credential paths, Git metadata and dependency/build
outputs are excluded from the source snapshot, with exclusions recorded.
Neither delivery mode is proof that tests passed or that remediation is safe.

See [remediation delivery](remediation-delivery.md) for commands, restrictions,
receipts, failure handling and CI upload examples.
