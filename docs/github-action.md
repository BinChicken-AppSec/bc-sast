# Using `bc-sast` as a GitHub Action

> **This action is one of two ways to run `bc-sast` in CI, and the more
> convenient rather than the recommended one.** The recommended model is to
> build the image once, push it to a registry you control, and pull it from
> each target repository's pull-request workflow. See
> [`deployment.md`](deployment.md). This action exists for consumers who
> would rather not run a registry; it pays a container build on every run.

`action.yml` at the repo root is a Docker container action. It builds its
image from this repo's own `Dockerfile` on the consumer's runner at usage
time rather than referencing a registry image: this repository publishes no
image of its own, and an image published to a private, authenticated
registry cannot serve as a default reference for arbitrary external
consumers without also handing out pull credentials. If you want a faster,
pre-built image instead of paying the build cost on every run, point
`image:` at a digest you've published somewhere your runners can reach,
which is exactly what [`deployment.md`](deployment.md) describes.

It writes `security-scan/report.sarif`, `report.md`, `report.csv` and
`findings.json` inside the checked-out workspace when the scan reaches
S9. The findings export also requires a known Git SHA. That directory is
`bc-sast`'s default out-dir, so the workspace must be writable. The action
does not upload SARIF
or post PR comments itself. Both are separate steps in your own workflow
(SARIF via the maintained `github/codeql-action/upload-sarif` action; PR
comments via `bc-sast`'s own `--post-comments-from` mode, run as a second,
privileged step). Keeping this action a pure *producer* is what makes the
fork-PR-safe two-workflow pattern below work for both outputs, not just
SARIF.

## Inputs

Every input has either a fixed value or a shipped default, so no input is
ever passed to the container as a literal empty string. GitHub Actions
cannot conditionally omit one element of a static `args:` array, and the
image's entrypoint is the scanner binary itself rather than a wrapper
script that could work around it.

| Input | Required | Default | Maps to |
|---|---|---|---|
| `gateway-base-url` | yes | n/a | `--gateway-base-url` |
| `gateway-api-key` | no | `""` | The `BC_GATEWAY_API_KEY` environment variable, not a CLI argument. |
| `model` | no | `gpt-4o` | `--model` |
| `dialect` | no | `openai` | `--dialect` (`openai` or `anthropic`) |
| `remediate` | no | `"false"` | `--remediate <value>`, always passed explicitly, which is why the flag accepts a value as well as being bare. |
| `remediation-delivery` | no | `patch` | `--remediation-delivery`: `patch` or `zip`. ZIP requires full-scan remediation and a consumer artifact upload step. Branch mode requires explicit CLI destination flags not exposed by this action. |
| `app-id` | no | `""` | `--app-id`, the **CMDB** application id used for environmental-CVSS/OffensivePriority enrichment. (Not to be confused with a GitHub App's `app-id`, which the apply-fix workflow further down also uses.) |
| `cmdb-csv` | no | `""` | `--cmdb-csv`, a path inside the workspace to a CMDB CSV export, used alongside `app-id`. |
| `git-sha` | no | `""` | `--git-sha`. Strongly recommended. The image ships `git`, so leaving it unset now falls back to `git rev-parse HEAD` in the container instead of giving up, but the workflow authoritatively knows which commit it checked out and a shallow or detached checkout can leave `git rev-parse` disagreeing. With no usable sha, `report.git_sha` stays unset and `findings.json` is never written at all. |

The action also passes `--out-findings-json` and
`--out-remediation-json` explicitly, under `security-scan/`. The first is
redundant for eligible scans, since `findings.json` already defaults to
the out-dir, and is kept only so the path in the `args:` array stays
readable alongside the rest. Neither file is unconditional: `findings.json`
is written only when the scan reaches a final report **and** a git sha is
known, and `remediation.json` only when `remediate: "true"` actually ran
remediation against a final report. With remediation off, no
`remediation.json` is produced, not even an empty one.

### Full-scan ZIP delivery

Set `remediate: "true"` and `remediation-delivery: zip` on a full-scan
invocation to produce updated source without requiring Git. This mode
works with remediation alone. The Docker action does not expose
`--target-tests` or `--scan-framework`; use a direct configured CLI or
container invocation when selecting those flags.

ZIP delivery uses an isolated source snapshot and writes
`security-scan/remediated-source.zip` plus `security-scan/delivery.json`
after applicable gates permit delivery. It does not upload them. Add a
consumer step after the scan:

```yaml
- name: Upload remediated source
  if: success()
  uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
  with:
    name: remediated-source
    path: |
      security-scan/remediated-source.zip
      security-scan/delivery.json
    if-no-files-found: error
```

Use a fresh workspace for each run. Existing ZIP output is rejected, and
delivery failure produces a nonzero scanner exit status. Inspect the
receipt's validation state and exclusions; successful delivery does not
prove tests ran. CI controls artifact retention and download permissions.
This new delivery/upload flow has not been validated on a live CI runner.
See [remediation delivery](remediation-delivery.md) for limitations and
[testing profiles](target-testing.md) for the separate execution policy.

### The environment the action sets for you

`action.yml`'s `runs.env` sets two things the container needs and no
input controls:

| Variable | Value | Why |
|---|---|---|
| `BC_GATEWAY_API_KEY` | the `gateway-api-key` input | A credential belongs in the environment, not in an `args:` array that shows up in process listings. |
| `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_0`/`VALUE_0` | `1`, then `safe.directory` for the literal `/github/workspace` | Marks the one directory under scan as safe for `git`, so the container's uid 65532 can actually read the runner-owned checkout. Without it every git-backed feature degrades silently. |

**Why the `safe.directory` entry exists.** Git 2.35 and later refuse a
repository owned by a different user (`fatal: detected dubious
ownership`). The image runs as uid 65532 and the runner bind-mounts a
checkout that keeps the runner's own ownership, so `git` inside the
container refuses it. Nothing fails loudly when that happens: commit-sha
detection, `--remediate`'s worktree isolation and S10's git revert
backstop each probe for git and quietly fall back, so a scan still runs
and simply does less than you configured it to do.

A docker action has nowhere to run a shell step before its entrypoint
(the entrypoint is the scanner binary), and a nonroot container cannot
`chown` its own mount, so the two remedies
[`deployment.md`](deployment.md) offers a `docker run` operator are both
out of reach here. Git's environment-variable config scope is what is
left, and it is sufficient: `GIT_CONFIG_KEY_n`/`VALUE_n` land in git's
`command` scope, which git treats as *protected* configuration and
therefore honours for `safe.directory`. A repository's own `.git/config`
is not protected, so a scanned repository still cannot grant itself the
exemption.

**Why the path is written literally.** An action manifest cannot use
the `github` context at all. Only `inputs` is available, and any
`${{ github.* }}` expression anywhere in `action.yml` fails the whole
manifest to load with `Unrecognized named-value: 'github'`. That
includes expressions written inside a `description:` string, which the
runner evaluates along with everything else, so an example in prose has
to be written as a bare context path rather than as an expression.

The workspace is therefore named by the mount point directly. Measured on
a real runner, the container is started with
`-v "/home/runner/work/<repo>/<repo>":"/github/workspace"` and
`--workdir /github/workspace`, so `/github/workspace` is the path that
exists inside the container.

This matters for `args:` as well as `env:`, because the two are handled
differently. Environment values are path-translated: an environment
variable carrying the host workspace path arrives inside the container
rewritten to `/github/workspace`. Arguments are not. In
`src/Runner.Worker/Handlers/ContainerActionHandler.cs`,
`TranslateToContainerPath` is applied to every environment value, while
`ContainerEntryPointArgs` is assembled verbatim from
`EvaluateContainerArguments` and passed to `docker run` untouched. A
probe on a real runner confirmed both halves: the same host path passed
through `env` came back as `/github/workspace`, and passed through `args`
came back as the host path, pointing at a directory that does not exist
in the container.

Neither entry is `safe.directory=*`: turning an ownership check off for
every repository, by default, in a security tool is not a decision this
action gets to make for an operator. Both name a single directory, and
the `GIT_CONFIG_*` variables reach only this container's own process
tree. Running `bc-sast --doctor` reports which of the two states you are
in, naming the scan target and, on a refusal, the exact remedy.

## PR comments: how `bc-github` decides where to post

Every finding gets exactly one comment, keyed by a hidden
`<!-- bc:finding-id=<id> -->` marker using the same stable id as the SARIF
`partialFingerprints` field, so a finding has one identity everywhere it's
surfaced, and re-scans update the existing comment rather than piling up
duplicates:

- If the finding's line is part of the PR's diff (fetched via the
  `application/vnd.github.v3.diff` media type on the pull request itself),
  it becomes an inline **review comment** anchored to that line.
- Otherwise it falls back to a plain **conversation comment** on the PR.
- Once a finding has a posted comment of either kind, later scans update
  that same comment in place (even if the diff-touched status of its line
  later changes) rather than creating a second comment at a new anchor.

`--pr-comments` on the `bc-sast` binary opts into this, on top of
`--github-token`/`--github-repo owner/name`/`--pr-number` naming the pull
request and `--diff-scope` scoping the scan to it. All five are required:
the credential trio alone is a read-only claim about which PR the run is
about (that is what `--diff-scope` fetches its diff through), and it no
longer implies consent to write to the review thread. Without
`--pr-comments`, posting is skipped entirely and Markdown/SARIF output is
unaffected. Passing `--pr-comments` without `--diff-scope` is refused at
startup, because a finding outside the diff has no line to anchor to and
a fix suggestion outside the diff has no commit button. A posting failure
is reported in the CLI's summary line but never fails the scan itself.
SARIF/Markdown are the scan's real output, PR comments are a best-effort
delivery layer on top.

## Why a two-workflow split, and not a single `pull_request` workflow

A single workflow triggered on `pull_request` that both scans AND uploads
SARIF (`security-events: write`) or posts PR comments (`pull-requests:
write`) would need those permissions available to a fork PR's workflow
run, but `GITHUB_TOKEN` is read-only for PRs opened from forks. Using
`pull_request_target` to get a writable token instead is the commonly
recommended-against pattern here, because it runs with repo secrets in a
context that also checks out and can execute the fork's own code.

The *scanning* stages' `ToolExecutor` is `Read`/`Glob`/`Grep` only, and
no stage is ever offered a `Bash` tool (see the main project's
`bc-sandbox-tools`), so the scanning step itself never executes anything
from the target repository. With `remediate: "true"`, S10 additionally
gets `Edit`/`Write` against the checkout: still no shell tool, and still
path-jailed to the repo root, but it does write. The runtime image does
contain a `sh`, which the agent has no tool to reach; the only string
that gets to `sh -c` is the operator's own `step_remediate.verify_command`
from a `--config` file, which has no default. That means the scanning
job can safely hold the gateway secret even when analyzing a fork PR.
There's no code-execution path for that secret to leak through. The only
steps that need a privileged, secret-bearing context are the
*SARIF upload* and the *PR-comment posting*. GitHub's own Security Lab
documents exactly this split as the safe alternative to
`pull_request_target`, and `bc-sast` is designed so it applies to both
outputs, not just SARIF:

1. An **unprivileged** workflow triggered on `pull_request` runs the scan
   and uploads its SARIF *and* its findings JSON (`--out-findings-json`,
   always requested by `action.yml`, and actually written whenever the
   scan reaches a final report with a known `git-sha:`) as build
   artifacts. No write token, no
   secrets beyond the gateway key (safe here, since nothing from the fork
   ever executes).
2. A **privileged** workflow triggered on `workflow_run` (fired when (1)
   completes) runs in the base repo's trusted context (write token,
   `security-events: write` and/or `pull-requests: write`) and only ever
   *consumes the artifacts as inert data* (a SARIF file, a findings JSON
   file), never executing anything from them. It uploads SARIF via
   `upload-sarif`, and posts/updates PR comments via
   `bc-sast --post-comments-from findings.json`, a mode that reads the
   findings snapshot and talks to the GitHub API directly, without
   re-running any pipeline stage or touching the fork's own code at all.

## Consumer workflow 1: `analysis.yml` (unprivileged, runs the scan)

> **Pin these actions before you use them.** The workflow examples below
> reference third-party actions by tag, such as `actions/checkout@v4`,
> because a tag stays readable and does not rot in prose. A tag is
> mutable: whoever controls it can repoint it at different code, which
> then runs with your workflow's permissions. This project pins every
> action in its own `.github/workflows/ci.yml` to a full commit SHA, and
> you should do the same in anything you actually deploy.

```yaml
name: bc-sast scan
on:
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      # `ref:` is NOT optional here. A bare `actions/checkout@v4` on a
      # `pull_request` trigger checks out GitHub's own synthetic merge
      # commit (`refs/pull/N/merge`, base+head merged), not the PR's real
      # head commit. This checkout is what the container's own
      # `--repo` scans, so a wrong `ref:` here means wrong file content,
      # not just a wrong recorded sha. Pin explicitly to the PR's actual
      # head sha.
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      # The container runs as a non-root user (uid 65532), and its
      # entrypoint is the scanner, so nothing inside fixes this up before
      # the scan starts. A bind-mounted `github.workspace` directory
      # keeps the RUNNER's ownership/permissions, which the container's
      # own uid can't write into by default. This bites you
      # twice, confirmed live both times:
      #   1. Without security-scan/ writable, bc-sast refuses the run
      #      up front (it creates the out-dir before scanning precisely
      #      so this costs a second rather than a whole run's LLM
      #      calls). Historically it failed at the very end instead: an
      #      expensive way to fail, and the reason the check moved.
      #   2. With `remediate: true`, S10 edits repo files in place (e.g.
      #      the vulnerable file itself) to apply a fix, then diffs
      #      before/after. Without the REPO ITSELF writable too, the edit
      #      silently doesn't happen. The verdict still says "Fixed"
      #      (the agent's own narrative), but `diff` comes back `null` on
      #      every single finding, because the file never actually
      #      changed on disk. `--post-fixes-from` then has nothing to
      #      post at all.
      # `chmod -R .` (the whole checkout), not just security-scan/, is
      # what actually fixes case 2.
      #
      # The `chown` is about git rather than about writability. Git 2.35+
      # refuses a repository owned by another user
      # (`fatal: detected dubious ownership`), and permissions alone do
      # not satisfy that check. When you run the scanner through THIS
      # action you no longer need it: `action.yml` marks the
      # workspace it mounts as a `safe.directory` for the container (see
      # "The environment the action sets for you" in
      # `docs/github-action.md`). It is kept here because it costs
      # nothing, it is still required for the plain `docker run` model in
      # `docs/deployment.md`, and it makes this snippet correct to copy
      # into either. Without one or the other, HEAD-sha detection,
      # remediation worktree isolation and the git revert backstop all
      # probe, get "no git", and degrade exactly as they did on the old
      # shell-less image: nothing breaks, nothing improves.
      - name: Make the checkout writable by the container
        run: |
          # Hand the checkout to the container's uid rather than opening it
          # to every user on the host. `chmod -R 777` would also work and is
          # portable where `chown` is unavailable, but on a long-lived or
          # shared runner it leaves a world-writable source tree behind, so
          # it is not what this example teaches. If `chown` cannot work in
          # your environment, prefer running the container as the runner's
          # own uid with `--user "$(id -u):$(id -g)"` over widening the mode.
          mkdir -p security-scan
          sudo chown -R 65532:65532 . || chown -R 65532:65532 .

      - name: Run bc-sast
        uses: OWNER/bc-sast@v1
        with:
          gateway-base-url: ${{ vars.BC_GATEWAY_BASE_URL }}
          gateway-api-key: ${{ secrets.BC_GATEWAY_API_KEY }}
          # Strongly recommended for job 2's PR-comment posting. The
          # image ships `git`, so an unset value falls back to
          # `git rev-parse HEAD` rather than giving up, but a shallow or
          # detached checkout can leave that disagreeing with the sha the
          # comment API will accept. With no usable sha,
          # `report.git_sha` stays `None` and `findings.json`'s
          # `commit_sha` is silently absent.
          # Matches the `ref:` the checkout step above already pins to,
          # for the same reason (the synthetic merge commit a bare
          # checkout would otherwise use isn't part of the PR, so a sha
          # derived from it gets rejected by GitHub's comment API or
          # anchors incorrectly).
          git-sha: ${{ github.event.pull_request.head.sha }}

      - name: Record the PR number
        run: |
          echo "${{ github.event.pull_request.number }}" > security-scan/pr_number.txt

      - name: Upload results as build artifacts
        uses: actions/upload-artifact@v4
        with:
          name: bc-sast-results
          path: |
            security-scan/report.sarif
            security-scan/findings.json
            security-scan/pr_number.txt
          retention-days: 7
```

**If you also want auto-remediation**: add `remediate: "true"` to the "Run
bc-sast" step's `with:` block above, and add `security-scan/remediation.json`
to the `upload-artifact` step's `path:` list. `action.yml` always passes
`--out-remediation-json`, but the file is only written when remediation
actually ran against a final report. With `remediate: "false"` it is
absent entirely, which is why the consuming steps below guard on
`hashFiles(...)`. Posting the resulting fix-suggestion PR comments is a
separate step, shown in consumer workflow 2 below.

## Consumer workflow 2: `publish-results.yml` (privileged, uploads + comments)

```yaml
name: bc-sast publish results
on:
  workflow_run:
    workflows: ["bc-sast scan"]
    types: [completed]

permissions:
  contents: read
  security-events: write # Code Scanning upload
  pull-requests: write # PR comment posting

jobs:
  publish:
    if: github.event.workflow_run.conclusion == 'success'
    runs-on: ubuntu-latest
    steps:
      # `path: security-scan`, not `path: .`. `upload-artifact@v4` roots
      # the archive at the least common ancestor of the uploaded paths
      # (`security-scan/`), so the files come back WITHOUT that prefix.
      # Downloading into a directory of that name puts them back where
      # the rest of this job expects them.
      - name: Download the scan's artifacts
        uses: actions/download-artifact@v4
        with:
          name: bc-sast-results
          path: security-scan
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-scan/report.sarif

      # A lightweight checkout only to satisfy `--repo`'s required-arg
      # constraint. `--post-comments-from` mode never reads repo content,
      # it only reads `findings.json` and talks to the GitHub API.
      - uses: actions/checkout@v4

      - name: Post/update PR comments
        run: |
          PR_NUMBER=$(cat security-scan/pr_number.txt)
          docker run --rm \
            -v "$PWD:/workspace" \
            <your-registry>/bc-sast:<tag> \
            --repo /workspace \
            --gateway-base-url unused \
            --post-comments-from /workspace/security-scan/findings.json \
            --github-token "${{ secrets.GITHUB_TOKEN }}" \
            --github-repo "${{ github.repository }}" \
            --pr-number "$PR_NUMBER"

      # Only meaningful if job 1 also ran `--remediate --out-remediation-
      # json` (see the aside on workflow 1 above) and uploaded
      # `remediation.json`. It is a no-op (nothing to post) otherwise,
      # since the file simply won't exist in the downloaded artifact.
      - name: Post/update fix-suggestion comments
        if: hashFiles('security-scan/remediation.json') != ''
        run: |
          PR_NUMBER=$(cat security-scan/pr_number.txt)
          docker run --rm \
            -v "$PWD:/workspace" \
            <your-registry>/bc-sast:<tag> \
            --repo /workspace \
            --gateway-base-url unused \
            --post-fixes-from /workspace/security-scan/remediation.json \
            --github-token "${{ secrets.GITHUB_TOKEN }}" \
            --github-repo "${{ github.repository }}" \
            --pr-number "$PR_NUMBER"
```

This job never checks out the PR's own *code with intent to execute it*
(the `actions/checkout@v4` step above only provides a directory for
`--repo`'s required-but-unused argument) and never executes anything
from the downloaded artifacts beyond handing `report.sarif` to
`upload-sarif` and `findings.json`/`remediation.json` to `bc-sast`'s own
`--post-comments-from`/`--post-fixes-from` modes as inert data. That's the
exact property that makes this safe for fork PRs without
`pull_request_target`: neither mode runs a pipeline stage, calls the LLM
gateway, or touches repo content: each only deserializes a JSON snapshot
and talks to the GitHub REST API.

These steps invoke the published image directly with `docker run` rather
than through `action.yml`, since `action.yml`'s own inputs don't (yet)
expose `--post-comments-from`/`--post-fixes-from`/`--github-token`/
`--pr-number`. See "Deferred" below.

## Scoping a scan to the PR's diff (`--diff-scope`)

A Rust-only feature (no Python-original equivalent): instead of
re-analyzing the whole repository on every PR, `--diff-scope` scopes S3's
chunking and S4's deep-dive to the PR's own changed files. The rest of
the repo is still available as call-graph/import context (so a changed
`api.js` importing an untouched `utils.js` is still reasoned about
correctly), it just never gets newly chunked or reported on. See
`docs/USER_GUIDE.md` §1a for the full mechanics and its one documented
limitation (one-hop cross-file context for a >2-hop taint chain through
unchanged files).

**Not (yet) an `action.yml` input**, for the same reason `--stop-after` and
`--post-comments-from`/`--post-fixes-from` aren't (see "Deferred" below):
it needs `--github-token`/`--github-repo`/`--pr-number` at *scan* time, and
consumer workflow 1 above deliberately never passes those to the
container. The scan job is designed to need nothing beyond the gateway
key (see "Why a two-workflow split" above). Fetching a diff is a read-only
call (`GET .../pulls/{n}` with the `.v3.diff` media type), so unlike
posting comments it doesn't need `pull-requests: write`: the default,
automatically-provided `GITHUB_TOKEN` on a same-repo `pull_request` trigger
already has enough read access for it. Until this is a first-class input,
invoke the image directly instead of through `action.yml`, the same way
consumer workflow 2 already does for `--post-comments-from`:

```yaml
- name: Run bc-sast with diff-scope
  # Both credentials go in as environment variables, never as CLI
  # arguments: `--gateway-api-key` and `--github-token` are both wired
  # with clap `env = ...`, so the container picks them up without them
  # ever appearing in a process listing or a shell trace.
  env:
    BC_GATEWAY_API_KEY: ${{ secrets.BC_GATEWAY_API_KEY }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    docker run --rm \
      -v "$PWD:/workspace" \
      -e BC_GATEWAY_API_KEY \
      -e GITHUB_TOKEN \
      <your-registry>/bc-sast:<tag> \
      --repo /workspace \
      --gateway-base-url "${{ vars.BC_GATEWAY_BASE_URL }}" \
      --git-sha "${{ github.event.pull_request.head.sha }}" \
      --out-findings-json /workspace/security-scan/findings.json \
      --diff-scope \
      --github-repo "${{ github.repository }}" \
      --pr-number "${{ github.event.pull_request.number }}"
```

Note the absence of `--pr-comments`: this job holds a token so it can read
the PR's diff, and reading is all it does. The findings go out through
`findings.json` to workflow 2's `--post-comments-from` step, which is
where `pull-requests: write` lives. Adding `--pr-comments` here would make
the unprivileged scan job post directly, which is exactly what the
two-workflow split exists to avoid.

The default `GITHUB_TOKEN` (not a privileged App token) is enough here:
this is still the *unprivileged* scan job, just now also fetching a
read-only diff before it starts. It stays safe under the same reasoning as
consumer workflow 1: the diff text is data fed into the LLM prompt (S3's
"PRIORITIZE THESE FILES" hint), never executed, and this job still has no
`Edit`/`Write`/shell tool access to anything the PR's own branch controls.

## Applying a suggested fix (`apply-fix.yml`)

`--post-fixes-from` posts comments for every remediated finding that
actually changed something on disk. Every one carries a hidden
`<id>:fix` marker built from the same stable finding id as the
`<!-- bc:finding-id=<id> -->` marker on that finding's own description
comment:

- A fix whose **every hunk lands entirely on lines the PR's own diff
  already touches** gets one native, anchored review comment **per hunk**,
  each with a `suggestion`-fenced body. GitHub renders a one-click
  "Commit suggestion" button on each (hidden markers `<id>:fix` for a
  single-hunk fix, `<id>:fix:0`/`<id>:fix:1`/... for a multi-hunk one, so
  re-scans update each in place rather than piling up duplicates).
- Every other fix (multi-file, a brand-new/deleted file, or ANY hunk
  landing even partly off the PR's diff) falls back to one plain,
  unanchored conversation comment with the whole diff as a fenced `diff`
  code block instead, plus a written
  `comment /apply-fix <finding-id>` instruction.

That written instruction appears on the **fallback comment only**, where
it is the sole way to apply the fix. An anchored suggestion comment
leaves it out: GitHub's own "Commit suggestion" button sits directly
above it, so the sentence is noise, and the alternative it would offer is
retyping a forty-character hex id. Typing `/apply-fix <finding-id>`
anywhere on the PR still works either way, since the workflow below reads
the id out of the commenter's own message rather than out of the comment
being replied to.

**The fix's actual diff content is never sourced from the comment body.**
Both the `suggestion` and the `diff` renderings are passed through
`bc_redact::redact` before they reach GitHub (either might contain a
secret the finding itself is *about*), and redaction is lossy, so a
redacted copy can't reliably `git apply` cleanly, and scraping Markdown
that could render either way is fragile. Instead,
`/apply-fix` re-downloads the same `remediation.json` artifact `analysis.yml`
already uploaded for this PR's most recent scan and reads that finding's
diff directly. The unredacted diff exists only transiently on the runner's
disk and inside that artifact (access-controlled the same as the repo
itself), never inside a PR comment, hidden or visible.

A third, separate workflow, triggered on `issue_comment` (a top-level PR
conversation reply) or `pull_request_review_comment` (a reply on an inline
suggestion thread), reads the `/apply-fix <finding-id>` command and does
the actual work: verify the commenter's permission, locate this PR's most
recent scan run, download its `remediation.json`, look up the finding's
diff, apply it to the PR branch, and push.

**Authenticates as your own GitHub App**, not the default `GITHUB_TOKEN`,
so commits and comments show as your bot's identity (e.g.
`agentic-sast-bot[bot]`), not a generic "github-actions[bot]" or a
personal account. Create a **private** GitHub App ("Only on this account"
under "Where can this GitHub App be installed?"; private apps aren't
listed anywhere public and aren't installable by anyone outside your org)
with repository permissions **Contents: Read and write**, **Pull requests:
Read and write**, install it on this repo, and store its App ID/private
key as `APP_ID`/`APP_PRIVATE_KEY` secrets.

```yaml
name: bc-sast apply fix
on:
  issue_comment:
    types: [created]
  pull_request_review_comment:
    types: [created]

permissions:
  contents: read

jobs:
  apply-fix:
    if: |
      startsWith(github.event.comment.body, '/apply-fix ') &&
      (github.event_name == 'pull_request_review_comment' || github.event.issue.pull_request != null)
    runs-on: ubuntu-latest
    steps:
      - name: Mint a short-lived token for our GitHub App
        id: app-token
        uses: actions/create-github-app-token@v3
        with:
          app-id: ${{ secrets.APP_ID }}
          private-key: ${{ secrets.APP_PRIVATE_KEY }}

      # issue_comment carries the PR number as github.event.issue.number;
      # pull_request_review_comment carries it directly as
      # github.event.pull_request.number. Normalize once, up front.
      - name: Resolve the PR number for this event
        id: ctx
        run: |
          if [ "${{ github.event_name }}" = "pull_request_review_comment" ]; then
            echo "pr_number=${{ github.event.pull_request.number }}" >> "$GITHUB_OUTPUT"
          else
            echo "pr_number=${{ github.event.issue.number }}" >> "$GITHUB_OUTPUT"
          fi

      # Fail closed: only a repo collaborator with write (or higher)
      # access may trigger this: anyone can comment on a PR, and this
      # job pushes a commit.
      - name: Check commenter's permission
        id: perm
        run: |
          level=$(gh api "repos/${{ github.repository }}/collaborators/${{ github.event.comment.user.login }}/permission" --jq .permission)
          echo "level=$level" >> "$GITHUB_OUTPUT"
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}

      - name: Refuse if the commenter lacks write access
        if: |
          steps.perm.outputs.level != 'admin' &&
          steps.perm.outputs.level != 'maintain' &&
          steps.perm.outputs.level != 'write'
        run: |
          gh api "repos/${{ github.repository }}/issues/${{ steps.ctx.outputs.pr_number }}/comments" \
            -f body="@${{ github.event.comment.user.login }}: applying a fix requires write access to this repository."
          exit 1
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}

      - name: Resolve the PR's head repo/ref
        id: pr
        run: |
          pr=$(gh api "repos/${{ github.repository }}/pulls/${{ steps.ctx.outputs.pr_number }}")
          echo "head_repo=$(echo "$pr" | jq -r .head.repo.full_name)" >> "$GITHUB_OUTPUT"
          echo "head_ref=$(echo "$pr" | jq -r .head.ref)" >> "$GITHUB_OUTPUT"
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}

      # An installation token has no write access to a fork either.
      # Refuse plainly rather than let `git push` fail with a confusing
      # permission error.
      - name: Refuse fork PRs (not yet supported)
        if: steps.pr.outputs.head_repo != github.repository
        run: |
          gh api "repos/${{ github.repository }}/issues/${{ steps.ctx.outputs.pr_number }}/comments" \
            -f body="/apply-fix can only commit back to same-repo PRs today. This PR's branch lives in a fork, which the bot's token can't push to."
          exit 1
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}

      # Moved here (not right before the git-apply step) deliberately,
      # confirmed live: `gh run download`, a few steps below, refuses to
      # run at all outside a git repository ("failed to run git: fatal:
      # not a git repository ..."), and the bare GitHub Actions workspace
      # isn't one until a checkout actually happens. Also serves the
      # later git-apply step, so this isn't a second/wasted checkout.
      - uses: actions/checkout@v4
        with:
          ref: ${{ steps.pr.outputs.head_ref }}
          token: ${{ steps.app-token.outputs.token }}

      - name: Extract the requested finding id
        id: finding
        run: |
          finding_id=$(echo "${{ github.event.comment.body }}" | sed -n 's/^\/apply-fix[[:space:]]\+//p' | tr -d '[:space:]')
          if [ -z "$finding_id" ]; then
            gh api "repos/${{ github.repository }}/issues/${{ steps.ctx.outputs.pr_number }}/comments" \
              -f body="Couldn't parse a finding id from that command. Expected \`/apply-fix <finding-id>\`."
            exit 1
          fi
          echo "id=$finding_id" >> "$GITHUB_OUTPUT"
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}

      # Finds the most recent COMPLETED `pull_request`-triggered run of
      # the scan workflow for exactly this PR: independent discovery,
      # since this job isn't chained from that run via `workflow_run` the
      # way consumer workflow 2 is.
      - name: Find this PR's most recent scan run
        id: scan_run
        run: |
          run_id=$(gh api "repos/${{ github.repository }}/actions/runs?event=pull_request&status=completed" \
            --jq '[.workflow_runs[] | select(.name == "bc-sast scan") | select(.pull_requests[]?.number == ${{ steps.ctx.outputs.pr_number }})] | sort_by(.created_at) | reverse | .[0].id')
          if [ -z "$run_id" ] || [ "$run_id" = "null" ]; then
            gh api "repos/${{ github.repository }}/issues/${{ steps.ctx.outputs.pr_number }}/comments" \
              -f body="No completed scan run found for this PR. Re-run the scan and try again."
            exit 1
          fi
          echo "run_id=$run_id" >> "$GITHUB_OUTPUT"
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}

      - name: Download that run's remediation data
        run: gh run download "${{ steps.scan_run.outputs.run_id }}" -n bc-sast-results -D artifact
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}

      - name: Look up this finding's diff
        run: |
          if [ ! -f artifact/remediation.json ]; then
            gh api "repos/${{ github.repository }}/issues/${{ steps.ctx.outputs.pr_number }}/comments" \
              -f body="No remediation data found for this PR's latest scan. Was \`remediate: true\` enabled and \`remediation.json\` uploaded?"
            exit 1
          fi
          # Written straight from jq's stdout to the file, never through a
          # shell variable - confirmed live: `diff=$(jq ...)` followed by
          # `printf '%s' "$diff"` corrupts the patch whenever the diff's
          # final hunk line is a blank context line, because command
          # substitution strips trailing newlines and silently eats that
          # line's own newline. git apply then rejects it as corrupt.
          jq -r --arg fid "${{ steps.finding.outputs.id }}" \
            '.results[] | select(.status == "processed" and .finding_id == $fid) | .diff // empty' \
            artifact/remediation.json > /tmp/fix.diff
          if [ ! -s /tmp/fix.diff ]; then
            gh api "repos/${{ github.repository }}/issues/${{ steps.ctx.outputs.pr_number }}/comments" \
              -f body="No applicable fix found for finding \`${{ steps.finding.outputs.id }}\` in the latest scan."
            exit 1
          fi
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}

      - name: Apply, commit, and push as the bot
        run: |
          if ! git apply /tmp/fix.diff; then
            gh api "repos/${{ github.repository }}/issues/${{ steps.ctx.outputs.pr_number }}/comments" \
              -f body="This fix no longer applies cleanly (the surrounding code has changed since it was suggested). Please resolve it manually."
            exit 1
          fi
          git -c user.name="${{ steps.app-token.outputs.app-slug }}[bot]" \
              -c user.email="${{ steps.app-token.outputs.app-slug }}[bot]@users.noreply.github.com" \
              commit -am "Apply suggested fix for ${{ steps.finding.outputs.id }}"
          git push origin "HEAD:${{ steps.pr.outputs.head_ref }}"
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}

      - name: React to confirm success
        if: success()
        run: |
          if [ "${{ github.event_name }}" = "pull_request_review_comment" ]; then
            gh api "repos/${{ github.repository }}/pulls/comments/${{ github.event.comment.id }}/reactions" -f content="+1"
          else
            gh api "repos/${{ github.repository }}/issues/comments/${{ github.event.comment.id }}/reactions" -f content="+1"
          fi
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
```

**Empirically tested end to end against a real PR** (via a
`secrets.GITHUB_TOKEN`-based variant of this workflow, before adding the
GitHub App token shown above; the mechanics are otherwise identical): the
comment trigger, permission check, fork refusal, finding-id extraction,
scan-run discovery, artifact download, diff lookup, `git apply`, commit,
push, and reaction all ran for real on a live PR. Three real bugs surfaced
and are already fixed in the version above (the checkout ordering, the
`security-scan/`-prefixed artifact path, and the shell-variable diff
round-trip). Each is called out inline where it was fixed, with what the
live failure actually looked like.

All three workflows on this page (`analysis.yml`, `publish-results.yml`,
`apply-fix.yml`) are **consumer-side examples**: they are meant to be
copied into a repository you want scanned, and none of them exists in this
repository. This repo's own `.github/workflows/` holds only its build and
release plumbing.

## Deferred (not in this action yet)

- **`--stop-after` as an `action.yml` input**: the CLI supports it (as a
  raw `String` now; see `bc-cli`'s `non_empty`/`parse_stop_after`, the
  same empty-string-tolerance mechanism `app-id`/`cmdb-csv` now use), but
  it has no value that's meaningful to expose the way those two do: a CI
  consumer almost always wants the full scan, not an early stop; this is
  primarily a debugging/development flag. Not exposed as an input,
  though nothing structurally blocks it if a use case comes up.
- **Pointing `action.yml` at a pre-built image instead of building from
  `Dockerfile` on every run**: an image in a private, authenticated
  registry can't back this action's default reference for external
  consumers without also exposing pull credentials, and this repository
  publishes no public image. Inside one organization this is a solved
  problem: publish to your own registry and pull it by digest, which is
  what [`deployment.md`](deployment.md) covers.
- **`--post-comments-from`/`--post-fixes-from` as `action.yml` inputs**:
  still not exposed. These are a different MODE (posting from
  an already-written JSON snapshot, not scanning), mutually exclusive with
  every other input this action's single `args:` array is built around,
  and always run from the privileged `workflow_run` job rather than
  alongside the scan itself. Exposing them means either a second,
  differently-shaped action or making `action.yml`'s whole args list
  conditional on a "mode" input: a real design question, not just the
  empty-string-tolerance fix above. Consumer workflow 2's `docker run`
  steps remain the way to invoke these today, and work fine as-is (no
  static-args-array limitation applies to a plain shell step).
  `--remediate`/`--out-remediation-json`, by contrast, ARE now real
  `action.yml` inputs (`remediate: "true"`), and they fit the single-mode
  "run a scan" shape this action was already built around.
- **`--diff-scope`/`--pr-comments`/`--github-token`/`--github-repo`/
  `--pr-number` as `action.yml` inputs**: see "Scoping a scan to the PR's diff" above for
  why and the `docker run` workaround. `--diff-scope` itself is a bare
  flag (`#[arg(long)]`, not `--remediate`'s `num_args = 0..=1`
  explicit-value-capable shape), so (unlike `--stop-after`, which is a
  `String` that already tolerates the empty string and could therefore be
  an unconditional `args:` element today) it cannot go into the static
  `args:` array as-is. Nothing structurally blocks adding it
  (and the three GitHub flags, which workflow 2 already threads through
  as plain strings) the same way `--remediate` was, if a real use case
  comes up.
- **`--gc`/`--gc-run` as an `action.yml` input**: not exposed. It's a
  local checkpoint-state maintenance operation on `$BC_STATE_DIR` (no
  GitHub credentials, no repo content, no scan) that belongs on a
  scheduled maintenance job against the runner's persistent state volume,
  not a per-PR scan workflow step. See `docs/USER_GUIDE.md` §1b.
