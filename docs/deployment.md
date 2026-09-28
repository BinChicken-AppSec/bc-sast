# Deploying `bc-sast`

The recommended way to run `bc-sast` across an organization is to build it
**once**, publish it as a container image to a registry you control, and
have each target repository pull that image from a pull-request workflow.
Four steps:

1. **Build the artifact** in CI: `cargo build --release -p bc-cli --bin bc-sast`.
2. **Containerize it** using this repo's own `Dockerfile` (multi-stage,
   `cargo-chef`-cached, minimal nonroot Wolfi runtime).
3. **Push the image** to your own container registry, tagged by git sha.
4. **Scan on pull request** in each target repo: a workflow triggered on
   `pull_request` into the protected branch pulls that image, runs the scan
   with `--diff-scope`, uploads SARIF to Code Scanning, and (with
   `--pr-comments`, which is opt-in) posts/reconciles PR review comments.

Steps 1-3 collapse into one workflow in practice, since the `Dockerfile`
does the `cargo build` itself inside its builder stage. There is no need
to build the binary on the runner and copy it in.

Nothing here is tied to a particular cloud, registry, or IAM model. The
deployment infrastructure behind it is yours to choose. This repository covers
the registry half only (one team's OIDC-authenticated CI role and private
image registry); it is not the way to deploy this, and the public mirror
ships the scanner only: no deploy or apply workflows.

---

Full-scan remediation can also publish one new branch or produce a source
ZIP. These are opt-in delivery modes, not PR diff-scanning features. ZIP
mode works without Git and needs the consuming CI's artifact-upload step.
Target-test execution requires a vetted compiled policy and a local Linux
container backend. Only `discovered-offline` ships execution authorization;
other testing levels do not execute code. That profile installs the
target's declared dependencies in one networked container per package
before the test phases, which stay network-isolated, so the engine's host
needs outbound access to the ecosystems' package registries. See
[remediation delivery](remediation-delivery.md) and
[target testing](target-testing.md) before configuring these paths.

## 1-3. Build, containerize, push

One workflow in the scanner's own repository. Registry-agnostic: replace
`REGISTRY`, `IMAGE`, and the login step with whatever your registry needs
(a docker-login action, a cloud CLI login, a `docker login` with a token
from your secret store).

> **Pin these actions before you use them.** The workflow examples below
> reference third-party actions by tag, such as `actions/checkout@v4`,
> because a tag stays readable and does not rot in prose. A tag is
> mutable: whoever controls it can repoint it at different code, which
> then runs with your workflow's permissions. This project pins every
> action in its own `.github/workflows/ci.yml` to a full commit SHA, and
> you should do the same in anything you actually deploy.

```yaml
name: publish scanner image
on:
  push:
    branches: [main]

# Only needed if your registry authenticates via OIDC. Delete both lines
# for a username/password or token login.
permissions:
  contents: read
  id-token: write

env:
  REGISTRY: registry.example.internal   # your registry host
  IMAGE: security/bc-sast               # your repository path in it

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Log in to the registry
        # Replace with your registry's own login mechanism. Read the
        # credential from your CI secret store; never inline it.
        run: |
          echo "${{ secrets.REGISTRY_PASSWORD }}" \
            | docker login "$REGISTRY" -u "${{ secrets.REGISTRY_USERNAME }}" --password-stdin

      # Tag by git sha, not by a moving tag: a scan result is only
      # reproducible if you can say which scanner produced it. `latest`
      # is published alongside for convenience, never used by a gate.
      - name: Build the image
        run: |
          docker build \
            -t "$REGISTRY/$IMAGE:${{ github.sha }}" \
            -t "$REGISTRY/$IMAGE:latest" \
            .

      - name: Push
        run: |
          docker push "$REGISTRY/$IMAGE:${{ github.sha }}"
          docker push "$REGISTRY/$IMAGE:latest"
```

What the build produces: a `cgr.dev/chainguard/wolfi-base` runtime image
with `git` installed, whose entrypoint is `/usr/local/bin/bc-sast`,
running as uid 65532. Roughly 135MB. `docker run <image> --repo /workspace`
passes flags straight to the binary. The base is glibc-based rather than
musl because `reqwest`'s resolved rustls backend pulls in `aws-lc-sys`, a
native C/C++ dependency. Both stages are pinned by digest. The
`Dockerfile`'s own header comment carries the full rationale.

**It ships a shell and a `git`, on purpose.** The runtime used to be
`gcr.io/distroless/cc-debian12:nonroot`, which had neither and was about
33MB smaller. That absence disabled the `step_remediate.verify_command`
safety gate outright (with no `sh`, it fails closed and downgrades every
fix to `Needs Review`), disabled the git revert backstop, disabled
worktree isolation for `--remediate`, and forced `--git-sha` to be passed
by hand. What did not change is the agent's reach: its tool allowlist is
Read, Glob, Grep, Edit and Write, with no shell tool of any kind, so the
posture moves from "no shell exists" to "a shell exists and the agent
cannot reach it". The only string that reaches `sh -c` is
`step_remediate.verify_command`, which comes from operator config, has no
default, and spawns nothing when unset.

**Expect to add your own toolchain.** The image ships a shell, `git` and
the scanner, and nothing else: no compilers, test runners or language
package managers. A `verify_command` naming a tool the image does not
have will fail the gate closed on every fix. The intended pattern is a
thin image of your own on top of this one:

```dockerfile
FROM registry.example.internal/security/bc-sast:<sha-or-digest>
USER root
RUN apk add --no-cache python-3.12 py3.12-pip   # whatever verify_command needs
USER nonroot
```

**Give the checkout to uid 65532, or `git` inside the container refuses to
touch it.** This is the one thing that decides whether shipping `git` buys
you anything. A bind-mounted checkout keeps the runner's ownership, and
git 2.35 and later refuse to operate on a repository owned by a different
user:

```
fatal: detected dubious ownership in repository at '/workspace'
```

`bc-sast` probes rather than assumes, so it degrades exactly as it did
under the old shell-less image: `report.git_sha` falls back to whatever
`--git-sha` you passed, remediation runs in place with a printed note, and
the git revert backstop stays a no-op. Nothing breaks; the features
simply do not fire. Verified against this image, git 2.55.

Two ways to fix it, both confirmed working:

```sh
# Preferred: hand the checkout to the container's uid.
sudo chown -R 65532:65532 .

# Or mark it safe for the one directory, without touching ownership.
docker run --rm \
  -e GIT_CONFIG_COUNT=1 \
  -e GIT_CONFIG_KEY_0=safe.directory \
  -e GIT_CONFIG_VALUE_0=/workspace \
  -v "$PWD:/workspace" <image> --repo /workspace
```

The image does **not** ship a global `safe.directory=*`. Turning off an
ownership check for every repository, by default, in a security tool is
not a decision to make on an operator's behalf. The second recipe above
is the targeted form of the same idea: it names one directory, and it
lives in the environment of one `docker run`, so no other repository on
the host is affected.

**`--doctor` tells you which state you are in.** Its `git` check probes
the scan target rather than only looking for `git` on `PATH`, so the
degradation stops being silent:

```
  ✓ git: found on PATH; /workspace is a usable worktree
  ⚠ git: found on PATH, but git refuses /workspace: detected dubious
    ownership (the repository is owned by another user). Commit-sha
    detection, remediation worktree isolation and the S10 git revert
    backstop all stay off until that is fixed.
```

Run it against the same mount the scan will use, with the same `--repo`
and the same uid, or it is answering a different question.

The GitHub Action needs neither recipe: `action.yml` marks the one
workspace it mounts as a `safe.directory` itself, because a docker
action has nowhere to run a shell step before its entrypoint. See
[`github-action.md`](github-action.md).

**Pin what you consume.** Once the image is published, target repositories
should reference it by digest (`$REGISTRY/$IMAGE@sha256:<digest>`) or by the sha
tag, not by `latest`, so a scanner upgrade is a deliberate change in each
consuming repo rather than something that happens overnight.

---

## 4. Scan on pull request (self-hosted runner)

A self-hosted runner is the preferred target: the environment is
ephemeral and under your control, the image pull stays on your own
network, and the gateway credential never leaves it. Put this in each
target repository.

```yaml
name: security scan
on:
  pull_request:
    branches: [main]        # the protected branch you are gating

permissions:
  contents: read
  security-events: write    # Code Scanning SARIF upload
  pull-requests: write      # PR review comments

env:
  SCANNER_IMAGE: registry.example.internal/security/bc-sast:<sha-or-digest>

jobs:
  scan:
    runs-on: [self-hosted, linux, x64]   # your own runner label set
    steps:
      # `ref:` is NOT optional. A bare checkout on a `pull_request`
      # trigger gives you GitHub's synthetic merge commit, not the PR's
      # real head - and this checkout is what the container scans.
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      # The container runs as a non-root uid and its entrypoint is the
      # scanner, not a shell, so nothing inside it fixes ownership before
      # the scan starts: the bind-mounted checkout has to be writable by
      # uid 65532 already. bc-sast creates its out-dir before scanning,
      # so an unwritable checkout is refused in a second rather than
      # after every LLM call has already been paid for.
      # The chown is separate from the chmod and matters on its own: git
      # 2.35+ refuses a repository owned by another user, so without it
      # every git-backed feature in the container degrades to off. See
      # "Give the checkout to uid 65532" above.
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

      - name: Pull the scanner image
        run: docker pull "$SCANNER_IMAGE"

      - name: Run the scan
        run: |
          docker run --rm \
            -v "$PWD:/workspace" \
            -e BC_GATEWAY_API_KEY \
            -e GITHUB_TOKEN \
            "$SCANNER_IMAGE" \
            --repo /workspace \
            --gateway-base-url "${{ vars.BC_GATEWAY_BASE_URL }}" \
            --dialect openai \
            --model "${{ vars.BC_MODEL }}" \
            --git-sha "${{ github.event.pull_request.head.sha }}" \
            --diff-scope \
            --pr-comments \
            --github-repo "${{ github.repository }}" \
            --pr-number "${{ github.event.pull_request.number }}" \
            --out-sarif /workspace/security-scan/report.sarif \
            --out-findings-json /workspace/security-scan/findings.json \
            --max-tokens 4000000 \
            --max-scan-seconds 3600 \
            --no-progress
        env:
          BC_GATEWAY_API_KEY: ${{ secrets.BC_GATEWAY_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-scan/report.sarif
```

Why each flag is there:

| Flag / env | Why |
|---|---|
| `--repo /workspace` | The bind-mounted checkout. Required on every invocation. |
| `--gateway-base-url` | Required. Also readable from `BC_GATEWAY_BASE_URL`. |
| `BC_GATEWAY_API_KEY` (env) | The gateway credential, passed as an environment variable rather than a CLI argument so it never lands in a process listing or a workflow log. `--gateway-api-key` is the flag equivalent. |
| `--dialect openai\|anthropic` | Which wire shape your gateway speaks. Defaults to `openai`. |
| `--model` | One model id for every stage; per-role overrides need a `--config` file. |
| `--git-sha` | **Recommended, no longer required.** The image ships `git`, so `bc-sast` can derive HEAD itself now. Pass it anyway: the workflow authoritatively knows which commit it checked out, while a shallow or detached checkout can leave `git rev-parse` reporting something else. Without a usable sha, `report.git_sha` is unset and PR-comment posting has nothing to anchor to. Pass the same sha the checkout pinned. |
| `--diff-scope` | Scopes the analysis to the PR's changed files; the rest of the repo stays available as call-graph context. Requires `--github-token`/`--github-repo`/`--pr-number` and fails hard rather than silently falling back to a full scan. |
| `--pr-comments` | Opts into posting one PR comment per finding. Without it the scan writes its reports and leaves the pull request alone, whatever credentials it holds. It requires `--diff-scope`, and refuses at startup without it, because a finding outside the diff has no line to anchor a comment to and a fix suggestion outside the diff has no commit button. |
| `GITHUB_TOKEN` (env) | Backs `--github-token`. Fetching the PR diff is a read-only call; posting comments needs `pull-requests: write`, declared above. |
| `--github-repo` / `--pr-number` | Identify the PR to read the diff from and post comments on. |
| `--out-sarif` / `--out-findings-json` | Explicit output paths under the bind mount. Both are written into `<repo>/security-scan/` by default anyway (as are `report.md` and `report.csv`, with no flag at all); naming them keeps the upload step's path obvious. `--out-dir` would move all four at once. |
| `--max-tokens` / `--max-scan-seconds` | Spend caps. Neither aborts the run: they stop *starting* new S4-S7 work, let in-flight work finish, and still produce a report, with the shortfall named in `## Scan Health` and every unexamined candidate reported as "not verified" rather than as a finding. Pick numbers your finance and CI-timeout budgets can both live with. |
| `--no-progress` | The live progress bar auto-disables on a non-TTY anyway; passing this makes it explicit and keeps CI logs clean. |

**Fork pull requests need the two-workflow split instead.** `GITHUB_TOKEN`
is read-only for a PR opened from a fork, so a single workflow cannot both
scan and post. Split it into an unprivileged `pull_request` scan job that
uploads its SARIF/findings as artifacts and a privileged `workflow_run` job
that consumes them. The full pattern, and why it is safe here, is in
[`github-action.md`](github-action.md).

### Hosted-runner variant

The same workflow runs unchanged on GitHub-hosted runners; only two things
differ:

- **`runs-on: ubuntu-latest`** instead of your self-hosted label set.
- **Registry reachability.** A hosted runner has to be able to reach your
  registry over the public internet and authenticate to it. If your
  registry is private and network-restricted, either publish a mirrored,
  read-only copy for CI, or build the image on the runner from this repo's
  `Dockerfile` instead of pulling one. That is exactly what `action.yml`
  does (`runs.image: "Dockerfile"`), at the cost of a container build on
  every run.

Everything else (the `chmod`, `--git-sha`, the flag set, the SARIF upload)
is identical. Prefer a self-hosted runner where you can: the environment
is ephemeral, and the gateway credential and the scanned source both stay
inside your own network.

---

## Batch and scheduled scans

`--diff-scope` on a PR covers the change; a periodic full scan covers the
rest of the estate. `--repo-file` takes a manifest and scans every entry in
sequence, each writing its own `security-scan/` output plus one roll-up
`batch_summary.md`:

```yaml
name: nightly estate scan
on:
  schedule:
    - cron: "0 2 * * *"

jobs:
  batch:
    runs-on: [self-hosted, linux, x64]
    steps:
      - uses: actions/checkout@v4        # the repo holding repos.csv

      - name: Scan every repo in the manifest
        run: |
          docker run --rm \
            -v "$PWD:/workspace" \
            -v "$PWD/.bc-state:/state" \
            -e BC_GATEWAY_API_KEY \
            -e BC_GIT_TOKEN \
            -e BC_STATE_DIR=/state \
            "$SCANNER_IMAGE" \
            --repo-file /workspace/repos.csv \
            --workspace /workspace/batch-workspace \
            --gateway-base-url "${{ vars.BC_GATEWAY_BASE_URL }}" \
            --model "${{ vars.BC_MODEL }}" \
            --out-batch-summary /workspace/batch_summary.md \
            --max-scan-seconds 21600 \
            --resume \
            --no-progress
        env:
          BC_GATEWAY_API_KEY: ${{ secrets.BC_GATEWAY_API_KEY }}
          BC_GIT_TOKEN: ${{ secrets.BC_GIT_TOKEN }}
```

Notes:

- Each manifest row is `application_id,repository_name,path[,baseline]`
  (`.txt`) or the aliased header columns of a `.csv`. The path cell is
  either an existing local directory or a git URL, cloned into
  `--workspace`. `BC_GIT_TOKEN` (or `--git-token`) authenticates an
  `http(s)` clone URL; it is never logged or written to the summary.
- **`--resume` needs persistent state.** Checkpoints live in the SQLite DB
  at `$BC_STATE_DIR/bc-sast.db` (default `$HOME/.bc-sast/state/`). Mount a
  volume for it, as above, or an ephemeral runner throws the checkpoints
  away between runs and `--resume` does nothing. Prune it periodically with
  `--gc` (see `USER_GUIDE.md` §1b).
- Each entry can carry its **own** `--baseline` in the manifest (a 4th
  `.txt` field or a `baseline` column) so a nightly run reports what
  changed per repo. The top-level `--baseline` flag is refused alongside
  `--repo-file`, because one repo's prior findings cannot classify
  another's.
- A batch entry's failure is recorded in `batch_summary.md` and skipped,
  never fatal to the rest of the batch.

See `USER_GUIDE.md` §1d for the full manifest reference.

---

## What the scanner needs network access to

Deliberately short. In its default configuration `bc-sast` makes outbound
calls to exactly two places:

| Destination | When | Why |
|---|---|---|
| Your **AI gateway / model endpoint** (`--gateway-base-url`) | Every stage that makes a model call | The only LLM traffic. TLS verification is always on and cannot be disabled; `--ca-cert` adds a trust anchor for a private/self-signed gateway without weakening it. A gateway that authenticates callers by certificate takes `--client-cert` (and `--client-key` for a separate key file, env `BC_GATEWAY_CLIENT_CERT`/`BC_GATEWAY_CLIENT_KEY`); an unloadable certificate stops the run rather than connecting without mTLS. See [Gateway TLS and credentials](configuration.md#gateway-tls-and-credentials). |
| The **GitHub REST API** (`--github-api-base-url`, default `https://api.github.com`) | Only when `--diff-scope`, `--github-token`, `--post-comments-from` or `--post-fixes-from` is in play | Fetching a PR diff, and posting/updating review comments. Set `--github-api-base-url https://<host>/api/v3` for GitHub Enterprise Server; Actions runners already export `GITHUB_API_URL`. |

Three optional additions, each only if you turn it on:

- **Your Git remotes**, for cloning URL entries in `--repo-file` batch
  mode and for explicitly authorized `--remediation-delivery branch`
  publication. Branch publication requires a named remote and a new branch.
- **A third-party scanner's API**, if you use the live-fetch flags for
  Semgrep, Snyk, Sonatype, Aikido or Checkmarx. See
  [`third-party-ingestion.md`](third-party-ingestion.md). The file-based
  ingest flags (`--semgrep-json` and friends) need no network at all.
- **Your container registry**, at image-pull time, which is the runner's
  concern rather than the scanner's.

There is no telemetry, no update check, and no call home. `bc-sast` never
executes, builds, or runs the code it scans: the tool executor is
`Read`/`Glob`/`Grep` (plus `Edit`/`Write` under `--remediate`), path-jailed
to the repo root, with no `Bash` tool at any stage.

`--doctor` runs the readiness checks plus one live gateway probe and
exits; `--setup` runs the same checks with no network call at all. Both are
useful smoke tests for a freshly provisioned runner.

---

## See also

- [`github-action.md`](github-action.md): the container action, the
  fork-PR-safe two-workflow pattern, and how PR comments and suggested-fix
  diffs get posted.
- [`USER_GUIDE.md`](USER_GUIDE.md): the full flag reference, batch mode,
  the environment variables named above.
- [`configuration.md`](configuration.md): the optional `--config` YAML,
  including a profile for reproducible runs.
- [`outputs.md`](outputs.md): the exact shape of everything written under
  `security-scan/`.
