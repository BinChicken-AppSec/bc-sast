# Copy-ready GitHub Actions workflows

Workflows for **your** repositories, not for this one. Deliberately not
under `.github/workflows/`: GitHub Actions only ever scans that exact
path, so cloning or forking this repo never starts them. Copy the one you
want into the relevant repository's own `.github/workflows/`.

Both are org-neutral: no account ids, no secrets, no cloud provider, no
registry hostname. Everything environment-specific is a repository
variable, a secret, or a clearly marked placeholder.

This project's own CI is a different thing and lives where it belongs, in
[`../.github/workflows/ci.yml`](../.github/workflows/ci.yml). It builds
and tests this code on pull requests and on `main`, uses no secrets, and
has read-only permissions, so a pull request from a fork runs the full
suite with nothing to leak.

- **`build-and-publish-image.yml`**: for **this** repo (or your fork).
  Builds the image from this repo's `Dockerfile` and pushes it to a
  container registry you control, tagged by git sha plus a moving
  `latest`. Registry-agnostic: the login step is a plain `docker login`
  reading `secrets.REGISTRY_USERNAME`/`secrets.REGISTRY_PASSWORD`, with a
  commented example showing where a cloud provider's own login action
  would go instead. This is step 1-3 of
  [`../docs/deployment.md`](../docs/deployment.md).

- **`scan-on-pr.yml`**: for a **target** repo, one you want scanned. On
  `pull_request` into the protected branch it pulls the published image,
  runs the scan with `--diff-scope`, uploads SARIF to code scanning, and
  posts/reconciles the per-finding PR review comments. Runs on a
  self-hosted runner label placeholder (with a note on why ephemeral
  runners matter here), and carries an optional, commented-out
  remediation block. This is step 4 of
  [`../docs/deployment.md`](../docs/deployment.md).

`scan-on-pr.yml` is the **same-repository** shape, where the automatic
`GITHUB_TOKEN` can both read the PR diff and write review comments. Fork
pull requests get a read-only token and need the two-workflow
`pull_request` + `workflow_run` split instead.
[`../docs/github-action.md`](../docs/github-action.md) has that pattern in
full, along with the no-registry alternative (the container action in
[`../action.yml`](../action.yml), which builds the image on the consumer's
own runner).
