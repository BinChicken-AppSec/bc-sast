# Dependency supply-chain policy

This is a security tool that runs inside customers' CI with source code and credentials.
Its own dependency tree is part of its attack surface, and so is the CI that builds
it. Three complementary controls:

## 1. Automated: `cargo-deny` (every dependency, every PR + scheduled)

`deny.toml` gates `advisories` (RustSec DB, yanked crates), `licenses` (allowlist),
`bans` (wildcard version bans, duplicate-version warnings), and `sources` (crates.io
only: no git deps, no unknown registries; intra-workspace `path` deps are allowed
by design, via `allow-wildcard-paths = true`). Run via
`cargo deny check advisories bans licenses sources`. This catches **known, already
publicly disclosed** issues across the full transitive tree. This project's own CI
runs it on every pull request, and again on a weekly schedule against the *unchanged*
lockfile, so a newly disclosed advisory against a dependency nobody touched still
trips the build.

## 2. Manual: new direct-dependency checklist (before adding to any `Cargo.toml`)

`cargo-deny` cannot catch a just-published or typosquatted malicious crate. Advisory
disclosure lags publication, sometimes by weeks. Every time a **new direct dependency**
is added (not transitive; those are covered by (1) above), check crates.io before
adding it:

```
curl -s https://crates.io/api/v1/crates/<name>
```

and confirm, at minimum:

- The specific version being pinned was published **at least 30 days ago**
  (`versions[0].created_at`), which gives the ecosystem time to notice something
  malicious.
- The crate itself has a real publication history, not a first-ever release
  (`crate.created_at`, `crate.num_versions`).
- Meaningful adoption (`crate.downloads` / `crate.recent_downloads`). A near-zero-download
  crate is a weaker signal even if old.
- A real repository link and a license in the `deny.toml` allowlist.
- No obviously typosquatted name of a well-known crate (e.g. `serde_json` vs
  `serde-json`, `tokio` vs `tokioo`).

Then pin it **exactly**. Every entry in `[workspace.dependencies]` uses `=x.y.z`,
never a caret range, so `cargo update` cannot silently move a vetted dependency onto
a version nobody has looked at.

Record the check as a comment directly above the `Cargo.toml` entry (the org/repo
it comes from, its download count, and the publish date of the pinned version) so
the reasoning isn't lost. That is the shape every existing entry already uses.

Prefer crates already in the workspace's dependency graph over adding a near-duplicate
(check `cargo tree -d` for existing near-equivalents before reaching for a new one).

## 3. CI actions are pinned the same way

A GitHub Action is third-party code with access to the build, and a tag is
mutable. Every `uses:` in `.github/workflows/ci.yml` therefore names a full
commit sha with the human-readable version in a trailing comment
(`actions/checkout@3d3c42e5... # v7.0.1`), so a compromised or retagged
upstream release cannot silently enter a build. That workflow also declares
`permissions: contents: read` at the top level, writes to nothing and uses
no secret, and triggers on `pull_request` rather than
`pull_request_target`, so a fork's pull request runs every check with a
read-only token. Bump a pin by resolving the new tag to its sha and
updating the comment with it.
