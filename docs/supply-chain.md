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

```text
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

## 2b. When the answer is to add nothing

The checklist above is for adding a dependency. Sometimes the right
outcome is not to, and `appsec-doctext` is the worked example: it reads
`.docx`, `.xlsx` and `.pptx` out of SharePoint, and it has **no
dependencies at all**.

The reasoning is recorded here because the conclusion is unusual enough
to be mistaken for dogma, and it is not. Three crates were vetted
properly first.

| crate | downloads | advisories | outcome |
| --- | --- | --- | --- |
| `zip` | 346M | 5, all in `extract()` | rejected |
| `quick-xml` | 550M | 2, both patched in `>= 0.41.0` | rejected |
| `miniz_oxide` | 1.1B | none, ever | the one that was defensible |

**`zip` was rejected on its advisory history, but not for the obvious
reason.** All five of its published vulnerabilities are in `extract()`:
symbolic links escaping a destination directory, path canonicalisation,
SUID/SGID preservation, permissions applied through a link, and a
process abort on a large declared size. Every one is a property of
writing an archive's contents to a filesystem, and none of them could be
reached by a reader that takes one named entry into memory.

That is not what disqualified it. Four of the five are patched only in
`>= 9.0.0`, a major release five weeks old at the time, so the only
version satisfying both the advisory database and the 30-day rule was
thirty days old *exactly* -- which is the letter of the rule and not its
spirit. Paying that for an API we would never call was the wrong trade.

**`quick-xml` was rejected because the feature set is the risk.** A
general XML parser implements document type definitions and entity
expansion, and then has to defend them; both of its advisories are the
ordinary cost of maintaining that surface. What this needed was a text
extractor, which can *refuse* those features -- so entity-expansion
attacks against it are not mitigated, they are unimplementable.

**`miniz_oxide` would have been a defensible addition** and is recorded
here so the decision is not read as blanket dependency aversion:
`forbid(unsafe_code)`, zero `unsafe` blocks, no advisory in its history.
It was not taken because DEFLATE is a frozen specification (RFC 1951)
describing a pure function from bytes to bytes, and because the result
can be checked against an implementation nobody here wrote. The
differential corpus in `crates/appsec-doctext/tests/` is compressed by
Python's zlib; without that, writing our own would have been the wrong
call.

**What replaces a dependency's reputation**, since "we wrote it" is not
by itself an argument:

- `#![forbid(unsafe_code)]`, crate-wide and compiler-enforced.
- No filesystem, no network, no path handling: `bytes in, String out`.
- Every bound enforced during the work, not after it, so a zip bomb is
  refused while being decoded rather than measured once expanded.
- Differential tests against Python's zlib, plus a deterministic
  mutation sweep asserting that corrupt input is always refused and
  never panics.
- CRC-32 checked against published vectors, so a decoder that is quietly
  wrong fails loudly rather than returning plausible nonsense.

**PDF followed, on the same terms.** The first revision of this section
said PDF could not be done without either a large parser dependency or a
project of its own, and recorded that as the cost of the rule. It was
then asked for under the same constraint, and the second horn turned out
to be affordable: `appsec-doctext::pdf` adds a tokeniser, an object
model and two character tables, reusing the DEFLATE decoder that was
already there for `FlateDecode`. Still no dependencies.

The candidates were weaker than the ones above, which made the decision
easier rather than harder: `lopdf` (30M downloads, an order of magnitude
below `zip` or `quick-xml`) carries a stack-overflow advisory from
deeply nested objects, and `pdf-extract` (8M) sits on top of it. Both
are a larger parser surface than anything already declined.

Two parts of the PDF work are technique rather than policy, because they
are what made it defensible rather than reckless:

- **The cross-reference table is not parsed at all.** A PDF normally
  locates objects through offsets it supplies. Following an
  attacker-chosen offset is a primitive worth not having, so the reader
  scans for object headers instead and keeps the last definition of
  each. That is also the repair path every serious reader needs anyway,
  so it is one code path rather than three.
- **The character tables are generated** from `cp1252` and `mac_roman`
  with the differences the specification lists, by
  `tests/generate_encodings.py`. A wrong entry in a hand-typed table is
  not a crash; it is one character that comes out wrong in documents
  nobody re-reads.

**What PDF still will not do**, stated so the limit is not discovered in
production: reading order is single-column, so a two-column layout or a
complex table comes out jumbled; a scanned page is an image of text and
yields nothing, which is reported rather than returned as emptiness; and
an encrypted file is refused rather than attempted.

**The remaining cost.** The legacy binary Office formats -- `.doc`,
`.xls`, `.ppt` -- are a different container again, with thinner crates
than any of the above. They are reported by name so an operator can
export them.

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
