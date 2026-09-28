# Third-party scan ingestion

`bc-sast` can ingest findings exported from five third-party SAST/SCA
scanners (Checkmarx, Snyk, Semgrep, Aikido, and Sonatype) alongside its
own LLM-driven scan. This is a **new feature with no Python-original
precedent**: the original tool has no third-party SAST/SCA ingestion of
any kind (confirmed by an exhaustive grep of the Python source for all
five vendor names). Don't confuse this with the CMDB CSV feature
(`--app-id`/`--cmdb-csv`, see [`configuration.md`](configuration.md)).
That's a separate, already-ported feature that enriches an *existing*
finding's environmental CVSS score, and never constructs new findings.

## Flags

Each vendor gets its own repeatable flag. Pass it once per file, or
repeat it to ingest several exports from the same vendor in one run:

| Flag | Format |
|---|---|
| `--checkmarx-xml` | Checkmarx CxSAST classic `CxXMLResults` XML report |
| `--snyk-json` | Snyk CLI JSON, one of `snyk test --json` (SCA `vulnerabilities[]`), `snyk test --all-projects --json` (a top-level **array** of those), or `snyk code test --json` (SAST, **SARIF**) |
| `--semgrep-json` | Semgrep native JSON (`semgrep scan --json`, `results[]` shape) |
| `--aikido-json` | Aikido Security "Export Issues" API JSON (a plain array of issue objects) |
| `--sonatype-json` | Sonatype Lifecycle/IQ Server raw report JSON (`components[].securityData.securityIssues[]` shape) |

All five default to empty. Omitting them is a full no-op, every existing
scan behaves exactly like today. A malformed or unreadable file is a WARN
to stderr, never a hard scan failure: third-party ingestion is a
best-effort enrichment layered on top of the LLM-driven scan, not
something that should abort a scan the operator otherwise wanted to run.

## Which format per vendor

Real vendor export shapes disagree with themselves across products and
API versions far more than you'd expect (see `bc-thirdparty`'s own crate
and module doc comments for the full research trail). Each parser targets
the shape(s) an operator is actually likely to have archived from CI:

- **Checkmarx**: CxSAST *classic* (on-prem) XML, not Checkmarx One's
  newer SARIF/JSON export. Classic XML is the stable, versioned,
  publicly-documented format; Checkmarx's own CSV UI-table export has no
  fixed public column schema (columns are user-configurable in the
  Results Viewer), so it isn't supported. The parser reads the
  `<Path><PathNode>` dataflow (source to sink, in element *text*) and the
  `Result@Status` (`New`/`Recurrent`) into the finding description.
- **Snyk**: three shapes, because all three are things `snyk` actually
  writes: `snyk test --json` (one SCA object), `snyk test
  --all-projects --json` (a top-level **array** of them, what a polyglot
  repo produces), and `snyk code test --json`, which is **SARIF** and is
  the only file-based path Snyk's SAST findings have.
- **Semgrep**: native JSON's SAST shape (`results[]`), not Semgrep Supply
  Chain's separately-shaped `vulns[]` array, and not SARIF (which drops
  the `fix` autofix field entirely, a known upstream Semgrep
  limitation). Both severity generations are understood: `CRITICAL`/
  `HIGH`/`MEDIUM`/`LOW` (Semgrep ≥ 1.72) and the legacy `ERROR`/
  `WARNING`/`INFO`. `metadata.cwe` is accepted as either a list or a
  single string (custom rules routinely write the latter).
- **Aikido**: the Export Issues API JSON. A documented SARIF export for
  the real product could not be confirmed, and the dashboard's CSV export
  has no published column schema.
- **Sonatype**: the raw report JSON. The policy-violations API and the
  Vulnerability Details API each use different, only partially-overlapping
  shapes (the latter has richer CWE/remediation text, but is a separate
  per-finding lookup this parser doesn't make).

### Findings a human already triaged out are skipped

Consistently, across every vendor that records the decision, an
operator's explicit "not a problem" shouldn't reappear as a fresh,
unreviewed finding:

| Vendor | Signal |
|---|---|
| Checkmarx (XML) | `Result@FalsePositive="True"` |
| Checkmarx One (live) | `state` of `NOT_EXPLOITABLE` / `PROPOSED_NOT_EXPLOITABLE` (also filtered server-side via `state=TO_VERIFY&state=CONFIRMED&state=URGENT`) |
| Semgrep (file) | `extra.is_ignored: true` (a `nosemgrep` comment) |
| Semgrep (live) | `status=open` |
| Snyk (live) | `status=open`, `ignored=false` |
| Aikido (live) | `filter_status=open` (the endpoint otherwise returns open **and** ignored/snoozed/closed) |
| Sonatype | `securityIssues[].status` of `"Not Applicable"` |

### Every export file is read under a size cap

Each file given to `--checkmarx-xml`, `--snyk-json`, `--semgrep-json`,
`--aikido-json` or `--sonatype-json` is read with a 256 MiB cap
(`MAX_VENDOR_EXPORT_BYTES` in `bc-orchestrator`). The size is checked
before reading and the read itself stops at the cap, so an oversized or
growing file is never loaded whole. A file over the cap is skipped with a
WARN naming it, and its ingestion record says the export could not be
read. Parsers can be stricter still: Checkmarx reports stop at 64 MiB
(below).

### Checkmarx XML is read under safety limits

A report file is untrusted input: whoever can hand the operator a file,
or commit one a CI job picks up, controls its contents. `--checkmarx-xml`
reports are therefore read with `bc-xml`, the workspace's bounded XML
reader, and refused outright when they cross any of these lines:

| Limit | Value | Why this value |
|---|---|---|
| File size | 64 MiB | The parsed tree costs about 36 bytes of memory per byte of a typical indented export, so this caps the peak near 2.3 GB. Very large real scans (tens of thousands of results) stay well under it. |
| Element nesting | 32 levels | A CxXML report nests eight levels deep (`CxXMLResults/Query/Result/Path/PathNode/Snippet/Line/Code`). |
| Nodes (elements, text runs, comments) | 10 million | A realistic 64 MiB export has about 5.2 million; this only trips on input denser than any real report. |
| Attributes per element | 256 | `bc-xml`'s default. |

A `<!DOCTYPE` is always refused, with or without an internal subset, so
external entities (XXE) and entity expansion ("billion laughs") cannot
happen. Only the five predefined entities (`&amp;`, `&lt;`, `&gt;`,
`&apos;`, `&quot;`) and character references are decoded. Real CxSAST
exports (an XML declaration, UTF-8, no DOCTYPE) are unaffected; a leading
byte order mark and CDATA sections are accepted.

A refusal is the same WARN-and-skip as any other malformed export. The
WARN names the file and the safeguard that fired, for example:

```text
[checkmarx] failed to parse reports/cx.xml (Checkmarx XML report refused
by a safety limit: line 1, column 1: input is 70000000 bytes, over the
67108864-byte limit (reports are capped at 64 MiB, 32 levels of nesting
and 10000000 nodes)); skipping
```

The reader is stricter than the hand-written parser it replaced: an
undefined entity such as `&nbsp;`, a bare `&`, or content after the root
element is now an error rather than being passed through or ignored.
.NET's `XmlWriter`, which writes CxSAST reports, never produces any of
those. The old parser also had no depth or size bound, so a report of
200,000 nested elements overflowed the stack and aborted the whole scan;
it is now an ordinary refused export.

## How ingested findings are processed

1. Each file is read and parsed into `bc-thirdparty`'s normalized
   intermediate representation (`ThirdPartyFinding`), then converted into
   this pipeline's own `bc_model::Finding` shape
   (`bc_thirdparty::to_finding`):
   - `chunk_id` is synthesized as `"external:<vendor>:<external_id>"`, and
     is audit-trail-only (rendered in the "Dropped Findings" table if the
     finding is later dropped), never a lookup key anywhere in this
     codebase.
   - `votes` is always `1`: one vendor scanner made one detection, the
     honest value, not a fabricated consensus count.
   - `code_snippet` is left empty, because S6's verifier always re-reads
     the real source itself via its own Read/Grep/Glob tools rather than
     trusting a caller-supplied snippet.
   - `vuln_class` is inferred from the vendor's CWE (when present) via a
     small, deliberately approximate classifier from a CWE to a
     `VulnClass`, falling back to `Other` (always a safe, harmless
     classification) when the CWE is absent or unrecognized.
   - Vendor severity is mapped onto a shared 5-point scale
     (Critical/High/Medium/Low/Info), then onto `confidence` in `[0,1]`.
2. Converted findings are merged into the pipeline's own findings
   **after S5 completes, before S6 runs**, never through S4 (chunk-scoped
   re-discovery; a vendor already found these) or S5 (its
   confidence-threshold/evidence-requirement gates are tuned for this
   pipeline's own noisy first-pass LLM output, not vendor-scanner output).
3. They get real **S6 adversarial re-verification**: the same LLM
   verifier that grades every LLM-discovered finding reads the actual
   source and judges whether the vendor's claim holds, exactly as it does
   for anything else, and can produce a `FalsePositive`/`Unconfirmed`
   drop just like any other finding.
4. Verified findings then go through real **S7 cross-origin
   deduplication** against the LLM's own findings. S7's dedup logic has
   no concept of "origin," only a finding's own content fields (file,
   line, vuln class, CWE, title/description), so a vendor-reported
   finding and an LLM-discovered one at the same location collapse
   together exactly as two LLM-discovered findings would.

## Interaction with `--diff-scope`

A diff-scoped scan (see [`USER_GUIDE.md` section 1a](USER_GUIDE.md)) is
confined to the pull request's changed files. Ingested vendor findings are
confined to the same boundary, and it is applied at the merge point in
step 2 above, before S6 ever sees them.

- **A vendor finding in a changed file behaves exactly as described
  above**: real S6 re-verification, real S7 dedup, reported, PR-commented
  and remediable like any other finding.
- **A vendor finding outside the changed files is retained, not
  discarded.** It is recorded with the drop reason `OUT_OF_DIFF_SCOPE`,
  which means one specific thing: this scan never examined that file, so
  it has neither confirmed nor refuted the vendor's claim. It appears in
  `report.md`'s `## Dropped Findings` section tagged
  `[OUT OF DIFF SCOPE]`, is counted on its own `Outside the PR diff` line
  in the `## Verification` block, stays in the provider ledger with the
  scope reason recorded as its limitation, and is surfaced in
  `report.sarif` as a run-level note. Dropping it silently would let a
  reader take the absence as evidence that the vendor's finding was
  resolved, which it is not.
- **It is not a finding, so it reaches nothing that consumes findings.**
  It is absent from `report.md`'s `## Findings` section, from
  `report.sarif`'s `results`, from `findings.json`, and therefore from
  `--pr-comments`. That last one is the point of the boundary:
  `--pr-comments` requires `--diff-scope` precisely because a comment can
  only anchor to a line the pull request changed, and provider findings
  used to reintroduce unanchorable comments through a side door.
- **It is never a remediation candidate.** S10 refuses any finding whose
  file is outside the changed set, independently of what reached it, and
  records the refusal with the policy action `out_of_diff_scope`. See
  [`remediation.md`](remediation.md).
- **Provider write-back is refused for the whole run.** `--provider-writeback
  apply` is rejected up front when combined with `--diff-scope`, and the
  generated plan carries the `full_scan_required` blocking reason for every
  origin. See [`provider-writeback.md`](provider-writeback.md).
- **Path matching is exact after normalization** (leading `./` and `/`
  stripped, backslashes folded to forward slashes), and it fails closed: a
  vendor path that cannot be matched to a changed file is treated as out
  of scope. No suffix or basename matching, so a vendor finding in
  `vendor/copy/src/app.py` never passes for a changed `src/app.py`.

Without `--diff-scope` none of this applies: every ingested finding is
processed exactly as steps 1 to 4 describe.

## Known limitations

- **SCA findings have no source line.** Snyk, Sonatype, and Aikido's
  `open_source`/dependency-type issues report a vulnerable *dependency*,
  not a specific line of code, so `line_start`/`line_end` default to `1`,
  and `file` is the best available manifest/package reference (e.g.
  `package.json`, a `pkg:npm/...` purl, or `group:artifact@version`).
  S6's verifier degrades gracefully when a line doesn't obviously relate
  to the claimed issue, because the finding's title/description still
  carries the real package/version evidence for the LLM to reason about.
- **Aikido's export has no description or remediation text field at
  all** (`how_to_fix` lives on the separate *issue group* resource, not
  on an exported issue). `description` is synthesized from the
  structured metadata that is present: `rule`, issue type,
  `affected_package`, `installed_version`, `patched_versions` and
  `cve_id`; `recommendation` is always empty for Aikido findings.
- **Aikido issue types with nothing to verify in the repo are skipped**:
  `cloud`, `scm_security` (posture findings about an account or an SCM
  configuration), `eol` (a support-date fact), `license` (legal /
  compliance) and `malware` (a registry-level verdict about a published
  package). S6 could only ever mark these unconfirmed.
- **Snyk issue types `license`, `config` and `cloud` are likewise
  skipped** by the live client, for the same reason.
- **Checkmarx classic XML has no free-text description field either.**
  It's a UI/database-only thing, not part of the report, so
  `description` is synthesized from the rule name, the location, the
  `Result@Status`, and the `<PathNode>` dataflow from source to sink.
- **Sonatype's raw report has no CWE at all** by default (only available
  via a separate Vulnerability Details API lookup or an opt-in
  `customData` query param, neither of which this parser reads). Sonatype
  findings always have `vuln_class: Other` unless a future revision adds
  that lookup. `dependencyData.directDependency` *is* surfaced in the
  description ("Direct dependency." / "Transitive dependency."), since it
  is the one decision-relevant fact the raw report does carry.
- **Checkmarx One's live client is SAST-only.** It reads
  `/api/sast-results` (typed `SastResult` objects with `queryName`,
  `cweID`, `similarityID`, `nodes`) rather than the multi-engine
  `/api/results`, whose per-engine payload is an untyped `data` object.
  The cost, stated plainly: IaC/SCA/secrets findings from a Checkmarx One
  scan are **not** ingested by that client.

See `crates/bc-thirdparty/src/*.rs`'s own module doc comments for the
exact field-by-field mapping per vendor, and confirmed CWE-format/
severity-scale quirks (e.g. Semgrep's `metadata.cwe[]` is a full
descriptive string, not a bare id; Sonatype's severity is numeric CVSS,
not a word bucket).

## Live vendor API fetch

Every flag above requires an operator to export a report file by hand
first. The flags below instead call each vendor's own REST API directly
to fetch the **latest scan of this same repo+branch**, no manual export
step needed. They are implemented in the separate `bc-thirdparty-api` crate
(`crates/bc-thirdparty-api/src/{semgrep,snyk,sonatype,aikido,checkmarx}.rs`),
purely additive alongside the file-based flags: both feed the identical
S6-verify/S7-dedup pipeline described above (the file-based `_xml`/
`_json` flags and the live flags below can be used together in the same
scan, one vendor via a file, another live, with no conflict).

Each vendor is **all-or-nothing**: every flag marked required below must
be present, or that vendor's live fetch is silently skipped (matching
`--github-token`/`--github-repo`/`--pr-number`'s own precedent). A
missing flag is never an error, just an inactive vendor. A live fetch
that fails (network error, auth failure, malformed response) is the same
WARN-and-skip degrade as a bad file: never a reason to abort the scan.

| Vendor | Required flags | Optional flags |
|---|---|---|
| Semgrep | `--semgrep-token` (env `SEMGREP_TOKEN`), `--semgrep-deployment-slug`, `--semgrep-repo` | `--semgrep-branch`, `--semgrep-base-url` |
| Snyk | `--snyk-token` (env `SNYK_TOKEN`), `--snyk-org-id`, `--snyk-project-id` | none |
| Sonatype | `--sonatype-base-url`, `--sonatype-username`, `--sonatype-password` (env `SONATYPE_PASSWORD`), `--sonatype-app-id` | `--sonatype-stage` (default `"build"`) |
| Aikido | `--aikido-client-id`, `--aikido-client-secret` (env `AIKIDO_CLIENT_SECRET`), `--aikido-repo-id` | `--aikido-base-url` |
| Checkmarx | `--checkmarx-base-url`, `--checkmarx-iam-url`, `--checkmarx-tenant`, `--checkmarx-api-key` (env `CHECKMARX_API_KEY`), `--checkmarx-project-id` | `--checkmarx-branch` |

Every credential-bearing flag also accepts its value via the listed
environment variable (matching `--github-token`'s own `GITHUB_TOKEN`
precedent). Prefer the env var over a literal CLI argument in CI, where
a plain argument can end up in process-listing/shell-history logs.

### How "this repo + branch" is matched

Per the user's own confirmed design: **explicit per-vendor project/org ID
config**, not automatic git-remote-URL matching. Each vendor's own data
model for "which scan is this" differs enough that a single
auto-detection heuristic couldn't cover all five honestly:

- **Snyk** ties a project ID to a specific branch already in its own data
  model, so there's deliberately no separate `--snyk-branch` flag.
- **Sonatype** has no branch concept at all; whichever branch a CI job
  scanned just overwrites that "stage"'s own report, so `--sonatype-stage`
  stands in for a branch (`"build"` is Sonatype's own default CI-scan
  stage).
- **Aikido**'s Export API has no branch filter of any kind. Its
  scanning is repo-level, tracking whichever branch is configured as
  monitored in the Aikido UI, not something choosable per API request.
- **Semgrep** and **Checkmarx** both support a real branch filter
  (`--semgrep-branch`, `--checkmarx-branch`); omit either to fetch across
  every branch that vendor has scanned for the configured repo/project.

### Vendor client architecture

Aikido's and Sonatype's live API responses are byte-identical in shape
to their file-export formats, so their live clients don't define new
response DTOs; they fetch the raw response body and hand it straight to
the existing `bc_thirdparty::sonatype::parse` /
`bc_thirdparty::aikido::parse_with_count` functions from the file-based
path above. (Aikido's live client needs the `_with_count` variant because
it pages on "was this page shorter than requested?" and must count the
RAW issues, not the ones that survive the skipped-type filter. Otherwise
one skipped issue on a full page ends pagination early and silently
truncates the vendor's results.) Semgrep, Snyk, and Checkmarx each need
new response DTOs (their live API shapes differ from any file export this
crate parses).

Auth is one of two shapes: a static header needing no refresh (Semgrep's
bearer token never expires; Snyk uses `Authorization: token <PAT>`, the
literal word `token`, not `Bearer`; Sonatype uses HTTP Basic, or a
generated user-token `userCode`/`passCode` pair in the same slot) or
OAuth2 with a cached, refreshable token (Aikido's real
`grant_type=client_credentials`; Checkmarx One's
`grant_type=refresh_token` exchange of the static API key against a
*separate* IAM/Keycloak host, not derivable from the
data-plane host, hence the separate `--checkmarx-iam-url` flag. For the
EU region that pair is `eu.ast.checkmarx.net` for data and
`eu.iam.checkmarx.net` for IAM; **an earlier revision of this document
said the EU IAM host was `deu.iam.checkmarx.net`, which is wrong**.
`deu.*` is the separate Germany (DEU) region, and an operator who copied
it would have gotten a 401 they'd have blamed on their API key.)

All five clients send their requests through one shared retry helper
(`bc-thirdparty-api/src/retry.rs`): up to 3 attempts, retrying only
`429`, `502`, `503` and `504`, honoring a `Retry-After` header in
seconds (capped at 60s) and otherwise backing off 1s then 2s. Transport
errors and other `4xx`es are not retried. This matters because a live
fetch that fails is a *warn-and-skip*: a single transient `429` otherwise
costs the operator that vendor's entire finding set for the run, with one
WARN line to show for it. Both vendors that publish rate limits document
exactly this contract: Aikido answers `429` with `Retry-After` in
seconds on a sliding one-minute window, and Snyk's own docs say "all
clients are expected to handle the `429` responses correctly, and such
requests can be retried later safely".

### Confidence per vendor (research grounding)

Read this section as a statement about *evidence*, not about quality.
**None of the five live clients has been validated against a real vendor
account** (there are no credentials for any of them), so every claim
below is "matches the primary source", never "observed working".

An earlier version of this section rated four of the five as
"confirmed"/"high confidence" while the clients could not in fact have
returned a single finding against the real API: Semgrep read a response
envelope that does not exist on that endpoint, Sonatype required a
`reportId` field the listing does not have, Snyk assigned a relative
`links.next` path verbatim as the next request URL, and Aikido typed two
nullable fields as non-nullable. All four errors came from the same
failure mode, reading a plausible-looking *component schema* or prose
paragraph instead of the operation that is actually called. The unit
tests could not catch any of them, because their fixtures were written
from the same misreadings rather than from vendor samples. What follows
is written to be falsifiable: it says which document was parsed, and what
is still guessed.

- **Semgrep**: verified by parsing
  `https://semgrep.dev/api/v1/public_v1.openapi.yaml` directly.
  Confirmed from the operation itself: the `200` body is a top-level
  `{"findings": [...]}`; the `dedup`, `status`, `page`, `page_size`,
  `repos` and `ref` query parameters and their defaults; the `SastFinding`
  fields (`id`, `match_based_id`, `severity` enum
  `low|medium|high|critical`, `rule.cwe_names`, `location.file_path`
  /`line`/`end_line`). Also confirmed: the `ListFindingsResponse`
  component (the old `sastFindings` wrapper) is referenced by no path in
  the document. *Still unverified:* that `ref=refs/heads/<branch>` is the
  right spelling for a plain branch (the spec's only example is a PR ref,
  `refs/pull/1234/merge`), and the pagination stop condition, inferred
  from the absence of any `total`/`has_more` field. The endpoint is
  tagged `Experimental` by Semgrep itself, so re-diff the spec
  periodically.
- **Snyk**: verified by downloading and parsing
  `https://api.snyk.io/rest/openapi/2024-10-15` (2.3 MB of JSON), plus
  `snyk/user-docs`' `about-the-rest-api.md`. Confirmed: `status`,
  `ignored`, `type`, `limit` (max 100) query parameters; the
  `IssueAttributes` schema including `coordinates[].representations[]`'s
  four-way `oneOf` (`sourceLocation`, `dependency`, `resourcePath`,
  `cloud_resource`), `problems[].id`, `classes[]`; `links.next` typed as
  `LinkProperty`, a `oneOf` of a string or `{href, meta}`; the four
  regional base URLs, all ending in `/rest`. *Still unverified:* the docs'
  example `links.next` is `/orgs/<id>/projects?...` with **no** `/rest`
  prefix, but this client also handles a `/rest/...`-prefixed path and an
  absolute URL, because which of the three the live API actually emits has
  not been observed. If pagination ever 404s on page two, that is the
  thing to check first.
- **Aikido**, better documented than previously claimed: Aikido ships a
  full OpenAPI 3.1 document embedded in its docs site, which was
  extracted and parsed. Confirmed: the export path is
  `/api/public/v1/issues/export` (an earlier doc comment here said
  `/api/public/v1/export/issues`, which is wrong); the four regional
  `servers` entries (`app.aikido.dev` EU, `app.us.aikido.dev`,
  `app.au.aikido.dev`, `app.me.aikido.dev`; an earlier comment listed
  three and omitted AU); every `filter_*` parameter including
  `filter_status` (`all|open|ignored|snoozed|closed`, default `all`);
  the full issue schema, in which `start_line`/`end_line` are documented
  as "'null' when the issue is not a sast or secret issue"; the OAuth2
  client-credentials token exchange; and the `429` + `Retry-After`
  rate-limit contract. *Still unverified:* nothing structural. The
  remaining risk is that this is a young API whose docs may lead its
  implementation.
- **Sonatype**: verified against `help.sonatype.com/en/report-rest-api.html`
  (fetched and read as text). Confirmed: the report listing's exact
  fields, including that there is **no** `reportId` and that the id is
  embedded in `reportDataUrl`
  (`api/v2/applications/Test123/reports/474ca...`, and `.../raw` on the
  sibling `/history` endpoint); `evaluationDate`'s offset-carrying
  RFC 3339 form; the raw report's
  `components[].securityData.securityIssues[]` shape with
  `status: "Open"`; `dependencyData.directDependency`. *Still
  unverified:* the complete set of `securityIssues[].status` values.
  `"Open"` is the only one appearing in a response sample, and
  `"Not Applicable"` is taken from the policy-condition text ("Security
  Vulnerability Status is not NOT_APPLICABLE... with status 'Acknowledged',
  not 'Not Applicable'"), so both spellings are matched. Also still
  unverified: whether the canonical SaaS hostname is
  `{tenant}.sonatype.app` or `{tenant}.iq.sonatype.app`, a low practical
  risk, since `--sonatype-base-url` is always operator-supplied in full.
- **Checkmarx One**: the weakest evidence of the five, and the most
  complex client (OAuth2 + scan resolution + paginated results).
  Checkmarx's own Stoplight docs are JS-rendered and return nothing to an
  HTTP fetch, so the sources used are the OpenAPI documents Checkmarx
  vendors into its own SDK repo (`checkmarx-ts/checkmarx-python-sdk`:
  `docs/swagger_yaml/CxOne/SAST_RESULTS.yaml`, `SCANS.yaml`,
  `SCANNERS_RESULTS.yaml`), that SDK's own `SastResult.from_dict`, and
  `Checkmarx/ast-cli`'s `internal/wrappers/results-http.go`. Confirmed
  from those: the response field is `cweID` (not `cweId`); `ID` is
  uppercase and not required, and the SDK itself keys on `resultHash`;
  `similarityID` exists and is the cross-scan-stable identity; the
  `state` filter is an array over `TO_VERIFY`, `NOT_EXPLOITABLE`,
  `PROPOSED_NOT_EXPLOITABLE`, `CONFIRMED`, `URGENT`, matched
  case-insensitively; `sort=-created_at` is a valid `/api/scans` sort
  value; `include-nodes` defaults to returning nodes only when asked.
  *Still unverified, and material:*
  - `sinkFileName`/`sinkLine`/`sourceFileName`/`sourceLine` are
    documented as query *filters* and `visible-columns` values but do
    **not** appear in the published `SastResult` response schema. The
    client reads them opportunistically and falls back to the `nodes`
    array, so it is correct either way, but the sink fields may simply
    never arrive.
  - The `Accept: application/json; version=1.0` header is declared
    `required: false` in the spec (its own example is `*/*; version=1.0`)
    and `ast-cli` does not send it. It is sent here as version-pinning
    insurance; the claim that it is *required* was not substantiated.
  - That node paths arrive `/`-prefixed (`"/src/app.py"`), which is why
    the leading separator is stripped. Stripping is harmless if they do
    not.
  - Data-flow node ordering within `nodes`: last node treated as the
    sink, first as the source, the dataflow convention, but not stated by
    any schema.
  - Whether `--checkmarx-branch` matches exactly or fuzzily on
    `GET /api/scans`.
  - The scans-list documentation page at `docs.checkmarx.com` returns a
    500 to a plain fetch, so the regional IAM/data host table
    (`eu.iam.checkmarx.net` etc.) is corroborated only by third-party
    integration docs, not by Checkmarx's own page.

### Testing

Fixtures in both crates' unit tests are copied **verbatim from vendor
documentation samples** (the response example in the vendor's own
OpenAPI document or docs page) rather than hand-written from a reading
of the prose, and the test that uses one says so. That is not a style
preference: every one of the five API bugs fixed in this revision was
invisible to a green test suite precisely because the fixture and the
client had been written from the same misreading, so the test could only
ever confirm the misreading. A fixture that came from the vendor cannot
do that.

When adding a vendor field or endpoint, prefer in this order: the
machine-readable spec (parse it; do not skim the rendered docs page), the
vendor's own SDK/CLI source, then documentation prose. Record which
one was used, plus anything still guessed, in the module doc comment and
in the section above.
