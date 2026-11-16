# Confluence and SharePoint, read-only: what the APIs actually allow

Research for `appsec-mcp`'s document sources, read off the vendor docs
rather than recalled. Nothing here is implemented. Facts are attributed;
where a page did not state something it says so, because designing a
security control on an inferred permission is how you end up with a
tenant-wide grant you did not intend.

## Confluence Cloud

### The credential: a service account with a scoped token

Three options exist and only one is suitable.

| option | verdict |
|---|---|
| unscoped API token | **no.** It acts as the user who made it and inherits their permissions, write included. Atlassian: "if you log in and do not have permission to view something in Confluence, you will not be able to view it using the REST API either" -- the converse is the problem. |
| OAuth 2.0 3LO | **no.** The only flow documented is the authorization code grant, which needs a human to authorize. No client-credentials flow is documented. |
| **scoped token on a service account** | **yes.** Atlassian Administration > Directory > Service accounts > Create credential > API token, then select scopes. "When you create a token you must select scopes for the token." |

Auth header is Basic over `email:token`:
`Authorization: Basic base64("svc@example.com:<token>")`.

**Token expiry is 1 to 365 days and cannot be disabled.** Rotation is
not optional, so the deployment has to handle a token that will expire
on a date, which matters before this is wired into CI.

### Read-only scopes

Classic (Atlassian recommends classic over granular):

- `search:confluence` -- "Search Confluence content and space summaries"
- `read:confluence-content.all` -- "Read all content, including content
  body (expansions permitted)"

Granular alternatives, if classic cannot be used:
`read:content-details:confluence`, `read:page:confluence`.

None of those is a write scope. The write set
(`write:confluence-content`, `write:page:confluence`,
`delete:page:confluence`, `manage:confluence-configuration`, ...) is
simply not requested. Note Atlassian's own caveat: "Some scopes
automatically imply that the app is granted other scopes", and which
ones is not documented -- so the granted set should be read back and
recorded rather than assumed from what was requested.

### Endpoints

Search is v1 and CQL-based:

```text
GET /wiki/rest/api/search?cql=<cql>&limit=25&cursor=<cursor>
```

Cursor pagination: "When additional results are available, returns
`next` and `prev` URLs". `limit` is capped at 25 when the body is
expanded.

A search hit carries what we need, including the age:
`results[].content.id`, `.title`, `.content.space.key`,
`.content.version.number`, and **`results[].lastModified`**.

### A security detail the API itself forces

**The `next` link in a search response is relative** -- the documented
example is `/rest/api/search?cql=...&cursor=...`, without even the
`/wiki` prefix. So the cursor must be pulled out and re-issued against
the host we were configured with.

That is the right behavior anyway: **never follow a URL taken from a
response body.** A response-supplied absolute URL is an SSRF primitive,
and here the vendor's own pagination would have broken a naive
implementation that trusted it.

Hosts to allowlist, and there are two:

- the site: `https://<domain>.atlassian.net` (path prefix `/wiki`)
- scoped tokens: `https://api.atlassian.com/ex/confluence/{cloudId}`

### Rate limits

`429` with `Retry-After` in seconds, plus `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, `X-RateLimit-Reset` (ISO 8601),
`X-RateLimit-NearLimit`. From March 2026 a points quota applies to
Forge/Connect/3LO apps; "API token-based traffic is not affected by this
change".

Atlassian's own backoff guidance, which we should just follow: retry
only when idempotent and `Retry-After` is present, exponential with
jitter, `maxRetries = 4`, cap 30s, jitter 0.7-1.3x.

**Implemented, with one gap.** `ConfluenceSource::get` retries only on
429, only when `Retry-After` is present, and waits
`retry_delay(attempt, retry_after)` -- exponential from 1s, capped at
30s, never shorter than the server asked -- through an injected sleeper,
so a test asserts the delays without taking them.

**Jitter is implemented, one-sided.** Atlassian documents 0.7-1.3x;
this spreads over 1.0-1.3x instead, and the deviation is deliberate: the
delay it multiplies has already taken the maximum of the exponential
backoff and the server's own `Retry-After`, so scaling it *down* would
retry earlier than the server asked. Spreading upward still breaks the
lockstep that jitter exists to break, and cannot under-wait.

The factor is sampled from `RandomState`, which the standard library
seeds per process from the operating system, mixed with the current
nanosecond. No dependency, and two scans starting together get
different sequences -- which is the case jitter is for.

A note on how this was nearly shipped wrong: `retry_delay` was written
and unit-tested first, and the loop was left calling `continue` without
it -- so the policy existed, passed its tests, and was never applied. A
security review caught it. The test that now guards it asserts the
*observed* sequence of waits, not that a helper returns the right number.

### Fetching one page

`GET /wiki/rest/api/content/{id}?expand=body.storage,space,version` --
the v1 content endpoint, not v2 `pages`, and the reason is confinement
rather than preference. The server checks a fetched document's space
against the operator's allowlist, which holds space **keys** (`ENG`),
matching what search returns in `content.space.key`. v2's page response
carries a numeric `spaceId` (`42`) instead, so that check compared two
namespaces and could never match: it refused every fetch while appearing
to enforce something. v1 with `space` expanded returns the key.

`space.key` is read first and a numeric `spaceId` only as a fallback, so
a v2-shaped response still parses but fails the allowlist rather than
slipping past it.

## SharePoint and OneDrive, via Microsoft Graph

> **Status, 2026-11-16. Implemented.** `BC_CONTEXT_SOURCE=sharepoint`
> serves a Graph-backed source: search the tenant for the subject's
> terms, confine the hits to the sites the operator permitted, read each
> item's metadata, and download the ones that are already text. Every
> claim below was researched against Microsoft Learn before any code was
> written, and each load-bearing claim was re-checked independently; 8 of
> the 15 re-checked in the first pass were corrected, and the second pass
> corrected three more. See "Corrections" at the end -- it is the most
> useful part of this section.
>
> **Nothing here has opened a socket to Microsoft.** See "What a live run
> still has to confirm".

### Auth, and the one parameter that is easy to miss

`POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`,
form-encoded, with `client_id`, `client_secret`,
`grant_type=client_credentials` and
`scope=https://graph.microsoft.com/.default`.

**Search with application permissions is supported**, which is the fact
the whole approach rests on. `POST /search/query` lists `Files.Read.All`
as the least privileged application permission and `Sites.Read.All` as
the higher one. Delegated permissions are not usable here: there is no
human in a scan to authorize one.

**`region` is required, and nothing defaults it.** `searchRequest`
states it plainly -- "Required for searches that use application
permissions" -- and the application-permissions concept page repeats it.
The value is the tenant's `siteCollection.dataLocationCode` (`NAM`,
`EUR`, ...). Microsoft documents neither the full set of valid values nor
what happens when it is omitted.

This is recorded first because it is the single fact most likely to have
been missed by inference. Every example on the main search page is a
delegated one, so a client written from those examples compiles, reads
correctly, and then fails every search it ever makes. It is required at
construction here (`BC_SHAREPOINT_REGION`) rather than discovered when
the one call this source exists to make comes back refused.

### What else is documented, and usable

**Resolving a site.** `GET /sites/{hostname}:/{server-relative-path}`.
The site `id` is **not a GUID**: it is a three-part comma-separated
composite of hostname, site-collection GUID and site GUID.

**Searching.** `POST /search/query` with
`{"requests":[{"entityTypes":["driveItem"],"query":{"queryString":...},"region":...}]}`.
`entityTypes` and `query` are required. `size` has two documented maxima
-- 500 on `searchRequest`, 1000 in the search overview, which also calls
200 "a reasonable page size". `fields` lets a caller ask for specific
properties, including SharePoint managed properties.

**KQL, for the query string.** Operators are uppercase and
case-sensitive (`AND`, `OR`, `NOT`); a phrase is double-quoted; a
property restriction is `property:value` with **no whitespace** around
the operator, or it degrades to free text. Documented managed properties
include `filetype:docx` and `filename:budget.xlsx`. The wildcard `*` is
prefix-matching only -- trailing, never leading -- and a query that is
empty or contains only operators "isn't valid". Length limits: 2,048
characters through the front end, 4,096 built programmatically.

**There is no documented path or site property.** The KQL reference
enumerates no property for restricting a search to a site or a path. So
a search cannot be narrowed to a site in the query, and the site
allowlist has to be applied to the results. That is where it has to hold
anyway, since an application-permission search is tenant-wide.

**Downloading.** `GET /drives/{drive-id}/items/{item-id}/content`
returns **302** to a pre-authenticated URL. The same value is available
as `@microsoft.graph.downloadUrl` via `select`, which avoids the redirect
entirely -- Microsoft calls it "the same URL that `/content` directs to".
No `Authorization` header is needed for it, and it is short-lived (the
`driveItem` page says one hour; the content page says "might expire
within minutes"). `/content` needs only `Files.Read.All` for an
application.

**Throttling.** `Retry-After` is documented in seconds, for Graph and for
SharePoint/OneDrive specifically, with Microsoft's guidance being to wait
that long and to back off exponentially when the header is absent. That
is exactly what `retry_delay` already encoded for Confluence, so the two
sources share one retry policy.

### The three problems, now decided

The previous revision of this section ended with three things that "have
to be decided, not coded around". All three are decided, and two of them
dissolved once the right question was asked.

**1. No documented download hosts -> don't send the credential.** The
only host in any Microsoft documentation is one illustrative example,
and it is absent from the enterprise-endpoints article that *does* list
`*.sharepoint.com` and `*.svc.ms`. No allowlist can be derived from the
documentation, by us or by an operator.

An allowlist was the wrong control to reach for. What matters is not
which host serves the bytes but that the bearer token never reaches it.
So the download URL is read from the item as
`@microsoft.graph.downloadUrl`, no redirect is followed at all, and the
URL is fetched by a transport method that sends **no `Authorization`
header and no cookie**, over TLS, with the body capped during the read
and the bytes treated as untrusted.

That is strictly stronger than an allowlist, and it does not depend on a
list Microsoft never published: an allowlist with a credential attached
still leaks the credential to a host on the list. Both halves are
asserted by test -- one against a recording fake, one against a real
socket that reads back the headers the request actually carried. The beta
`/contentStream` was not needed, so no beta dependency was taken.

**2. Graph cannot give us text -> read the container ourselves.**
Format conversion documents `jpg`, `pdf` and `html` and no `txt`, and
for application permissions it requires **write** scopes, which a
read-only gatherer must not hold. So a `.docx` arrives as what it is: a
ZIP archive of XML.

`appsec-doctext` reads it, along with `.xlsx` and `.pptx` (and the
macro-enabled `.docm`/`.xlsm`/`.pptm`, which are the same package
format -- this extracts text and executes nothing, so a macro is simply
a part that is not read). It has **no dependencies at all**: a DEFLATE
decoder, a ZIP central-directory reader and an XML text extractor, each
written against a frozen specification or a deliberately reduced subset
of one. `docs/supply-chain.md` section 2b records the three crates that
were vetted first and why each was declined -- the short version being
that `zip`'s entire advisory history is in `extract()`, and a reader
that takes one named entry into memory and never writes a file has no
shape for any of it.

Plain-text formats are still read as text: `md`, `txt`, `csv`, `json`,
`yaml`, `xml`, `html`, `adoc` and the rest. A text file that is not
valid UTF-8 is refused rather than decoded lossily, because mojibake in
a model prompt reads as prose.

**PDF is read too, and also with no dependency.** It was the one gap
this section previously recorded as a cost of the no-dependency rule.
`appsec-doctext::pdf` adds a tokeniser, an object model and two
generated character tables, reusing the DEFLATE decoder that
`FlateDecode` already needed.

Its limits are real, and better read here than found in a
report: reading order is single-column, so a two-column layout or a
complex table comes out jumbled; **a scanned page yields nothing**,
because an image of text holds no text, and that is reported as such
rather than as an empty document; and an encrypted PDF is refused rather
than attempted. The cross-reference table is deliberately not parsed --
objects are found by scanning -- which means a file with a broken index
still reads, and no offset the file supplied is ever followed.

**3. Scoped mode may not discover drives -> that is a permission
prerequisite, not a blocker.** This was the wrong framing. Search needs
`Files.Read.All` or `Sites.Read.All`, both tenant-wide; `Sites.Selected`
appears nowhere on the search endpoint's page. So a search-based source
simply requires tenant-wide *read* scopes, and that is a documented
prerequisite for the operator rather than something to engineer around.
Confinement then comes from the site allowlist applied to results, which
is a control we own rather than one we rent from a permission model.

### Two caveats an operator has to be told

**Private content is excluded by default.** The
application-permissions page states that app-only search "enable[s]
search on shared content and disable[s] search on private content".
Including private content needs `sharePointOneDriveOptions` with
`includeContent: "privateContent,sharedContent"`, and the page warns the
private index "can take days to a week" to build. So a design document
in a site nobody shared may simply not be found. This source does not set
that option.

**Deep paging is not available.** App-only search does not support a
`from` beyond about 1,000, and collapsing is unsupported. This source
therefore makes a single request of at most 200 hits and does no paging
at all -- which, as a side benefit, sidesteps the `$skiptoken`
contradiction recorded below entirely.

### Configuring it

The server reads its own credential from its own environment; the scanner
never holds it. Both sides name the sites, and **the strings have to
match** -- the server holds the real allowlist and refuses anything
outside it, so a site the scanner asks for and the server does not
permit is a refusal rather than a wider search.

On the server's environment (from CI secrets, in the intended
deployment):

```text
BC_CONTEXT_SOURCE=sharepoint
BC_SHAREPOINT_TENANT_ID=contoso.onmicrosoft.com
BC_SHAREPOINT_CLIENT_ID=<app registration's application id>
BC_SHAREPOINT_CLIENT_SECRET=<client secret>
BC_SHAREPOINT_REGION=NAM            # siteCollection.dataLocationCode
BC_SHAREPOINT_SITES=contoso.sharepoint.com:/sites/Engineering,contoso.sharepoint.com:/sites/Platform
BC_SHAREPOINT_SECRET_EXPIRES=2027-03-01   # optional, reported only
```

On the scan:

```sh
appsec-scan --context-mcp-server /usr/local/bin/appsec-mcp \
            --context-mcp-space 'contoso.sharepoint.com:/sites/Engineering' \
            --context-mcp-space 'contoso.sharepoint.com:/sites/Platform'
```

The app registration needs **`Files.Read.All` (application)**, which is
the least privileged permission documented for all three calls this
source makes, plus admin consent. `--context-mcp-label` is Confluence
only. Nothing else is needed: the search terms are derived from the
repository and application being scanned.

**What it will read.** Text formats (`md`, `txt`, `csv`, `json`, `yaml`,
`xml`, `html`, `adoc`, ...), Office packages (`docx`, `docm`, `xlsx`,
`xlsm`, `pptx`, `pptm`) and `pdf`. Anything else -- a legacy `.doc`, an
image -- is reported by name in the scan's context warnings rather than
skipped quietly, so a relevant document in an unreadable format is
visible and can be exported. A scanned PDF is reported the same way,
since it holds an image of text rather than text.

Every variable is required except the expiry hint, and each site is
parsed at startup -- so a site that cannot be addressed, or a missing
region, is a refusal before the first request rather than a failure
halfway through a scan. Error messages name the variable, never its
value.

### What a live run still has to confirm

The shapes below are read defensively because the documentation does not
settle them. A live run is what turns each into a fact.

- **The outer response envelope.** The resource pages document
  `searchResponse.hitsContainers[].hits[]`, and Graph returns collections
  under `value`, but no page states this endpoint's outer envelope. Both
  shapes are parsed, and a reply in neither is a reported shape error
  rather than an empty result.
- **Whether a hit's `resource` carries `parentReference`.** Graph needs a
  drive id *and* an item id to address an item, and no reference page
  promises which `driveItem` fields a search hit returns by default. They
  are requested explicitly through `fields`. A hit without them is
  skipped; *every* hit lacking them is an error, because that means the
  shape is not what this code reads and an empty gather would look like
  "nothing matched".
- **Whether `select` returns `@microsoft.graph.downloadUrl`.** The
  download example uses `select=id,@microsoft.graph.downloadUrl` (without
  the `$`, which is the form used here). The `driveItem` page does not say
  whether the property is returned by default, so it is selected
  explicitly.
- **Valid `region` values**, which are not enumerated anywhere.

### Corrections to decisions recorded earlier in this document

- **The redirect host allowlist defaulting to `*.files.1drv.com` was
  wrong**, and so was the idea of an allowlist. That FQDN is a single
  illustrative example absent from the enterprise endpoint list, and no
  allowlist can be derived from the documentation at all. Superseded by
  problem 1 above: the control is the absent credential, not the host.
- **"Re-issue the cursor against the configured host" does not transfer
  from Confluence.** Microsoft explicitly tells clients not to extract
  `$skiptoken` and reuse it, while the per-API pages list it as a
  supported input, with inconsistent casing. It also drops the query
  parameters, which live in the `nextLink`. Moot here: this source does
  not page.
- **"Scoped mode cannot use search" was true but not the useful
  statement.** The useful statement is that search requires tenant-wide
  read scopes, which makes it a prerequisite rather than a blocker. See
  problem 3.
- **`region` was not recorded at all**, and is required. A client written
  from the search page's examples -- all delegated -- would have failed
  every search.
- **`size` has two different documented maxima** (500 and 1000) on two
  reference pages. The lower figure, which is also the recommended one,
  is what this source uses.
- **The search overview contradicts the app-only pages.** It says
  "Search requests run in the context of the signed-in user, identified
  using an access token with delegated permissions", which the search
  endpoint's own permission table and the application-permissions
  concept page both contradict. The permission table was taken as
  authoritative.

## Decisions taken

### SharePoint scope: superseded by what shipped

> **Superseded, 2026-11-16.** The decision below was for two modes
> chosen by a flag. One shipped. The reasoning is kept because the
> asymmetry it names is real and still governs the deployment advice.

The original decision was a `scoped` mode (`Sites.Selected` with
`roles: ["read"]` per named site, enumerating libraries directly) as the
default, and a `tenant` mode (`Files.Read.All`, search across every site
collection) behind a flag -- on the grounds that defaulting to `tenant`
would hand an unattended CI job read access to every file in the estate
on the strength of someone not reading a flag.

**What shipped is the search mode only**, because the thing being asked
for was "search SharePoint and download what matches so the model can
judge whether it relates to this codebase", and search is the part
`Sites.Selected` cannot do. Enumerating a granted site's libraries finds
documents by position rather than by relevance, which does not answer
that.

The asymmetry the original decision named has not gone away; it is
answered differently. The grant is wide, so **confinement is a control
we own rather than one we rent from the permission model**: the site
allowlist is applied to the results of every search, an item whose site
maps to no allowlist entry is given a space name no allowlist can
contain, and the server's existing result-side check refuses it. That is
the same check that confines Confluence, and the same one a security
review found Confluence had got wrong -- which is why it is tested here
from both directions.

The honest cost, which belongs in the deployment advice rather than
hidden here: an operator granting `Files.Read.All` is granting
tenant-wide read to the app registration, and only our allowlist keeps a
scan to the sites they named. A `Sites.Selected` enumerating mode
remains a legitimate thing to add for a deployment that cannot accept
that, and it would not conflict with this one.

### The download redirect: superseded, and the reason is worth keeping

> **Superseded, 2026-11-16.** No redirect is followed at all. See
> "The three problems, now decided", problem 1.

The original decision followed the 302 under every bound that could be
applied without guessing at a vendor host pattern: one hop only, the
credential stripped, HTTPS only, an operator-configurable host allowlist
defaulting to the observed `*.files.1drv.com`, a size cap enforced
during the read, a timeout on the hop, and the resolved host recorded in
provenance.

Most of those bounds were right and survive in another form -- HTTPS
only, the cap applied during the read, the timeout, the body treated as
untrusted. Two things were wrong, and the way they were wrong is the
useful part:

- **The default host was a worked example, not a documented fact.**
  `*.files.1drv.com` appears exactly once in Microsoft's documentation,
  inside a sample response, and is absent from the enterprise-endpoints
  article that does enumerate SharePoint and OneDrive hosts. Pinning it
  would have refused every real download.
- **The control was aimed at the wrong thing.** "Make the operator
  supply the allowlist" moves a guess rather than removing it, because
  the documentation does not support *anyone* writing that list. The
  question worth asking was not "which hosts may serve the bytes" but
  "what does a wrong answer cost" -- and the answer was the credential.

Removing the credential removes the cost, which is why the shipped
version reads `@microsoft.graph.downloadUrl`, follows nothing, and sends
no `Authorization` header and no cookie to the host that serves the
bytes. The original decision's own note that "Microsoft states it is not
needed on the pre-authenticated URL, so removing it costs nothing" was
the whole answer, written down and then not followed to its conclusion.


## What this changes about the plan


- **Confluence first** is confirmed as the right order, and for a better
  reason than before: it is the one of the two that can actually be
  scoped read-only to named spaces with a service-account credential.
- **SharePoint takes a scope flag**, defaulting to `scoped`, so the
  tenant-wide grant is something an operator asks for rather than
  something they get by not reading a flag.
- **One rule gets stronger**: never resolve a URL from a response body.
  Confluence's relative `next` link makes that concrete rather than
  theoretical.
- **Token rotation is mandatory**, not a nicety, because Atlassian caps
  token life at 365 days.
