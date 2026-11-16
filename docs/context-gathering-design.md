# Gathering deployment context from outside the repository

Design note. Nothing here is implemented.

The point is to find and rate better. If the scan knows how an app is
deployed and used, it can tell a reachable chain from a theoretical one,
and score a finding the way the business would -- which is what decides
whether an engineer should fix it this week or this quarter.

## Most of this already exists, fed from the wrong place

Three consumers are already built and already do the work:

**Rating.** `appsec-enrich` computes an environmental CVSS score from
four facts about the application:

| fact (`AppInfo`) | feeds |
|---|---|
| `externally_facing` | `MAV`, the modified attack vector |
| `pci_scoped`, `processes_pan` | `CR` / `IR`, confidentiality and integrity requirements |
| `pii` | `CR` |

`appsec_cvss::environmental(base, mav, cr, ir, ar)` does the math, and
`appsec-stage-s8/src/severity.rs` treats the environmental rating as
**authoritative over base**. So an internet-facing PCI service already
rates the same SQL injection higher than an internal tool does.

Today those four facts come from a CMDB row, via `--app-id`. If the
deployment facts live in Confluence instead of a CMDB, the capability is
simply unavailable -- not missing, unreachable.

**Chaining.** S8's prompt already reads `call_graph`, `entry_points`,
`design_controls` and `notes`. What it cannot know from source alone is
which of those entry points is actually exposed, what sits in front of
them, and what the service can reach outbound. That is the difference
between "SSRF in an internal worker" and "SSRF in an internal worker
that can reach the metadata endpoint", and it is exactly what an
architecture page says.

**Targeting.** S2's threat model and S4's budget go further when they
know which endpoints are public and which data a path touches.

So this feature is a **second producer for existing consumers**. The
work is sourcing, typing and provenance -- not new scoring.

## Rating is not suppression

One constraint, and it is narrow.

`appsec-stage-s6/src/prompts.rs` renders an injected design control as:

> DESIGN CONTROLS IN EFFECT ON THIS PATH: ... If the control fully
> mitigates the finding, return FALSE_POSITIVE.

That path **deletes a finding**. Fed from a wiki, edit rights on a page
become finding-suppression rights, with no commit and no review, and a
two-year-old page does it by accident.

Everything above is a different operation. Changing `MAV` or `CR`
re-scores a finding that is still reported, still in the SARIF, still in
the report, with the context that moved it recorded next to it. A
reviewer can disagree and recompute. Nothing disappears.

So:

- gathered context **may** set the environmental inputs, supply topology
  to S2 and S8, and reorder priority -- freely, because all of it is
  visible and reversible;
- gathered context **is** now the only source of `design_controls`,
  since the hand-fed `--controls-file` is gone -- so every control it
  supplies carries the relevance gate and the corroboration check below,
  and reaches S2, S3, S6 and S8 as a claim about the code, not a verdict
  about it.

A gathered control claim is not discarded. It becomes a hypothesis for
code: S0 already resolves route guards and sanitizers, so "auth is
enforced at the gateway" becomes *find the guard*. Confirmed, it is
verified context and may mitigate. Unconfirmed, it is reported as a
claim the scan could not corroborate -- more useful than either trusting
or ignoring it, and often a finding in itself.

## Documents can also be handed over directly

A wiki is not the only place a design document lives. `--context-file`
takes a file or a directory of them; `--context-url` takes an https URL.
Both produce the same `SourceDocument` the MCP path produces, and both
go through the same typed extraction, the same relevance gate and the
same corroboration check. Nothing about a locally supplied document is
trusted more than a fetched one.

The URL path follows the same reasoning as the rest of this document:
the fetch never follows redirects, so a public URL cannot bounce into an
internal one; credentials in a URL are refused, because the scanner does
not authenticate to document hosts -- that is the MCP server's job and
its credential; and the link-local metadata range is refused outright.
Private and internal hosts are *not* blocked, because pointing the
scanner at an internal documentation host is the normal case rather than
an attack.

## Nothing fetched reaches a prompt as prose

> **Implemented, 2026-11-16.** `appsec-context::extract` is this
> boundary. Documents are read by a separate model call
> (`EXTRACTION_SYSTEM`, its own instructions, which cannot rate anything)
> whose only admitted output is a record set; `parse_facts` then drops any
> record whose exposure, data class, control kind or reach kind is not a
> known value, clears `notes` unconditionally, and requires every fact to
> cite the url of a document that was actually fetched. Admitted facts
> reach the stages through `AppProfile` and the design controls -- the
> shapes that already existed -- and `merge_into` may only add or raise,
> never remove or lower, so a document cannot clear a sensitivity flag or
> overrule an exposure a system of record already stated.
>
> The interim prose path that preceded this, which spliced labeled
> document text into the S2 and S8 prompts, has been removed along with
> the renderer that built it. No document prose reaches a scanning prompt.

## The shape, as built

```yaml
# All optional. Absent, a scan behaves exactly as it did before this
# existed.
id: payments-api
name: Payments API

exposure: internet        # internet | partner | internal | isolated
data: [pan, pii]          # pan | pci | pii | phi | secrets | none
availability: high        # high | normal | low -- optional

topology:
  reached_by:
    - name: edge-gateway
      kind: service
      authenticated: true
  reaches:
    - name: payments-db
      kind: database
    - instance-metadata   # a bare string, kind "other"

sources:
  - reference: docs/arch.md
    modified: 2024-02-01
```

Deliberately not the CMDB's shape, which is a ported input rather than a
chosen one. `exposure` is a scale where `externally_facing` was a
boolean that had to collapse a public endpoint and a partner API behind
mTLS into one answer. `data` is a set where three booleans were one
question with three of its answers. `availability` is new signal that
fixes an existing gap: `AppInfo::ar()` returned a hardcoded `M` because
a CMDB export has no such column, so a third of every environmental
vector carried no information.

`exposure` and `data` are required, because omitting either reads as a
safe default and under-rates. `availability` is optional, because
unstated yields the `M` every scan already produced and `M` is the middle
of the scale rather than the bottom.

`topology` is the chaining half. A call graph can show that a function
makes an outbound request; it cannot say the host on the other end is the
cloud metadata service. Rendered into S2's threat model and S8's chain
prompt as operator-stated fact, explicitly not as verified code
behavior, and `authenticated` distinguishes "nobody said" from "no".

### Still a toggle

`--context-dir` is off unless given, and a file that is present but
unusable fails the scan rather than degrading: degrading would rate every
finding as though the application were unreachable and held nothing,
which in a report is indistinguishable from a clean scan.

A CMDB still wins where there is one, so this answers only where the
CMDB did not.

## Only documents about the application under scan count

> **Implemented, 2026-11-16**, as rule 4 in `appsec_context::extract`.

A permitted space is not a single-application space. One wiki space or
document library routinely holds designs for a dozen services, and for
the first revision of this feature the extraction prompt described the
documents without ever stating which application was being scanned.
Every page's facts therefore landed in whichever application happened to
be scanned.

That is worse than noise, because of the precedence rule above: the merge
adds and raises and never lowers, so a sibling service's
"internet-facing, processes PAN" raised *this* application's rating with
nothing downstream able to undo it. The mechanism meant to stop a
document overstating a risk was being fed another application's facts.

So the extraction call is given a **subject** -- repository name, plus
the application id and name where a system of record supplied them --
stated before any document, because the question put to each document is
"is this about that?" and a document must not get to restate the subject.
The call returns a per-document verdict alongside the facts, and a fact
is admitted only if the document it cites was judged to be about the
subject.

It fails closed in both directions. A document the reply never mentions
is unrelated rather than assumed related, so a missing verdict admits
nothing instead of everything; and a verdict naming a document we never
fetched is discarded, the same check a fact's citation already passed.
Losing a fact leaves a scan rated exactly as it would be without this
feature at all, which is the recoverable direction.

The subject's terms do double duty: they ground the verdict, and a
search-based source turns them into its query. A document is then judged
on the same basis it was found on.

## Fetching: our own MCP server

An in-process connector would put a wiki token in the scanner's own
address space and in reach of a model prompt. An MCP server avoids that
structurally: the server holds the credential, the scanner calls tools,
the model sees only results. **That property comes from the process
boundary, not from who wrote the server** -- which is why writing it
ourselves keeps the benefit and drops the cost.

A third-party MCP server would be third-party code holding your wiki
token with network egress: a heavier supply-chain decision than an
ordinary dependency, and one that has to be re-made on every update. Our
own server ships in this workspace, on the same release, version, CI and
vetting posture as everything else, and the tool surface is fixed by us
rather than allowlisted against someone else's.

The honest cost: we own the SSRF controls instead of inheriting them.
For a security product that is the right side of the trade -- these are
controls we would want to have read and tested either way.

**No new dependencies.** `reqwest` is already a pinned workspace
dependency (`=0.13.4`, `default-features = false`, `rustls` only) used by
six crates, and MCP is JSON-RPC 2.0, which `serde_json` already covers.

### Shape

A separate binary, `appsec-mcp`, not linked into `appsec-scan`. The
scanner gets an MCP client and no HTTP egress of its own for this, so a
bug in the connector cannot affect a scan that does not use it.

Controls, in the server:

- **The token is read from the environment only**, held in a newtype
  whose `Debug` redacts. `appsec-github`'s `GithubConfig` derives `Debug`
  over a `pub token: String`; nothing prints it today, so it is a latent
  risk rather than a leak, but it is the pattern to not repeat.
- **A fixed, read-only tool set.** No generic request-shaped tool, which
  would be an egress channel the moment a model could call it.
- **Host, space and site allowlists**, supplied by the operator; no
  crawling, and links inside a fetched document are not followed. For a
  tenant-wide source the allowlist is applied to the *results*: Graph's
  search is tenant-wide and KQL documents no property to restrict it to a
  site, so confinement is a control we own rather than one the query
  expresses. An item whose site maps to no allowlist entry is given a
  space name no allowlist can contain, so the server's existing
  result-side check refuses it.
- **No redirect following**, so an allowlisted host cannot forward the
  request somewhere else.
- **Bounds**: document count, bytes per document, total bytes, request
  timeout.
- **`appsec-redact` before content leaves the server process.** Wiki
  spaces are full of credentials -- runbooks, connection strings,
  "temporary" tokens -- and redacting at the source means they never
  reach the scanner, let alone a prompt. `SandboxTools::new` already
  defaults `redact_reads` to true for the same reason.
- **Provenance in every result**: page URL, space, last-modified, so a
  rating stays auditable to its page and that page's age.

### What MCP still does not solve

**Prompt injection is unchanged.** MCP moves who holds the token; it does
not make a wiki page trustworthy. A fetched page is attacker-influenceable
content heading for a model that makes security decisions, so everything
above still applies: documents are parsed into the typed shape by an
isolated call, off-schema content is dropped, and no prose from a gathered
source reaches a scanning prompt.

Writing the server ourselves does not change that either. It is the one
property that no amount of credential hygiene buys.

## Sequence

1. **The typed extractor, `local_dir`, and the environmental inputs.**
   Done. Export the pages, review them, commit them, point at the
   directory. CMDB-quality rating with no CMDB, no credentials, no
   network.
2. **Topology into S2 and S8.** Done. Exposure, inbound and outbound
   reach, rendered as operator-stated fact rather than verified
   behavior.
3. **`appsec-mcp`**, our own server, Confluence first: its API gives
   labels, spaces and last-modified, so scoping and staleness are both
   expressible. Done, behind `--context-mcp-server` and off by default.
   The server holds the credential in its own process; documents are read
   by the isolated extraction call above and reach the stages only as
   typed records folded into `AppProfile` and the design controls.

   **SharePoint and OneDrive, through Graph. Done**, as
   `appsec_mcp::sharepoint`, behind `BC_CONTEXT_SOURCE=sharepoint`. It
   searches the tenant for the subject's terms, confines the hits to the
   sites the operator permitted, and downloads the ones that are already
   text. Two things about it, because they were
   decisions rather than details:

   - **The credential never leaves `graph.microsoft.com`.** Graph's
     `/content` answers 302 to a pre-authenticated URL on a host
     Microsoft does not document, so no allowlist can be written for it.
     The control is therefore the absent credential, not the host: the
     URL is read as `@microsoft.graph.downloadUrl`, no redirect is
     followed, and the fetch sends no `Authorization` header and no
     cookie. That is strictly stronger than an allowlist, which still
     leaks to a host that is on it.
   - **It reads Office documents, with no dependencies.** Graph cannot
     convert a document to text with read-only application permissions,
     so a `.docx` arrives as Office XML inside a ZIP. `appsec-doctext`
     reads `.docx`, `.xlsx` and `.pptx` and has no third-party
     dependencies at all -- a DEFLATE decoder, a ZIP central-directory
     reader and an XML text extractor, each against a frozen
     specification or a reduced subset of one.

     That is a deliberate answer to "a parser's dependency list is its
     attack surface", taken after vetting the alternatives rather than
     instead of it: `docs/supply-chain.md` section 2b has the table.
     What stands in for a dependency's reputation is
     `#![forbid(unsafe_code)]`, no filesystem or path handling at all,
     bounds enforced during decoding rather than after, differential
     tests against Python's zlib, and a mutation sweep asserting that
     corrupt input is refused and never panics.

     **PDF is read too**, on the same terms and with no dependency: a
     tokeniser, an object model and two generated character tables, on
     top of the DEFLATE decoder `FlateDecode` already needed. Its limits
     are stated rather than discovered -- single-column reading order,
     nothing at all from a scanned page (reported as such, not as an
     empty document), and encryption refused rather than attempted.

     Still unread: the legacy binary Office formats, which are a
     different container again. Those are reported by name.

   The grounded API facts, the corrections they forced, and what a live
   run still has to confirm are in `docs/context-mcp-apis.md`.
4. **Claim-to-code corroboration**, so a control claim becomes a checked
   hypothesis rather than either gospel or noise. Done, as
   `appsec_context::corroborate`, spliced into the S8 prompt.

   Each gathered control and topology edge is checked against this
   repository's own call graph, entry points and file list, and arrives
   beside what the code shows. Two verdicts, not three: **corroborated**
   (something here is consistent with the claim -- not that the control
   works) and **not corroborated** (this repository shows nothing either
   way).

   There is deliberately no "contradicted". Static signals cannot
   establish that a control is *absent*: a WAF sits in front of the
   application and leaves no trace inside it, and an authenticating
   gateway may be another repository entirely. A verdict implying
   otherwise would invite the worst reading -- treating an absence as
   proof a finding is exploitable. The block says so in those words, and
   also says never to let a corroborated claim argue the model out of
   reporting what the code shows.

   S8 and not S2, because this is where chaining and rating happen; a
   claimed control only matters once there is a finding to weigh against
   it, and S2 builds the threat model before any finding exists.

   It is a hypothesis check, not detection. A match means "the code has
   something by this name, go and look", which is worth more to a reader
   than either silence or a confident claim. `merge_into` still may only
   raise a rating, because a corroborated claim is still a claim.

Steps 1 and 2 are where the value is, and they are in. Step 3 only
changes where the documents come from -- which is why it came after the
extractor, and why that order is what made the credential question
answerable at all.

Live status: nothing in step 3 has yet run against a real Confluence. It
is proven by tests, including over a real process pipe, but the transport
has never opened a socket to Atlassian.
