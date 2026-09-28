# Target-repository testing during remediation

Target testing is opt-in and runs only after a full scan with isolated,
non-interactive remediation. It is separate from BC SAST's own Rust tests.
S8 produces the ranked typed report; S9 renders and publishes the scan
reports, followed by S10 remediation and S11 model review. S9 is
deterministic and does not call a model or reparse Markdown. Target-test
preparation runs before S10. Execution runs only with an execution-enabled
profile and a prepared local Docker environment. Postpatch execution, when
authorized, runs after S11 against the final combined proposal.

Add these options to your normally configured scanner invocation:

```text
--repo /path/to/clean/repository --remediate --target-tests comprehensive
```

`--target-tests` selects a policy embedded in the BC SAST binary. It accepts
a compiled profile name, not a JSON file path. `--target-tests` without a value
selects `comprehensive`; omitting the flag disables this workflow.
`--testing-level` is an alternate spelling.
Editing a runtime file cannot change these policies. Adding or changing a
profile requires reviewing the source policy and rebuilding the scanner.
This keeps repository contents, generated tests, and model output from
granting themselves new command or image permissions.

With default patch or explicit branch delivery, the target must be a clean
committed Git checkout and worktree creation must succeed. Explicit
`--remediation-delivery zip` instead uses an isolated source snapshot and
does not require Git. Scanning and remediation use that same copied tree. Any `--stop-after` setting, partial/diff scans,
prior-report remediation, resume, interactive remediation, in-place edits,
dry-run remediation, and the host `verify_command` are unsupported with this feature. These restrictions
bind discovery, baseline execution, and remediation to the same snapshot.
Existing scan-only and prior-report workflows do not perform target-test
planning, generation, or execution.

For a scan that only produces reports, use `--stop-after s9` without
`--target-tests`. That boundary prevents S10/S11 even when `--remediate`
is supplied. `--stop-after s8` stops before rendered report files.
Target testing requires continuing through remediation, so neither stop
boundary is compatible with `--target-tests`.

## Select testing depth

| Level | Requested scope |
|---|---|
| `discover` | Inspect the environment and record gaps without generating tests. |
| `unit` | Unit behavior and security regression tests. |
| `integration` | Unit scope plus component and integration contracts. |
| `comprehensive` | Relevant unit, integration, E2E, and security regression tests for core workflows and security-critical paths. |
| `e2e` | Alias for the cumulative comprehensive scope, including lower-level tests where appropriate. |
| `generate` | Compatible name for comprehensive generation. |
| `discovered-offline` | Comprehensive generation plus allowlisted discovered suites in ecosystem-specific Linux images, with the target's own lockfile-pinned dependencies installed first. |

These levels describe requested depth, not achieved coverage. The harness
rejects proposed test kinds outside the selected level; independent review
must assess whether the declared classification matches actual behavior.
All generation levels first discover existing tests and supply bounded
excerpts to both generator and reviewer. They should reuse suitable tests,
extend existing suites, and add missing meaningful coverage. Truncated,
inline, or undiscovered tests require further inspection and remain gaps.

A no-addition proposal can proceed only after independent model review of
existing test evidence. Test presence alone never establishes adequacy.
Generation without execution remains unverified. Levels choose test scope;
execution still requires a vetted compiled image/command policy. Only
`discovered-offline` ships execution authorization. `discover`, `unit`,
`integration`, `comprehensive`, `e2e`, and `generate` remain unauthorized
for execution, and none of them installs anything. `discovered-offline`
installs the target's declared dependencies from its lockfile, in a
separate container that is the only one with a network. See
[dependency provisioning](#dependency-provisioning).

## Discover and plan

The `discover` profile performs bounded static discovery for target testing;
S10/S11 remediation still runs because `--remediate` is required. The plan
records package manifests, native test layouts, framework hints,
workspaces, CI/service evidence, suggested commands, expectation sources,
HTTP framework evidence, API specification candidates, and risk-based
coverage obligations. Finding test files does not establish
adequate coverage. Discovery records unsupported and truncated inspection.

Select a generation level such as `--target-tests comprehensive` to request
a separate generation session and an independent read-only review session
before S10 edits production
code. Build-time `generator_model` and `reviewer_model` settings can route
these roles; otherwise both inherit the configured remediation model in
independent sessions. No particular model name is hardcoded.

The generator inspects existing tests and project contracts, then proposes
unit, integration, end-to-end, and security regression tests appropriate
to the target. Each proposal must cite an existing file, line, and exact
snippet supporting its expectations. These citations are checked locally;
the independent reviewer evaluates the behavioral interpretation. Models
can still make mistakes, and review is not executable proof.

The harness can extend existing test files or create tests in recognized
test layouts. Fixtures and setup files require exact paths in
the embedded policy's `allowed_support_paths`. Production source edits, Git
metadata, escaping paths, symlink aliases, and recognized credential-file
paths are rejected.
A reviewable batch is capped at 24 files, 64 KB per file, and 256 KB total.
Larger or underspecified applications retain explicit remaining gaps.
Inline Rust test modules inside production source are not automatically
rewritten by this test-generation path; integration tests under `tests/`
or a separately reviewed extension are appropriate alternatives.

### Generation batches and the findings budget

Generation is chunked across findings rather than refused when a report is
large. The findings evidence one generation request may carry is derived
from the generator model's context window, not written down as a fixed
byte count: the assumed window is 128,000 tokens, half of it is reserved
for the rest of the request (the role instructions, the discovery
inventory, the bounded existing-test excerpts, the read and search results
the generator collects across its turn budget, and its own reply), and the
remaining 64,000 tokens are estimated at four bytes per token. That is
256,000 bytes of findings evidence per batch today. The window is an
assumption because no per-model context limit is published anywhere in
this project; the price table carries token rates and long-context pricing
thresholds, which are not context limits. Assuming the smallest window the
generator role is routed to keeps the budget conservative.

Findings are grouped by the source file they are reported against, and a
source file's findings always stay in one batch. Tests for a source file
belong in one destination test file, so the source file is the smallest
unit that can move between batches without two batches proposing the same
destination. Groups are packed in sorted path order, so a directory's
files normally share a batch as well. Each batch is one generator session
that sees only its own findings and is told which source files it owns.

Generation is refused, never silently truncated, when:

- one source file's findings exceed a whole batch on their own, which no
  further splitting can fix;
- the report needs more than 8 batches, the ceiling on how many separate
  model calls one preparation will spend; or
- two batches propose the same destination test file. The two contents
  were written by sessions that never saw each other, so merging them
  would produce a file neither model wrote and neither reviewer would
  recognize, and keeping one would silently drop coverage the other batch
  reported as covered.

Independent review is a single session over the combined proposal from
every batch. The combined proposal is therefore bounded by the same caps
as one reviewable batch: 24 files, 64 KB per file, and 256 KB in total.
Batching bounds the evidence going in and does not buy room for more
reviewed output coming out. When more than one batch ran, the reviewer is
given each batch's source-file scope rather than every batch's findings
repeated, and the artifact records that as a remaining gap.

Generation is given the findings remediation is about to fix, which is the
same `--top N` CVSS selection S10 uses, not every finding in the report.

The remediation model receives the discovery plan. Reviewed generated
files and discovered existing tests are bound to their bytes: changing or
deleting them during remediation blocks patch export. This conservative
gate can reject an intentional compatibility change; review the contract
and tests separately rather than weaken assertions to accommodate a patch.

## API specifications

Generating levels above unit scope also look after the target's API
descriptions, in every standard the target uses. When discovery finds
evidence of an API (an HTTP framework, a GraphQL server, a messaging
client, a JSON-RPC server, gRPC, a SOAP server or an OData server) or an
existing description, the step
creates a missing document, completes or repairs an existing one, and,
when it is clearly misplaced, moves it to its framework's conventional
location, as far as each standard allows:

| Standard | Documents | What the step does |
|---|---|---|
| OpenAPI 3.0, 3.1 and 3.2, Swagger 2.0 | JSON or YAML | Creates, repairs and relocates. |
| GraphQL schema definition language | `schema.graphql`, `*.graphqls`, `schema.gql` and other SDL files | Creates, repairs and relocates. |
| AsyncAPI 2.0 to 2.6 and 3.x | JSON or YAML | Creates and repairs; never moves (no convention is read by tooling). |
| OpenRPC 1.x | JSON or YAML | Creates and repairs; never moves. |
| Protocol Buffers (proto2, proto3, editions) | `.proto` | Checks and reports only; compares services with the gRPC registrations in the code. |
| RAML 0.8 and 1.0 | `.raml` with a `#%RAML` header | Checks and reports only. |
| API Blueprint | `.apib` | Checks and reports only. |
| WSDL 1.1 and 2.0, with XML Schema | `.wsdl` (and `.xsd` files it imports) | Creates (WSDL 1.1, document/literal wrapped) and repairs; never moves (no SOAP library reads a WSDL from a fixed place). |
| OData CSDL 4.0 and 4.01 | `$metadata`, `.edmx`, `*.csdl.xml` or `*.csdl.json` | Repairs; never creates or moves (the frameworks generate CSDL from the model at run time). OData 2 and 3 metadata is checked and reported only. |

The step runs after discovery and test generation and before S10 edits
production code, so a document rides the same snapshot, the same
independent review discipline, and the same patch, branch or ZIP delivery
as the generated tests.

The step is static. The generator reads the source with the same
read-only `Read`, `Glob` and `Grep` tools test generation uses. Nothing
sends a request to the application, connects to a broker, queue or
socket, calls `rpc.discover`, `?wsdl` or `$metadata`, or fetches an
imported schema or referenced document, and no document is used to
exercise, probe or attack anything. It is a document proposed for review, like a
generated test.

| Level | API specification step |
|---|---|
| `discover`, `unit` | Skipped, and the artifact records why. |
| `integration`, `comprehensive`, `e2e`, `generate`, `discovered-offline` | Runs when discovery finds API evidence or a description; otherwise skipped with the reason recorded. |

`--api-spec auto|off` controls the step. `auto` is the default; `off` skips
it and records that it was skipped. `--api-spec-formats <list>` narrows it
to some standards, as a comma-separated list of `openapi`, `graphql`,
`asyncapi`, `openrpc`, `protobuf`, `raml`, `api_blueprint`, `wsdl` and
`odata`; the default
is every standard the profile allows. Neither flag can widen the step:
whether a profile includes it, which standards it allows, and what it may
write are compiled into the profile like every other target-testing
permission.

### What discovery provides

Discovery records three additional facts in the plan. `http_services`
lists each package directory whose manifest declares an HTTP framework,
read from dependency names rather than free text: Express, NestJS,
Fastify, Koa, hapi, Hono and Next.js from `package.json`; Flask, FastAPI,
Django, Starlette, aiohttp, Tornado, Falcon, Sanic and Bottle from Python
manifests; gin, echo, chi, gorilla/mux and fiber from `go.mod`; Spring
Boot, Quarkus, Micronaut, Ktor and JAX-RS from Maven and Gradle files;
ASP.NET Core from a web SDK project file; axum, actix-web, rocket, warp
and poem from `Cargo.toml`; Rails, Sinatra and Grape from a `Gemfile`; and
Laravel, Symfony and Slim from `composer.json`. `Gemfile` and
`composer.json` are read for this only and do not become test packages. A
Go service built on `net/http` alone declares no framework and is not
detected; neither is any framework missing from that list.

`api_surfaces` lists each package directory whose manifest declares an
API library of another kind, again from dependency names:

| Kind | Libraries |
|---|---|
| GraphQL servers | Apollo Server, GraphQL Yoga, graphql-js (`graphql-http`, `express-graphql`), Mercurius, NestJS GraphQL, TypeGraphQL, Nexus, Strawberry, Graphene, Ariadne, gqlgen, graph-gophers/graphql-go, graphql-go, Hot Chocolate, Spring for GraphQL, Netflix DGS, graphql-java, Juniper, async-graphql, graphql-ruby, Lighthouse, graphql-php |
| Messaging (AsyncAPI) | Kafka, AMQP/RabbitMQ, MQTT, NATS, SQS, SNS, WebSocket and Socket.IO clients in each ecosystem |
| JSON-RPC (OpenRPC) | jayson, json-rpc-2.0, `@open-rpc/server-js`, jsonrpcserver, json-rpc, fastapi-jsonrpc, sourcegraph/jsonrpc2, jsonrpc4j, jsonrpsee, jsonrpc-core, StreamJsonRpc |
| gRPC (Protocol Buffers) | `@grpc/grpc-js`, grpcio, `google.golang.org/grpc`, `io.grpc` and its Spring and Quarkus starters, Grpc.AspNetCore, tonic, the grpc gem and package |
| SOAP servers (WSDL) | JAX-WS (`jaxws-rt`, `jakarta.xml.ws-api`, `jaxws-api`, Apache CXF's JAX-WS frontend and Spring Boot starter), Spring Web Services, WCF (a `System.ServiceModel` assembly reference), CoreWCF, ASMX (`System.Web.Services`), spyne, PHP's SOAP extension (`ext-soap`) or laminas-soap, and the `soap` or `strong-soap` package for Node.js |
| OData servers (OData CSDL) | ASP.NET Core OData (`Microsoft.AspNetCore.OData`), SAP CAP (`@sap/cds`, `com.sap.cds`), Apache Olingo |

A Redis client is deliberately not messaging evidence on its own, because
most services use Redis as a cache, and a general cloud SDK such as boto3
says nothing about queues. Redis pub/sub is still inventoried when a
service is otherwise a messaging service. Likewise zeep and the
`System.ServiceModel.*` packages are SOAP clients, so they do not make a
package a SOAP service.

`api_spec_candidates` lists files named like a description in any
standard. For OpenAPI, strong names are `openapi.*`, `swagger.*`,
`*.openapi.*`, `*.swagger.*` and Ktor's `openapi/documentation.yaml`,
which cover the common layouts such as `swagger/v1/swagger.yaml`,
`wwwroot/swagger/v1/swagger.json`, `src/main/resources/static/openapi.yaml`,
`docs/api/openapi.yaml` and `api/openapi.yaml`. Weaker names such as
l5-swagger's `api-docs.json`, `api.yaml`, or any name containing `openapi`
or `swagger`, count only when their content confirms them. Only `.json`,
`.yaml` and `.yml` files are considered. AsyncAPI and OpenRPC follow the
same pattern with `asyncapi.*` and `openrpc.*`. For GraphQL, `*.graphqls`,
`*.gqls`, `schema.graphql` and `schema.gql` are strong, and any other
`*.graphql` or `*.gql` file counts only when it holds type definitions and
no operation. Every `.proto`, `.raml` and `.apib` file is a candidate.
For WSDL, `*.wsdl` is strong; an `*.xml` file whose name mentions `wsdl`
or `soap` counts only when its root is a WSDL description, and every
`*.xsd` file is read as a supporting document (see below). For OData,
`$metadata`, `$metadata.xml`, `$metadata.json`, `*.edmx`, `*.csdl.xml`
and `*.csdl.json` are strong, and an `.xml` or `.json` file whose name
mentions `metadata`, `edmx`, `csdl` or `odata` (such as a UI5 app's
`webapp/localService/metadata.xml`) counts only when its content is
CSDL.

Each candidate belongs to one standard: the first whose content check
confirms it, or else the first that nominates it without rejecting it.
A strongly named `openapi.yaml` that declares `asyncapi` is AsyncAPI's,
never an incomplete OpenAPI document.

### Reading an existing specification

Each candidate is read with a bounded, jailed read that refuses symlinks,
then classified by content. A document is an OpenAPI specification when
its top level declares `openapi: 3.0.x`, `3.1.x` or `3.2.x`, or
`swagger: "2.0"`; an AsyncAPI one when it declares `asyncapi: 2.0.0` to
`2.6.x` or `3.0.x`; an OpenRPC one when it declares `openrpc: 1.x`. A
misquoted `swagger: 2.0` or `openapi: 3.1` is still recognized, and the
missing quotes are reported as a diagnostic to repair.

JSON is parsed by `serde_json`. YAML is parsed by `bc_yaml::parse_strict`,
because the supply-chain policy rules out a full YAML library. The strict
parser reads block mappings and sequences, flow collections, quoted and
plain scalars, comments and `|`/`>` block scalars. It refuses anchors,
aliases, tags, multi-line plain scalars, multiple documents and duplicate
keys rather than approximating them. A YAML file it refuses is recorded as
`unverifiable`, "could not be verified by the built-in parser", and is
never modified. It is not treated as malformed: a working specification
must never be overwritten because this parser is limited. The same applies
to a file over the size cap, a non-UTF-8 file, JSON nested deeper than
`serde_json` reads, and a document declaring a version this step does not
support.

GraphQL SDL and Protocol Buffers are read by small parsers written for
this step (for the same supply-chain reason), from the GraphQL
specification (October 2021) and the protobuf language specifications. A
file either parser cannot read is likewise `unverifiable` and never
modified: these parsers are this project's own, so their refusal is never
taken as proof the file is broken. A GraphQL file holding an operation or
fragment is a client document, not a schema, and is ignored. RAML is
YAML with a `#%RAML 0.8` or `#%RAML 1.0` header; a `.raml` file without
one is an included fragment and is ignored, and one using `!include` (a
YAML tag) is unverifiable. API Blueprint is read as a Markdown outline:
the `FORMAT: 1A` metadata, headings and response items.

WSDL, XML Schema and EDMX are read with `bc_xml`, this project's own XML
reader, which refuses any DOCTYPE outright (so no entity is ever
declared, expanded or fetched), bounds the input, nesting depth,
attributes, nodes and namespace bindings, and resolves every prefix to
its namespace URI. A file it refuses, a DOCTYPE included, is
`unverifiable` and never modified. A `.wsdl` file is a WSDL 1.1 document
when its root is `definitions` in `http://schemas.xmlsoap.org/wsdl/` and
a WSDL 2.0 one when its root is `description` in
`http://www.w3.org/ns/wsdl`; the version is kept as declared. An `.xsd`
file is a supporting document: the schemas a WSDL imports are read so
that imports and the elements and types they declare can be checked, but
an XML Schema is never assessed, repaired or created on its own. An EDMX
document is OData 4 when its root is `edmx:Edmx` in the OASIS namespace
(`http://docs.oasis-open.org/odata/ns/edmx`) and legacy OData 2 or 3 in
the Microsoft namespace (`http://schemas.microsoft.com/ado/2007/06/edmx`,
told apart by `m:DataServiceVersion`); an Entity Framework designer model
(`.edmx` without `DataServices`) is not OData metadata and is ignored. A
CSDL JSON document is a JSON object with `$Version`.

A strongly named JSON file that does not parse at all is malformed, and is
the only case where a repair may replace the whole text. A strongly named,
parseable mapping with `info` or `paths` (AsyncAPI: `info`, `channels`
or `operations`; OpenRPC: `info` or `methods`) but no version key is an
incomplete specification, repaired in place.

A GraphQL schema is often split across files (Spring for GraphQL and
gqlgen read every schema file of a directory, and `extend type Query` in a
second file is idiomatic), and protobuf types and imports span files. So
validation and completeness read a document together with the
standard's other documents in the repository: their types, directives,
root fields, imports and services count as defined. Duplicates are still
checked within one document only, because two services in one repository
may each define their own `Query`. The same holds for WSDL (the messages,
port types, bindings and schema declarations of the other WSDL and XML
Schema files) and OData (the types, operations and entity sets of the
other CSDL documents). An import or reference names a file by a relative
location, while a document here is not told its own path, so a location
matches a readable file whose repository path ends with it once `./` and
`../` segments are dropped, the rule Protocol Buffers imports use.

### Where a new specification goes

A new document is created where the framework's common tooling reads a
static document, so it is served or found without extra configuration.
These locations are unverified against each framework's own
documentation. A wrong entry only affects where a new specification is
created, or whether an existing one is treated as misplaced.

OpenAPI:

| Framework | Location, relative to the service root | Why |
|---|---|---|
| Spring Boot | `src/main/resources/static/openapi.yaml` | Spring serves `static/`; springdoc's UI reads a static document through `springdoc.swagger-ui.url`. |
| Quarkus | `src/main/resources/META-INF/openapi.yaml` | SmallRye OpenAPI merges this static file. |
| Ktor | `src/main/resources/openapi/documentation.yaml` | The default path of Ktor's OpenAPI and Swagger plugins. |
| ASP.NET Core | `wwwroot/swagger/v1/swagger.json` | Static files serve it at Swashbuckle UI's default `/swagger/v1/swagger.json`. |
| Rails | `swagger/v1/swagger.yaml` | rswag's default `openapi_root` and document name. |
| Laravel | `storage/api-docs/api-docs.json` | l5-swagger's default docs path and file name. |
| Go (gin, echo, chi, gorilla/mux, fiber) | `api/openapi.yaml` | The golang-standards project layout's `api/` directory. |
| Anything else, including Express, NestJS, Fastify, Koa, Flask, FastAPI and Django | `docs/api/openapi.yaml` | Their tooling generates documents at runtime, so no static location is conventional; `docs/api/` is neutral. |

GraphQL:

| Library | Location, relative to the service root | Why |
|---|---|---|
| Spring for GraphQL | `src/main/resources/graphql/schema.graphqls` | It loads `*.graphqls` and `*.gqls` from `classpath:graphql/**/` by default. |
| Netflix DGS | `src/main/resources/schema/schema.graphqls` | It loads `schema/**/*.graphql*` from the classpath by default. |
| Lighthouse | `graphql/schema.graphql` | Its default `schema_path`. |
| gqlgen | `graph/schema.graphqls` | What `gqlgen init` writes; `gqlgen.yml` lists the files it reads. |
| graphql-java | `src/main/resources/schema.graphqls` | The application names the file; the classpath root is common. |
| NestJS GraphQL | `src/schema.gql` | Its documented `autoSchemaFile` location for a code-first schema. |
| Strawberry, Graphene, Juniper, async-graphql, Hot Chocolate, graphql-go, graphql-ruby, graphql-php, TypeGraphQL, Nexus | `schema.graphql` | These build the schema from code (code first); the file is a reviewed snapshot. |
| Anything else (Apollo Server, GraphQL Yoga, graphql-js, Mercurius, Ariadne, graph-gophers) | `schema.graphql` | The application loads a file it names; the service root is neutral. |

Other standards:

| Standard | Location, relative to the service root | Why |
|---|---|---|
| AsyncAPI | `asyncapi.yaml` | No messaging library reads a static AsyncAPI document from a fixed place; `asyncapi.yaml` at the service root (or `docs/asyncapi.yaml`) is the usual name, and any location is accepted. |
| OpenRPC | `openrpc.json` | Services serve the document through `rpc.discover`; `openrpc.json` at the service root is the usual static name. |
| Protocol Buffers | never created | Usually under `proto/` or `api/proto/`; the definition is the source of truth. |
| RAML, API Blueprint | never created | Reported where they are. |

WSDL:

| Library | Location, relative to the service root | Why |
|---|---|---|
| JAX-WS (Metro, Apache CXF, Jakarta XML Web Services) | `src/main/resources/wsdl/service.wsdl` | JAX-WS builds the WSDL from the annotated endpoint at run time unless `@WebService(wsdlLocation = ...)` names a packaged one; `src/main/resources/wsdl/` is where CXF's and the JAX-WS Maven plugins' examples keep WSDL files. The file is a reviewed snapshot. |
| Spring Web Services | `src/main/resources/wsdl/service.wsdl` | `SimpleWsdl11Definition` publishes a classpath WSDL the application names; `DefaultWsdl11Definition` builds one from an XSD at run time. |
| WCF, CoreWCF, ASMX, spyne | `wsdl/service.wsdl` | They generate the WSDL from the service contract at run time (`?wsdl`); the file is a reviewed snapshot. |
| PHP `SoapServer`, Node.js `soap` | `wsdl/service.wsdl` | The server loads a WSDL file the application names; `wsdl/` at the service root is neutral. |
| Anything else | `wsdl/service.wsdl` | Neutral. |

None of these is confident, since every SOAP library reads a WSDL from
wherever the code names it. The file name `service.wsdl` is fixed
because a convention path is static; rename the created file by hand if
the service has a better name.

OData CSDL:

| Library | Location | Why |
|---|---|---|
| ASP.NET Core OData | never created | It builds the EDM model in code (`ODataConventionModelBuilder`) and serves CSDL at `$metadata` at run time. |
| SAP CAP | never created | It compiles CSDL from the `.cds` model (`srv/`) at run time or with `cds compile --to edmx`. |
| Apache Olingo | never created | It builds CSDL from the application's `CsdlEdmProvider` at run time. |

No OData library reads a static CSDL file from a conventional place, so
the step validates and repairs an OData 4 document where it is (a copy
kept for a UI5 mock server, a gateway or documentation) and never
creates one; for a service with no document, a run note records why none
was created.

A service root is the directory of the manifest that declared the framework
or library, so in a monorepo each service gets its document under its own
root. A framework with no row of its own defers to one that has one in the
same service (graphql-java defers to Spring for GraphQL or DGS); two
conflicting conventions fall back to the standard's neutral location. New
OpenAPI documents are OpenAPI 3.1.0, in YAML unless the convention is JSON;
new AsyncAPI documents are AsyncAPI 3.0.0 in YAML; new OpenRPC documents are
OpenRPC 1.3.2 in JSON; new GraphQL schemas are SDL; new WSDL documents are
WSDL 1.1 in the document/literal wrapped style, the most interoperable one.
No document is created for a service that already owns one of that standard,
nor while an existing one sits outside every service root and may already
document it, nor when something else already occupies the conventional path.

For a code-first GraphQL library, and for JAX-WS, WCF, CoreWCF, ASMX and
spyne, the created document is a static snapshot of what the framework
builds at run or build time. The step creates it only at the convention
path and says so in the outcome: it must be regenerated when the code
changes. When a service turns out to serve no
operations of a standard at all (a messaging client used only as a
cache, say), the generator answers `not_applicable` with an empty
inventory and nothing is created.

### Relocating a misplaced specification

Only some conventions are confident, because their tooling reads the file
from that place: for OpenAPI the first six rows of its table, and for
GraphQL Spring for GraphQL, DGS and Lighthouse. For those an existing
document counts as correctly placed anywhere under
`src/main/resources/` (Spring Boot, Quarkus and Ktor), `wwwroot/`
(ASP.NET Core), `swagger/`, `openapi/` or `public/` (Rails),
`storage/api-docs/` or `public/` (Laravel), `src/main/resources/graphql/`
(Spring for GraphQL), `src/main/resources/schema/` (DGS) or `graphql/`
(Lighthouse). A repository-root `openapi.yaml` or `schema.graphqls` is not
accepted for them, because their tooling would not find it. For every
other framework and library, and for AsyncAPI, OpenRPC, WSDL, OData
CSDL and the checked standards, any location is accepted and nothing is
moved.

A move is proposed only when ownership is beyond doubt: exactly one
service owning documents of that standard, exactly one such document,
owned by that service, outside every accepted location. Otherwise the
document is assessed in place and a note explains why no move was
considered. The new path keeps the file's format, so YAML stays YAML; a
GraphQL schema takes the convention's file name, so `schema.graphql`
moving for Spring for GraphQL becomes `schema.graphqls`, which is what
Spring loads.

Before proposing a move, the step scans every text file in the repository
for the file's name. The scan never follows symlinks, skips dependency and
build output (`.git`, `node_modules`, `target`, `vendor`, virtual
environments, `dist`, `build`, `bin`, `obj`, `.next`, `.tox`), and refuses
to decide when it would exceed 20,000 entries, 32 directory levels, 4 MiB
for one file or 64 MiB in total. A mention is rewritten only when it is
exactly the repository-relative path or the path relative to the mentioning
file's directory (including `../` climbs), with or without a leading `./`,
and only in a file the compiled policy names. The shipped policies name
documentation (`*.md`, `*.rst`, `*.adoc`) and framework configuration
(`application.yml`, `application.yaml`, `application.properties`, their
`application-*` profile variants, `appsettings.json` and
`appsettings.*.json`). A policy pattern may not reach source code: each is
one file-name pattern with at most one `*`, ending in a documentation or
configuration extension.

Any other mention blocks the move: one in source code, a test, a build
file, a CI workflow, a Dockerfile, a hidden directory or a non-UTF-8 file,
a URL path such as `springdoc.swagger-ui.url=/openapi.yaml`, a
`classpath:` or `${...}` prefix, another directory's file with the same
name, or a file that already contains credential-looking values. So does a
symlink on the old or new path, or a file already at the new path. The
document then stays where it is, is still repaired in place if needed,
and the gap names each blocking reference as `file:line`. A stale
reference is worse than an unconventional location.

The reviewer is shown the move explicitly: old path, new path and every
reference to be rewritten. A rejection leaves everything unchanged. An
accepted move writes the new file, rewrites the references and deletes the
old file as one transaction, rolled back if any part fails. Patch delivery
records it as a Git rename, branch delivery commits the deletion and the
addition, and ZIP delivery packages the moved tree.

### Generation, repair and review

The generator first builds an inventory of what the code serves, each
entry with its code's file, line and an exact snippet from that line. What
an entry is depends on the standard:

| Standard | `method` | `path` |
|---|---|---|
| OpenAPI | the HTTP method | the route's path template |
| GraphQL | `query`, `mutation` or `subscription` | the root field name |
| AsyncAPI | `send` (the application produces or publishes) or `receive` (it consumes or subscribes) | the channel address: topic, queue, subject, routing key, event name or socket path |
| OpenRPC | `call` | the JSON-RPC method name |
| WSDL | `operation` | `PortType/operation` (WSDL 2.0: `Interface/operation`), or the operation name alone to match it in any port type |
| OData CSDL | `entity_set`, `singleton`, `action` or `function` | the simple name the service exposes |

No deterministic inventory of these exists in this project (the
call-graph seed engine records route patterns only for parameterized
routes, and without methods for several frameworks), so the inventory
comes from the generator and every citation is checked locally exactly
like a test expectation. The independent reviewer judges whether the
inventory is accurate and complete. For WSDL the generator looks for
JAX-WS `@WebService` classes and their `@WebMethod` methods, Spring-WS
`@Endpoint` classes and their `@PayloadRoot` methods, WCF and CoreWCF
`[ServiceContract]` interfaces and their `[OperationContract]` methods,
ASMX `[WebMethod]` methods, spyne `@rpc` methods, PHP `SoapServer`
handler classes and Node `soap.listen` services; for OData, ASP.NET Core
OData model builders (`EntitySet<T>("Name")`, `Singleton`, `Action`,
`Function`) and their controllers, SAP CAP `service` definitions in
`.cds` files, and Olingo EDM providers. AsyncAPI 2.x names operations from
the other side of a channel, so its `subscribe` operation counts as the
application's `send` and `publish` as its `receive`, matching 3.x.

For a missing OpenAPI, AsyncAPI or OpenRPC document the generator returns
the document as a JSON object, and the harness serializes it: YAML in a
conservative subset that the strict parser is tested to read back exactly
(two-space blocks, every string double-quoted), or two-space JSON, both
in the standard's conventional key order. A new GraphQL schema is returned
as SDL text and must parse as a schema. A new WSDL document is returned
as XML text, must parse with the built-in reader, and must be WSDL 1.1
document/literal wrapped: a target namespace, a SOAP binding with style
`document` and `literal` bodies, one part per message referencing a
schema element, and a service with a port (its address a placeholder
such as `http://example.com/ws/quote`). For an existing document it
returns minimal edits, each an exact text that occurs once in the current
file and its replacement, so comments, key order, quoting and
indentation survive and the diff is only the repair. The version is never
converted: Swagger 2.0 stays Swagger 2.0, AsyncAPI 2.6 stays 2.6, WSDL
1.1 stays 1.1 (with its namespace prefixes), and OData CSDL keeps its
version and its XML or JSON syntax.
`no_change` is accepted only for a document that is already valid and
documents every cited operation.

Every proposal then passes deterministic checks before any reviewer sees
it:

- It parses in its format with the built-in parser, within the 1 MiB
  specification cap. The cap is separate from the 64 KB test-file cap,
  which is far too small for a real API.
- It validates. The rules are implemented from the specifications, with
  no validator dependency, and each problem is a typed diagnostic with a
  pointer (a JSON pointer, or for SDL a `/types/User/fields/id` path):
  - OpenAPI: required `openapi`/`swagger`, `info.title`, `info.version`
    (a string) and `paths` (optional in OpenAPI 3.1 when `components` or
    `webhooks` is present); lower-case HTTP method keys; every operation
    has `responses` (a warning from 3.1, where it became optional) with
    `default`, three-digit or, from 3.0, `1XX` to `5XX` keys, each with a
    description; every `{name}` in a path template declared `in: path`
    with `required: true` at path or operation level, and no declared path
    parameter missing from the template; parameters with a name, a valid
    location and a schema or type, and none repeated; unique operation
    identifiers; local `$ref` targets that resolve; servers with a URL and
    no embedded credentials, or a Swagger `host` without scheme or path, a
    `basePath` starting with `/` and valid `schemes`; well-formed security
    schemes, and security requirements that name defined schemes.
  - GraphQL: no duplicate type, field, argument, enum value, directive or
    schema definition; every referenced type defined (here, in another
    schema file, or built in); input positions (arguments, input fields)
    use input types and output fields use output types; interfaces exist
    and their fields are implemented; union members are object types;
    extensions extend a defined type of the same kind; no empty type;
    no `__` names; valid directive locations; root operation types that
    are defined object types, including a query root. An undefined
    directive is a warning, since federation and gateways define their
    own.
  - AsyncAPI: `asyncapi` and `info`; servers with a `url` (2.x) or `host`
    (3.x), a protocol (one outside the bindings registry is a warning)
    and no embedded credentials; 2.x channel items with only their own
    fields, unique `operationId`s and security requirements naming
    defined schemes; 3.x operations with `action` `send` or `receive`, a
    channel reference and messages of that channel; channel parameters
    that appear in the address; known security scheme types; local
    `$ref` targets that resolve.
  - OpenRPC: `openrpc` and `info`; servers with a credential-free URL;
    methods with a unique name not starting with `rpc.`, `params` whose
    content descriptors have unique names and a schema, a valid
    `paramStructure`, a `result` (its absence, a notification, is a
    warning) and errors with an integer code and a message; local `$ref`
    targets that resolve.
  - WSDL: a `targetNamespace` (required by WSDL 2.0; its absence in 1.1
    is a warning); imports (`wsdl:import`, `wsdl:include`, `xsd:import`,
    `xsd:include`) that name a readable file of the repository, where a
    URL or absolute path is never fetched but reported as a warning that
    what it declares is unverified (and references into its namespace
    are not checked), a relative location no file matches is an error,
    and an `xsd:import` without a location must name a namespace some
    schema declares; unique message, port type or interface, binding and
    service names and unique parts, operations and ports within them
    (overloaded WSDL 1.1 operations are a warning, as the WS-I Basic
    Profile forbids them); message parts naming exactly one element or
    type, declared by a schema here or in the repository or an XML Schema
    built-in type; operation inputs, outputs and faults naming existing
    messages (1.1) or schema elements (2.0), and WSDL 2.0 fault
    references naming a fault of the interface or one it extends;
    bindings that reference an existing port type or interface and bind
    only its operations (an unbound operation is a warning), a WSDL 1.1
    SOAP 1.1, SOAP 1.2 or HTTP binding, a SOAP transport, a `document` or
    `rpc` style (none is a warning, as `document` is assumed), `encoded`
    bodies as a warning, a WSDL 2.0 binding `type` and `wsoap:protocol`;
    ports and endpoints that reference an existing binding, a WSDL 1.1
    port address, no credentials in an address, and WSDL 2.0 endpoints
    whose binding is for their service's interface.
  - OData CSDL: version `4.0` or `4.01` (legacy 2 and 3 are a warning);
    references that name a readable CSDL file of the repository (a URL is
    a warning and never fetched, and none for the OASIS vocabularies
    under `Org.OData.`); unique schema namespaces and aliases, none
    reserved (`Edm`, `odata`, `System`, `Transient`); unique types,
    members and container children, operations whose name is used by one
    kind only (overloads allowed), at most one entity container, and a
    JSON `$EntityContainer` that names it; a key on every entity type
    that is neither abstract nor derived, whose properties exist (a
    nullable key property is a warning); type references resolved
    through aliases to an `Edm` primitive or a declared type of the right
    kind (base types, structural and navigation properties, parameters
    and return types); navigation partners that the target declares;
    entity sets and singletons of entity types; navigation bindings that
    target an entity set or singleton; action and function imports of
    unbound actions and functions and of the container's entity sets; a
    return type on every function and a binding parameter on every bound
    operation.
- It is complete against the cited inventory. OpenAPI path parameters are
  compared by position, not name, across `:id`, `{id}`, `{id:int}`,
  `{*slug}`, `<int:id>`, `<id>`, `[id]`, `[...slug]`, `(?P<id>...)` and
  `*` spellings, and server base paths are allowed in front of documented
  paths; AsyncAPI addresses are compared with parameters by position and
  a leading `/` ignored. Missing operations block. Documented operations
  the inventory does not show are kept and reported as unverified for a
  human to decide; static discovery misses operations, so absence is
  never a reason to delete one. A new document, and any operation a
  repair adds, may contain only cited operations.
- A repair keeps the author's content: the same version, every documented
  path and operation (GraphQL: type and field; AsyncAPI: channel and
  operation; OpenRPC: method; WSDL: namespace prefix, import, schema
  element and type, message and part, port type and operation, binding
  and binding operation, service and port; OData: reference, schema,
  type and member, action and function, container and child), and every
  part that had no diagnostic.
  Additions are allowed; removals are not.
- It contains nothing credential-like. Proposed text is checked line by
  line with `bc_redact`, and the whole document is checked too, because
  branch delivery refuses to publish any changed file the redactor would
  alter. Examples should use placeholders such as `<api-key>`, and
  security schemes and servers describe mechanisms (bearer, API key header
  names, OAuth2 flows, a broker host placeholder) without values. An
  existing document that already contains credential-looking values is not
  modified at all.

A failing proposal is returned to the generator with its diagnostics for
up to two repair rounds; after that it is rejected and its last
diagnostics, missing operations and failures are recorded. A passing
proposal goes to the independent reviewer, which must confirm that the
inventory is supported, the document matches the code, the author's
content is preserved and the location is appropriate. Only an accepted
proposal is written, through the same write jail as generated tests, and
only to the document's own path and, for a move, the policy-named
reference files. Production source is never written. Written bytes are
bound like reviewed tests, so a remediation edit to them withholds export.

Each standard has its own cap on documents per run (OpenAPI 4, GraphQL 2,
AsyncAPI 2, OpenRPC 2, Protocol Buffers 32, RAML 8, API Blueprint 8, WSDL 4
and OData CSDL 4 in the shipped profiles), and at most eight generator
sessions run across all standards; the rest are named in a note. Each
generator reply is bounded by the same 16,000-token reply budget as test
generation, so a very large API may not fit one reply; its document is then
rejected with the missing operations listed rather than written incomplete.

### Standards that are only checked

Protocol Buffers, RAML and API Blueprint documents, and OData 2 and 3
metadata, are validated and reported with the action `reported`; no
model is involved and nothing is written. OData 2 and 3 are validated with
the OData 4 rules that apply to them (keys, types, entity sets and
duplicates; their association-based navigation is not checked), with a
warning that the version is legacy; OData 4 documents are repaired.

A `.proto` file is normally the source of truth that client and server
code is generated from, so the step never generates one from code or
edits one. It checks the syntax (proto2 or proto3; editions are read but
their label rules are not checked), unique names and field and enum value
numbers, field numbers within 1 to 2^29 - 1 and outside 19000 to 19999,
conflicts with `reserved` numbers, ranges and names and with `extensions`
ranges, labels per syntax (no `required` or groups in proto3, a label on
every proto2 field outside a `oneof` or map, none on `oneof` and map
fields), a zero first value and no unannounced aliases in proto3 enums,
imports that resolve within the repository or to well-known types (an
unresolved import is a warning, since it may come from a buf module or
googleapis), and field and RPC types resolved by protobuf's scoping rules
across the repository's `.proto` files.

The step then scans the repository's source, outside test layouts and
within the reference scan's bounds, for gRPC server registrations:

| Language | Registration | Service |
|---|---|---|
| Go | `pb.RegisterGreeterServer(s, ...)`, grpc-gateway's `RegisterGreeterHandlerServer(...)` | `Greeter` |
| Python | `add_GreeterServicer_to_server(...)` | `Greeter` |
| Java, Kotlin | `extends GreeterGrpc.GreeterImplBase`, `GreeterGrpcKt.GreeterCoroutineImplBase` | `Greeter` |
| C# | `: Greeter.GreeterBase` | `Greeter` |
| JavaScript, TypeScript | `addService(proto.Greeter.service, ...)`, `addService(GreeterService, ...)` | `Greeter` |
| Rust (tonic) | `GreeterServer::new(...)`, `GreeterServer::from_arc(...)` | `Greeter` |
| C++ | `: public Greeter::Service` (and `CallbackService`, `AsyncService`) | `Greeter` |

A registered service that no `.proto` file defines is a finding, named in
a run note with its `file:line`. A defined service with no registration
found is reported as unverified: it may be client-only, or registered in
a way the scan does not recognize. When the scan would exceed its bounds,
a note says the registrations were not checked.

RAML and API Blueprint are sanity-checked (RAML: a `title`, a
credential-free `baseUri`, resources that are mappings, known methods and
numeric response codes; API Blueprint: the `FORMAT: 1A` metadata, an API
name, a credential-free `HOST`, valid methods and URI templates, and a
response per action) and never rewritten. The outcome notes that they
could be converted to OpenAPI by hand, after which this step maintains
the OpenAPI document.

### What is recorded

`security-scan/target-tests.json` carries an `api_spec` object: the step's
`state` (`not_requested`, `skipped` or `assessed`), the skip `reason`,
planning `notes`, and one entry per document with its standard
(`spec_format`), path (and previous path after a move), service root,
frameworks and libraries, convention, `action`, version, `syntax`, any
parse error, diagnostics before and after (for WSDL a pointer such as
`/portTypes/QuotePortType/operations/GetQuote`, for OData
`/types/Catalog.Product/properties/ID`), missing and unverified
operations, the cited inventory (for Protocol Buffers, the registrations
found), rewritten references, the generator's changes and the reviewer's
verdict, plus the gaps that explain the outcome. Actions are `created`,
`repaired`, `relocated`, `complete`, `unverifiable`, `rejected`,
`skipped` and `reported`. The Markdown and SARIF annotations carry the
step's state.

A document the step could not produce or repair does not withhold patch
export. It is additional documentation, and the security fix it
accompanies should not wait for it; its gaps say what is missing.

### Adding a standard

Each standard is one implementation of the `SpecFormat` trait in
`crates/bc-api-spec/src/format.rs`, registered in `FormatId`, `registry()`
and `format()`. It provides detection (`candidate_strength`,
`classify`), its own `parse` into a JSON tree, `validate` with peer
documents, `operations`, `compare` with an inventory, `preservation`,
`inventory_operation`, `emit`, `new_document_problems`, `owners` and
`fallback` for location conventions, `capabilities` (create, repair,
relocate, or check only), optionally `document_capabilities` (a
narrower allowance for some versions, as OData uses for its legacy ones)
and `supporting` (documents read only as peers, as WSDL uses for XML
Schema files) and, for a deterministic inventory, `scans_source` and
`scan_source`. Repairs are exact text edits, which work on any text
format. The XML standards show how a new syntax plugs in: `Syntax::Xml`,
a `parse` that reads the text with `bc_xml` (DTDs refused, bounded by its
`Limits`) and converts the element tree into a JSON model of the
standard with every qualified name resolved to its namespace URI, and
the standard's rules over that model. A new XML document is emitted as
text (the generator returns it as a string, as for GraphQL) and must
parse back. `bc_xml` can also locate minimal edits by the byte spans of
parsed elements and attributes (`SpanEdit`); the step does not need them,
because the generator's exact-once text edits already change only the
bytes they name.
A written standard also needs its generator and reviewer prompts in
`crates/bc-cli/src/target_testing/api_spec/prompts.rs` and a cap in the
compiled profiles.

## Build and select an execution profile

Before `discovered-offline` was added, every shipped profile omitted
execution authorization. Generation and review could complete, but no
stock profile could run baseline or postpatch tests. That limitation was
not a successful validation outcome.

Select the new opt-in profile with:

```text
--repo /path/to/clean/repository --remediate --target-tests discovered-offline
```

Discovery provides package language, directory, manifest evidence, and
command suggestions. The build-owned profile authorizes exact argv
alternatives for each ecosystem. Matching is case-sensitive and covers
every argument; it permits no wildcard, prefix, shell-text substitution,
or additional arguments. The caller contains no language-specific branch.
Every resolved command also passes `ContainerPolicy::validate`, including
the original image pin, argument, path, and command-count checks. At most
64 commands are authorized across the whole target. Duplicate package
commands are deduplicated and ordering is stable.

| Detected ecosystem | Pinned upstream image family | Allowed discovered command |
|---|---|---|
| Rust | Docker Official `rust:1-bookworm` | `cargo test --locked --offline` |
| JavaScript/TypeScript | Docker Official `node:22-bookworm-slim` | `npm run` with exactly `test`, `test:unit`, `test:integration`, or `test:e2e` |
| Python | Docker Official `python:3.12-slim-bookworm` | `python -m pytest` |
| Go | Docker Official `golang:1-bookworm` | The exact Go test invocation emitted by discovery, including its recursive package selector |
| Java/Kotlin | Docker Official `maven:3-eclipse-temurin-21` | `mvn --offline test` |
| .NET | Microsoft `dotnet/sdk:8.0-bookworm-slim` | `dotnet test --no-restore` |

The policy contains immutable digest references, not these mutable tags.
The digests were checked against [Docker Hub tag metadata](https://hub.docker.com/v2/repositories/library/node/tags/22-bookworm-slim)
and the [Microsoft registry manifest](https://mcr.microsoft.com/v2/dotnet/sdk/manifests/8.0-bookworm-slim)
on 2026-09-10. The other Docker Official Images use the same tag metadata
endpoint with their image name and tag. These established upstream
families provide the relevant toolchains without adding target credentials
or application-specific bootstrap scripts. Digest pinning makes changes
reviewable; it is not a vulnerability assessment of the image.

Preload each required image by the exact reference in
`crates/bc-cli/src/target_testing/policies/discovered-offline.json` on the
local Docker engine before scanning. Image acquisition is a separate,
trusted operator task. The executor uses `--pull never` and never downloads
an image during testing.

These are base toolchain images, not universal application test images.
The Python image does not contain pytest, and the Node image does not
contain Jest. Neither contains the target's own dependencies, and the
execution snapshot deliberately excludes the host's `node_modules`,
`vendor`, `target`, and virtual environment directories. That is what the
provisioning phase below exists to fix. Unavailable services, incompatible
runtime versions, or an absent local image still produce failed or blocked
commands. A supported ecosystem means its commands can be authorized, not
that every project can run in that base image.

An unmatched suggestion is recorded in `remaining_gaps`, naming its
manifest and argv. A recognized package with no suggestion names the
package and ecosystem in its refusal. An ecosystem absent from the
catalog is refused explicitly. A package the build cannot install
dependencies for is refused before its tests are considered, and its
refusal names both the pins the ecosystem accepts and the pins that were
actually found. If no package ecosystem is recognized, the refusal
includes inspected-entry counts and available test/project evidence.
Refusals block verified export even if other packages pass. The current
discovery does not suggest Gradle, tox, or nox commands. Its pnpm, Yarn,
and Bun packages are refused by this profile because the Node image
provides npm only.

## Dependency provisioning

Running a project's test suite already executes that project's code, so
refusing to install that project's declared dependencies is not a coherent
security line: it only guarantees the suite fails for a reason that has
nothing to do with the target. The genuine marginal risks are network
access during the install and install-time hook scripts, and both are
addressed directly rather than avoided.

Provisioning is a separate phase with its own container invocation, run
once per package, before any baseline. That container is the only one in
the whole run that has a network. Every test phase keeps `--network none`,
and nothing about the test phases was relaxed to make provisioning
possible: an install and a test command are different command kinds, and
only the build-owned install kind selects the networked invocation.

| Detected ecosystem | Pin the build requires | Provisioning command | Install-time scripts |
|---|---|---|---|
| Rust | `Cargo.lock` | `cargo fetch --locked` | No control. Cargo build scripts do not run during a fetch, but they do run later during `cargo test`, as they would anywhere. |
| JavaScript/TypeScript | `package-lock.json` or `npm-shrinkwrap.json` | `npm ci --ignore-scripts --no-audit --no-fund` | Disabled. `--ignore-scripts` stops `preinstall`, `install`, and `postinstall` hooks. |
| Python | `requirements.txt` | `pip install --user --no-input --no-cache-dir --only-binary :all: -r requirements.txt` | Disabled in effect. `--only-binary :all:` installs wheels only, so no `setup.py` is executed during the install. A project with only source distributions fails the install rather than running one. |
| Go | `go.mod` | `go mod download` | None to disable. Downloading a module does not execute it. |
| Java/Kotlin | `pom.xml` | `mvn -B dependency:go-offline` | No control. Maven resolves and can execute plugin code during resolution, and offers no equivalent flag. |
| .NET | `packages.lock.json` | `dotnet restore --locked-mode` | No control. Restore evaluates the project's own MSBuild logic and any `.props` or `.targets` a restored package brings. |

Each command is the ecosystem's lockfile-respecting form, not its
resolving one, so the installed versions are the ones the target committed.
`npm ci` fails outright without a lockfile rather than writing one;
`cargo fetch --locked` refuses a stale or absent `Cargo.lock`;
`dotnet restore --locked-mode` fails if a restore would change
`packages.lock.json`. A package with none of the pins its ecosystem
accepts is refused: there is no resolve-from-the-internet fallback, and
because vendored dependency directories are stripped from the snapshot,
running its suite anyway could only produce a misleading failure. That
refusal is recorded before anything runs, and it blocks verified export.

Provisioning is per package, and a package is a manifest with a pin beside
it. That is a real limit for workspace layouts that keep one lockfile at
the repository root: an npm workspace member with no `package-lock.json`
of its own is refused, even though the root package it belongs to may
install and test fine. Workspace-aware installs are not implemented, and
guessing that an ancestor lockfile covers a member would be exactly the
kind of assumption this profile refuses to make.

Two ecosystems deserve their limits stated plainly. Maven has no lockfile
at all: a POM with exact versions is the only pin it has, and a POM using
version ranges is not reproducible. `dependency:go-offline` is also known
not to resolve every plugin dependency, so an offline `mvn test` can still
fail on a plugin it never fetched. For Python, `requirements.txt` is only
as pinned as the project made it; hashes are not required, because
requiring them would refuse nearly every real requirements file. Poetry,
uv, and Pipenv locks are recorded in the plan as discovered evidence and
then refused, because installing from them needs a tool the vetted image
does not carry. Gradle is refused for the same reason it has no test
command today.

The provisioning container is hardened exactly like the test containers:
digest-pinned image, `--pull never`, unprivileged UID, all capabilities
dropped, `no-new-privileges`, read-only container root, CPU, memory, and
process limits, bounded output, and a cleared host environment with a
private empty `DOCKER_CONFIG`. It inherits no scanner environment, no
credentials, and no registry logins, so an install reaches public package
registries as an anonymous client and cannot reach a private one. Its
deadline is 1,200 seconds rather than the 600 seconds a test command gets,
because a cold dependency tree takes longer to fetch than the suite it
enables takes to run.

It receives one writable mount, and it is not a path from the host
project: a private per-run dependency store in a fresh temporary
directory, narrowed to the host user, that is removed when the run ends.
The install writes there; every test phase mounts that same store
read-only and copies what it needs into its own throwaway working copy, so
target code can never modify what a later phase reads. The target's own
source stays read-only in every phase, provisioning included.

Two consequences are worth knowing. Each test command copies the
dependency tree into its container before running, so a large
`node_modules` or Maven repository costs time and temporary space per
command. And the current source is copied over the store's older copy at
the start of every phase, so a file the patch changed is the patched one,
while a file the patch deleted can still linger in the working copy.

Resolved suite commands are `Existing`: they run in `existing_baseline`
before generation and in `postpatch` after remediation. They do not run in
`generated_baseline`, and neither does the install, which runs once in
`provision` and is never repeated after the patch. Reinstalling afterwards
would replace the environment the baseline was measured against.
Discovery cannot supply a trustworthy security
failure signature, so it must not relabel an existing suite as a security
regression. Generated tests collected by the existing suite may run after
the patch, but their prepatch reproduction is unmeasured. Even when both
suite runs pass, the result remains
`functional_checks_passed_security_unverified`.

The resolved image/command list is recorded in
`resolved_execution_policies` in `security-scan/target-tests.json` and
supplied to generation and review. Resolution happens once before any
model edits. Later target changes cannot expand the approved command set.

Policies live under `crates/bc-cli/src/target_testing/policies/` and are
embedded with `include_str!` by `target_testing/builtin_profiles.rs`.
To add an execution profile:

1. Review the target's test commands and prepare a vetted local image.
2. Add a strict JSON policy to that source directory. For discovered
   execution, use `discovered_execution` entries with `language`, a
   digest-pinned `image`, `allowed_argv` arrays of exact alternatives, and
   a `provisioning` object carrying `pins`, `argv`, and `scripts_disabled`.
   Provisioning is required, not optional: an ecosystem whose dependencies
   the build cannot install is one whose suite cannot be believed. Follow
   `discovered-offline.json`. For a target-specific security reproduction
   with a reviewed failure marker, use the existing literal `execution`
   schema below; a literal policy that declares no provisioning command
   runs unprovisioned, against an image that must already carry what its
   commands need. Do not combine both forms. Approve any exact
   fixture/setup paths separately.
3. Register a unique name and version in `PROFILES`, using `include_str!`.
4. Run the policy and executor tests, then rebuild with
   `cargo build --release -p bc-cli`.
5. Select the compiled name with `--target-tests your-profile-name`.

Bump the profile version when its permissions or behavior change. The
assurance artifact records the selected name and version. A target file,
model output, or runtime JSON file cannot introduce commands or override
the compiled policy. Unknown names and paths fail closed. Existing
full-scan and isolation requirements apply to every profile.

For example, this is a **source policy template**, not a shipped profile
or runtime file. Adapt it to the actual pytest layout before registering:

```json
{
  "generate": true,
  "allowed_support_paths": ["tests/conftest.py"],
  "execution": {
    "image": "your-local-test-image@sha256:REPLACE_WITH_64_HEX_DIGEST",
    "commands": [
      {
        "id": "existing",
        "cwd": ".",
        "argv": ["python", "-m", "pytest", "tests/existing"],
        "kind": "existing"
      },
      {
        "id": "legitimate-workflows",
        "cwd": ".",
        "argv": ["python", "-m", "pytest", "tests/functional"],
        "kind": "functional"
      },
      {
        "id": "ownership-regression",
        "cwd": ".",
        "argv": ["python", "-m", "pytest", "tests/security/test_ownership.py"],
        "kind": "security_regression",
        "expected_failure_contains": "test_non_owner_cannot_read_record"
      }
    ]
  }
}
```

The placeholder digest is deliberately invalid. Prepare and vet the image
outside this workflow. A literal `execution` policy declares no
provisioning command, so its image must already carry the frameworks and
dependencies its commands need; the profile above is the one that installs
them. The harness never pulls an image or installs anything on the host.
Network-disabled test commands cannot fetch packages; external services
remain blockers.

The backend requires a local Docker engine running Linux containers. It
uses a bounded copied source snapshot, a read-only source mount, an
unprivileged user, dropped capabilities, a read-only container root,
bounded temporary storage, CPU/memory/process limits, bounded output, and
timeouts. Test commands additionally run with no network. It does not
mount the host target writable, the Docker socket, host home, or
credentials into the container. The one writable mount any container
receives is the private per-run dependency store described above, and only
the provisioning phase gets it writable. Target commands never fall back
to execution on the host. Recognized secret files, symlinks, dependency
and build directories are excluded from the execution snapshot; this can
block projects that need them and does not prove arbitrary source files
contain no secrets. Supply synthetic fixtures, not production credentials.

Test network isolation is enforced by Docker's `--network none`, not by a
prompt or an npm setting. Only a build-owned provisioning command runs
with a network, and it runs before any test phase. The executor clears the
host environment and uses a private, empty `DOCKER_CONFIG`. It does not
inherit registry logins or Docker contexts. It limits execution to 600
seconds per test command and 1,200 seconds per install, two CPUs, 4 GB
memory, 256 processes, and a 4 GB temporary filesystem. The temporary
filesystem holds the working copy of the target plus whatever provisioning
installed, which is why it and the memory limit are larger than the
512 MB and 2 GB used before dependencies were installed at all.

An allowlisted runner still executes untrusted target code. For example,
`npm run test` can invoke project lifecycle scripts. The Docker boundary
contains that code; argv matching cannot prevent it from opening another
container path, spawning a process, or attempting an installation. A test
command has no network to install over regardless, and no host dependency
installation is allowed in any phase. The working directory is a safe
initial directory, not an
in-container chroot. This design assumes a trusted, patched local Docker
engine and reviewed images without embedded credentials. Literal
confinement of every test process to its working directory is not provided
by this executor.

The fixed setup shell is inside the Linux image. A Windows host does not
need POSIX `sh`, but does need the supported local Linux-container backend.
This is not native Windows application testing. Windows-specific targets
and multi-service E2E environments require a separately supported executor;
they must not be represented as tested by this backend.

## Execution order and results

1. Install each provisionable package's declared dependencies, once, in
   the run's only networked container.
2. Run approved existing suites against the unpatched snapshot.
3. Generate and independently inspect proposed tests, and the API
   specification, if requested.
4. Run approved functional and security tests before the patch.
5. Run S10 remediation and S11 independent model review.
6. Confirm test bytes are unchanged, then rerun all approved test commands
   on the final combined patch. The install does not repeat.
7. Record scoped results and gate both patch-file and remediation-JSON
   exports. A blocked result never becomes a passing result.

The artifact is `security-scan/target-tests.json`; successful workflow runs
also annotate Markdown and SARIF with scoped assurance status. It distinguishes
the compiled policy name/version, static discovery,
generated/inspected/applied test artifacts, actual
execution results, baseline failures, missing security reproduction,
postpatch failures, and remaining gaps. Text is redacted for reporting;
proposed test and remediation patches still contain actual code and need
normal source-access controls.

### An environment failure is not a test failure

Each command result carries one state, and they mean different things:

| State | Meaning |
|---|---|
| `passed` | The command ran against a prepared environment and succeeded. |
| `failed` | The command ran against a prepared environment and the target's own code failed. This is the only state that is evidence about the target. |
| `environment_failed` | The environment could not be prepared. Either an install exited nonzero, or a test phase was refused because its dependencies were never installed. Nothing was learned about the target. |
| `blocked` | The command could not be started at all: invalid policy, unusable snapshot, or a container the engine refused to run. Docker's own reserved exit codes 125 to 127 land here. |
| `timed_out` | The command exceeded its deadline and its container was removed. |

A failed install never becomes `failed`, and a suite whose install failed
is not run at all: it is recorded as `environment_failed` with the install
command and its outcome named in the result. Before this distinction
existed, an unprovisioned suite exited 1 and was recorded as a failing
test, which then blocked the export of a fix that was never in question.
The gap text follows the same split, so a reader is told that an
environment could not be prepared rather than that a baseline failed. The
artifact also carries a top-level `environment_blocked` flag, repeated in
the Markdown and SARIF annotations, so an unusable environment is visible
without reading every result.

An environment failure still withholds export. Being unable to run the
tests is not permission to skip them; it is a different, and honestly
labeled, reason to stop.

A security command must fail before the patch with its configured failure
signature and pass afterwards to demonstrate that regression. A nonzero
exit alone is insufficient: a syntax error is not a reproduced
vulnerability, and neither is an `environment_failed` result, which cannot
satisfy the reproduction check at all. Even a matching failure signature
warrants human inspection of the test and its failure; it is not universal
proof of a fix. Baseline failures against a prepared environment are
reported as pre-existing pending investigation. Automatic flaky-test
classification is not implemented.

A command passing establishes only that command's observed result. This
feature does not claim comprehensive coverage for an arbitrary application,
that a model's proposed expectations are correct, or that passing tests
exclude other vulnerabilities and regressions. Budgeted generation,
unsupported frameworks, unavailable services, and unmet coverage obligations
remain explicit gaps.

Individual generated files remain `not_individually_verified`: runner
collection reports are not yet parsed to prove which cases actually ran.
The approved commands and observed exit statuses are recorded separately.
Rejected or incomplete requested generation withholds patch export. The
artifact records requested generator/reviewer models and usage returned by
completed sessions; usage lost when a model session errors is still unknown.

## Retain tests for future runs

Generation edits the detached remediation worktree, or the isolated source
snapshot for ZIP delivery, following the target's
existing test layout and package boundaries. Examples include Rust `tests/`,
Python `tests/`, and framework-native colocated JavaScript test files.
Fixtures and setup changes remain subject to the compiled profile's exact
support-path permissions. No universal directory is imposed on monorepos.

With default `--remediation-delivery patch`, the combined
`security-scan/remediation.patch` carries new test files,
extensions to existing tests, approved support files, and production fixes.
The separate `security-scan/target-tests.json` stores assurance metadata and
results; it is not the reusable test suite. Per-finding remediation JSON
must not be used as a substitute for the combined patch: tests generated
before S10 are not necessarily part of a per-finding diff.

After inspecting the combined patch and its validation gaps, apply it from
the original target repository root:

```sh
git apply --check security-scan/remediation.patch
git apply security-scan/remediation.patch
```

For default patch delivery, review and commit the resulting test and source
changes using the target's normal contribution process. This mode does not
automatically apply the patch to the original checkout, commit, or push it.
Once committed, the tests are ordinary target-project tests available to
developers, CI, and future BC SAST runs. The project's test commands/CI must collect them;
merely storing a file does not establish that it executes.

`--keep-remediation-worktree` retains the proposal checkout for inspection.
Normally it is removed after export. If writing a nonempty patch fails,
the worktree is retained and its recovery path is printed. Validation gates
can withhold export; a retained blocked proposal is not an approved fix.

Explicit `--remediation-delivery branch` commits and pushes the combined
changes to an explicitly named new remote branch. Explicit
`--remediation-delivery zip` packages the updated isolated source tree,
including accepted tests, at `security-scan/remediated-source.zip` without
requiring Git. CI must upload that file through its artifact mechanism.
See [remediation delivery](remediation-delivery.md) for flags, authorization,
exclusions, failure handling, and reuse. Delivery mode does not authorize
test execution or change the selected testing level.

Note the operational scope: the authorization, refusal and classification
paths are covered by tests, while the container execution path itself has
not yet been observed running against a live engine.
