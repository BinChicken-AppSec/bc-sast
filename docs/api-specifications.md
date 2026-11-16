# API specifications

The API specification step of `--target-tests`, controlled by
`--api-spec` and `--api-spec-formats`. It runs at `integration` or
wider and is **static**: it reads source with the same read-only
tools the rest of the pipeline uses and makes no network request of
any kind.

Part of [target testing](target-testing.md); split out because it is a
separate feature with its own flags and its own crate
(`appsec-api-spec`), and it was 52% of that document.

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

## What discovery provides

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

## Reading an existing specification

Each candidate is read with a bounded, jailed read that refuses symlinks,
then classified by content. A document is an OpenAPI specification when
its top level declares `openapi: 3.0.x`, `3.1.x` or `3.2.x`, or
`swagger: "2.0"`; an AsyncAPI one when it declares `asyncapi: 2.0.0` to
`2.6.x` or `3.0.x`; an OpenRPC one when it declares `openrpc: 1.x`. A
misquoted `swagger: 2.0` or `openapi: 3.1` is still recognized, and the
missing quotes are reported as a diagnostic to repair.

JSON is parsed by `serde_json`. YAML is parsed by `appsec_yaml::parse_strict`,
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

WSDL, XML Schema and EDMX are read with `appsec_xml`, this project's own XML
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

## Where a new specification goes

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

## Relocating a misplaced specification

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

## Generation, repair and review

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
  line with `appsec_redact`, and the whole document is checked too, because
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

## Standards that are only checked

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

## What is recorded

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

## Adding a standard

Each standard is one implementation of the `SpecFormat` trait in
`crates/appsec-api-spec/src/format.rs`, registered in `FormatId`, `registry()`
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
a `parse` that reads the text with `appsec_xml` (DTDs refused, bounded by its
`Limits`) and converts the element tree into a JSON model of the
standard with every qualified name resolved to its namespace URI, and
the standard's rules over that model. A new XML document is emitted as
text (the generator returns it as a string, as for GraphQL) and must
parse back. `appsec_xml` can also locate minimal edits by the byte spans of
parsed elements and attributes (`SpanEdit`); the step does not need them,
because the generator's exact-once text edits already change only the
bytes they name.
A written standard also needs its generator and reviewer prompts in
`crates/appsec-cli/src/target_testing/api_spec/prompts.rs` and a cap in the
compiled profiles.
