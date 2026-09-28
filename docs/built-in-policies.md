# Built-in policies and rule sources

BC SAST bundles framework policies, target-testing profiles, and its S0
source/sink corpus into the executable. Operators select named policies
with flags. Policy authors change source, review the change, and rebuild;
the scanner does not read runtime replacement files for these inputs.

## Runtime selection

Add these flags to a normally configured scan:

```text
--scan-framework asvs --scan-framework pci-dss --compliance-scope annotate
```

`--compliance-preset` is a compatible spelling of `--scan-framework`.
Available framework names are `asvs`, `pci-dss`, `ssdf`, and `soc2`.
Framework selection does not require Semgrep, Checkmarx, or other external
SAST providers. Unknown names fail closed. `--compliance-policy <PATH>`
is no longer supported.

For full-scan, isolated remediation, select a target-testing profile:

```text
--remediate --target-tests discover
--remediate --target-tests comprehensive
```

`discover` inspects test structure and records a plan and gaps. Generation
levels (`unit`, `integration`, `e2e`, and `comprehensive`)
also produce and independently review tests before applying accepted
changes to the worktree. `discovered-offline` additionally authorizes
discovered commands through exact, ecosystem-specific argv allowlists and
pinned container images, plus one lockfile-respecting install command per
ecosystem. All other shipped profiles remain generation-only or
discovery-only and install nothing. A package with no lockfile the build
can install from is refused rather than run without dependencies.
The `integration`, `comprehensive`, `e2e`, `generate` and
`discovered-offline` profiles also carry the API specification step's
allowances in an `api_spec` object: the specification size cap, repair
rounds, the run-wide cap on generator sessions (`max_documents`), the
file-name patterns of documentation and framework configuration a
relocation may update, and a `formats` object naming each API
description standard the profile allows with its own `max_documents`
(OpenAPI 4, GraphQL 2, AsyncAPI 2, OpenRPC 2, Protocol Buffers 32, RAML 8,
API Blueprint 8, WSDL 4 and OData CSDL 4). A standard absent from
`formats` is never assessed.
See
[API specification](target-testing.md#api-specifications).
Omitting `--target-tests` leaves this additional testing workflow disabled.
The flag accepts a name, not a JSON file path. A bare `--target-tests`
selects `comprehensive`; `generate` remains a compatible comprehensive
profile. See [testing levels and persistence](target-testing.md).

## What framework rules establish

A framework requirement describes an individual expectation, such as
protecting a particular security boundary. The embedded framework files
provide model guidance and maps from finding CWE/vulnerability class to
requirement IDs. Guidance enters S1/S3/S4/S6/S8 prompts; requirement tags
are assigned before S8 and rendered by S9.

A finding tagged with a requirement is evidence relevant to that
requirement, not proof that the requirement is satisfied. Compliance is a
broader assessment that can require operational, organizational, and
runtime evidence unavailable to a source scanner. These files do not add
an independent rule engine or demonstrate complete framework coverage.
Read the mapping assumptions and gaps in each source file.

`annotate` retains unmapped findings. `filter` excludes findings from the
main report when they match no active filter policy, recording them in
`report.dropped`. Sparse mappings can hide relevant issues in filtered
reports. Selecting a framework does not narrow repository analysis scope.

## Source changes and rebuild

| Content | Source and registration |
|---|---|
| Framework guidance and requirement mappings | `crates/bc-compliance/presets/*.yaml`; register names and `include_str!` entries in `crates/bc-compliance/src/presets.rs`. |
| Target-testing authorization | `crates/bc-cli/src/target_testing/policies/*.json`; register names, versions, and `include_str!` entries in `crates/bc-cli/src/target_testing/builtin_profiles.rs`. |
| S0 source/sink detection corpus | `crates/bc-stage-s0/corpus/sources.yaml` and `sinks.yaml`. CLI `step0.sources_yaml`/`step0.sinks_yaml` overrides are rejected. |

JSON and YAML remain readable, version-controlled source formats. Their
contents are embedded at compilation; there is no adjacent policy file to
deploy or replace. Existing named profiles can be edited in place; adding
a profile also requires a registry entry. Bump a target-testing profile's
version when its authorization or behavior changes.

A custom target-execution profile must supply a vetted locally available,
digest-pinned Linux image and approved commands for its intended target
stack. Do not copy a placeholder image digest into a shipped profile.
The existing container isolation, baseline comparison, and patch-export
gates still apply. Rebuilding grants no host execution fallback and does
not remove full-scan or isolation requirements. Patch and branch delivery
require a clean committed Git checkout and an isolated worktree; ZIP
delivery instead uses an isolated source snapshot and does not require Git.
See [Target-repository testing](target-testing.md) for the schema and
validation states.

Before distributing a changed binary, validate every embedded profile and
its registry, add focused tests for changed matching/authorization behavior,
and run the applicable checks in `CONTRIBUTING.md`. Build with:

```sh
cargo build --release -p bc-cli
```

Stage tuning and provider configuration still use the existing runtime
configuration mechanisms. The separate remediation deny/allow policy is
unchanged by this feature. This build boundary applies to the framework,
S0 rule, and target-testing inputs described above; it does not imply that
all scanner configuration has become immutable.
