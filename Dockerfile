# syntax=docker/dockerfile:1
#
# Multi-stage build for the `bc-sast` scanner binary (crates/bc-cli).
#
# Target: x86_64-unknown-linux-gnu (glibc), NOT musl. The workspace's
# `reqwest` dependency (pinned via `[workspace.dependencies]`, vetted per
# docs/supply-chain.md) resolves rustls's crypto provider to `aws-lc-rs`,
# which compiles a bundled C/C++ library (a BoringSSL fork, via `aws-lc-sys`)
# rather than being pure Rust — the original "pure-Rust, therefore muslable"
# assumption doesn't hold once that resolved dependency tree is checked.
# The packages below are `aws-lc-sys`'s own build-time requirements (per
# aws-lc-rs's README + aws-lc's own BUILDING.md), not anything this
# project's own code needs directly: `cmake` (>=3.0, required), a C/C++
# compiler (`clang` covers both C and C++ via `clang++`), and
# `libclang-dev` (the `bindgen` crate needs the *development* package —
# headers + unversioned `libclang.so` symlink — not just the `clang`
# package's own runtime shared library). `perl` is included defensively:
# aws-lc-sys ships pre-generated build files specifically so consumers
# don't need Go/Perl for codegen, but a stray invocation costs nothing to
# guard against and Perl is a tiny package. Go is deliberately NOT
# installed — genuinely unneeded per aws-lc-sys's own docs, and a much
# larger download than the others.
#
# Runtime is a minimal, nonroot Wolfi image with `git` added. See the
# runtime stage below for why it ships a shell and a `git` when the
# previous `distroless/cc` runtime shipped neither.
#
# `cargo-chef` caches dependency compilation as its own Docker layer, so an
# app-code-only change doesn't force every dependency to rebuild.
#
# Both stages are pinned by immutable digest, per the project's
# supply-chain policy for published artifacts. Digests resolved
# 2026-09-09; refresh them deliberately, never by dropping the pin.

# Debian bookworm, deliberately kept as the builder even though the
# runtime is now Wolfi. Its glibc (2.36) is OLDER than Wolfi's, and glibc
# is backward compatible, so a binary linked here runs on both families;
# building on the newer glibc instead would produce a binary that no
# longer runs on Debian. The toolchain here is also the proven one, and
# nothing about the runtime change requires touching it.
FROM rust:1-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157 AS chef
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang libclang-dev cmake pkg-config perl \
    && rm -rf /var/lib/apt/lists/*
# cargo-chef 0.1.77 — vetted per docs/supply-chain.md (crates.io
# max_stable_version at time of writing); a build-time-only tool, never
# shipped in the final image.
RUN cargo install cargo-chef --locked --version =0.1.77
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release -p bc-cli --bin bc-sast

# Runtime: Chainguard's `wolfi-base` (glibc, `apk`, a `sh`, and a
# `nonroot` user already at uid 65532 in `/etc/passwd`), plus `git`.
#
# WHY A SECURITY TOOL SHIPS A SHELL AND A `git`, which is the first
# question a reviewer should ask. The previous runtime was
# `gcr.io/distroless/cc-debian12:nonroot`, which has neither, and the
# absence disabled four things that are already implemented and were
# inert only because the tools were missing:
#
#   1. `step_remediate.verify_command`. The S10 verify gate runs the
#      operator's own build or test command under `sh -c` before it will
#      accept an agent's fix. With no shell the gate cannot run at all,
#      so it fails CLOSED: it rolls the patch back and downgrades the
#      finding to `Needs Review`. A safety feature that can never pass is
#      a safety feature nobody can use.
#   2. The git-based revert backstop in `bc-stage-s10`
#      (`revert_record`), the fallback for a `--resume`d record whose
#      in-memory byte baseline did not survive the first process.
#   3. `bc_orchestrator::head_sha`, so `--git-sha` no longer has to be
#      passed by hand for `report.git_sha` to be populated.
#   4. Git worktree isolation for `--remediate`, which keeps an agent's
#      edits out of the caller's checkout.
#
# The security posture changes in wording rather than in substance. It
# was "no shell exists"; it is now "a shell exists and the agent cannot
# reach it". The remediation agent's tool allowlist is Read, Glob, Grep,
# Edit and Write, with no shell tool of any kind, so no model-derived
# string reaches a process spawn. The one string that does reach `sh -c`
# is `step_remediate.verify_command`, which comes from operator config
# only, has no default, and spawns nothing at all when unset.
#
# The cost is real and small: about 135MB against distroless's 102MB,
# and a shell plus a package manager now exist on disk for anything that
# does achieve code execution in the container.
#
# The verify gate only helps a project whose own toolchain is present in
# the image, and this image ships no compilers, test runners or package
# managers for the languages it scans. The practical pattern is
# therefore `FROM <this image>` plus whatever `verify_command` needs.
#
# One operational caveat, because it decides whether items 2-4 above fire
# at all: git 2.35 and later refuse a repository owned by another user
# ("detected dubious ownership"). A bind-mounted CI checkout keeps the
# runner's ownership, so the operator has to `chown -R 65532:65532` it or
# set `safe.directory` for that path. Every one of those code paths
# probes rather than assumes, so it degrades to the old behavior instead
# of failing, and `--doctor` now names which of the two states a given
# mount is in rather than only reporting whether `git` is on PATH. No
# global `safe.directory=*` is set here: disabling an ownership check for
# every repository by default, in a security tool, is not this image's
# call to make. The targeted form IS applied where the path is known
# ahead of time: `action.yml` sets `safe.directory` for the one
# workspace it mounts, since a docker action has nowhere to run a shell
# step before this entrypoint. See docs/deployment.md and
# docs/github-action.md.
FROM cgr.dev/chainguard/wolfi-base@sha256:918a593b8268c222afd4e2c4f06860ac984e60719b4697e4c71d796bc8fcd042 AS runtime
# `wolfi-base` defaults to root, so `apk` needs that before `USER
# nonroot` drops back down for the actual run.
USER root
RUN apk add --no-cache git
COPY --from=builder /build/target/release/bc-sast /usr/local/bin/bc-sast
USER nonroot
ENTRYPOINT ["/usr/local/bin/bc-sast"]
