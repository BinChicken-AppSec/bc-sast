#!/usr/bin/env bash
#
# Run the CI checks in a Linux container, so a local pass means what CI means.
#
#   scripts/checks.sh              fmt, clippy, tests, size, deny, all 13 gates
#   scripts/checks.sh gates        the coverage gates only
#   scripts/checks.sh gates mcp    one gate, matched on its name
#   scripts/checks.sh shell        a prompt inside the image
#
# The first run compiles the whole dependency tree inside the container and
# takes a while. After that the cargo registry and the Linux target directory
# persist in named volumes, so repeat runs are incremental.
#
# This does not replace CI. CI remains the authority -- it runs the same
# toolchain on the same platform, from a clean checkout. What this removes is
# spending a CI round trip to learn something a container could have said.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=bc-sast-checks
# Host-owned caches, so the container can run as the host user and still
# write them. A docker named volume is created root-owned, which an arbitrary
# --user cannot write.
CACHE="$REPO/.docker"

if ! docker version >/dev/null 2>&1; then
  echo "error: the Docker daemon is not reachable." >&2
  echo "       On macOS: open -a Docker, wait for it to start, then re-run." >&2
  exit 1
fi

echo "==> building $IMAGE (cached after the first run)"
docker build -f "$REPO/Dockerfile.checks" -t "$IMAGE" "$REPO" >/dev/null

mkdir -p "$CACHE/cargo" "$CACHE/target-linux" "$CACHE/home"

# --user is for the PERMISSION semantics, not for file ownership: Docker
# Desktop's virtiofs presents a macOS bind mount as root-owned inside the
# container whatever uid we run as, so git still raises "dubious ownership"
# and still needs the exception below. Scoped to the one mounted path -- a
# global `safe.directory=*` would disable an ownership check everywhere, which
# is not a default a security tool should carry.
SAFE_DIR='git config --global --add safe.directory /work'

DOCKER_ARGS=(
  --rm --init
  --user "$(id -u):$(id -g)"
  -v "$REPO:/work"
  -w /work
  -e "CARGO_HOME=/work/.docker/cargo"
  -e "CARGO_TARGET_DIR=/work/.docker/target-linux"
  -e "HOME=/work/.docker/home"
)

run() {
  docker run "${DOCKER_ARGS[@]}" "$IMAGE" bash -c "$SAFE_DIR && { $1; }"
}

case "${1:-all}" in
  shell)
    docker run -it "${DOCKER_ARGS[@]}" "$IMAGE" bash -c "$SAFE_DIR && exec bash"
    ;;
  gates)
    shift
    run "python3 scripts/coverage_gates.py $*"
    ;;
  all)
    run '
      set -e
      echo "--- fmt";    cargo fmt --all --check
      echo "--- clippy"; cargo clippy --workspace --all-targets -- -D warnings
      echo "--- tests";  cargo test --workspace 2>&1 | tail -3
      echo "--- size";   python3 scripts/loc_audit.py --check
      echo "--- deny";   cargo deny check 2>&1 | tail -1
      echo "--- coverage gates"
      python3 scripts/coverage_gates.py
    '
    ;;
  *)
    echo "usage: scripts/checks.sh [all|gates [name...]|shell]" >&2
    exit 2
    ;;
esac
