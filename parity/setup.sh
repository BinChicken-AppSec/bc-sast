#!/usr/bin/env bash
# Creates the Python venv used by bc-parity-tests to cross-check this
# Rust port against the real vvaharness Python source (imported read-only,
# never modified — see ../docs/parity-harness.md).
#
# Requires a real Python 3.10+ (vvaharness/pyproject.toml's own
# requires-python). On a broken/old system Python, fix that first — this
# script does not attempt to install or repair a Python interpreter.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PYTHON="${1:-python3}"
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 10), f"need Python 3.10+, got {sys.version}"'

rm -rf .venv
"$PYTHON" -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt

echo "venv ready at $(pwd)/.venv"
