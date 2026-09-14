# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Parity oracle: batch-runs the real vvaharness.config merge/expand helpers
(imported, never modified) so the Rust vva-config port can be cross-checked
against it. These are the same underscore-prefixed helpers the harness's own
tests/test_config.py imports directly, so reaching into them here follows
the project's own precedent for what counts as its tested surface.

Input (stdin): a JSON array of operation entries:
  {"op": "deep_merge" | "replace_merge" | "append_merge",
   "base": <json>, "over": <json>}
  {"op": "expand", "value": <json>, "env": {"VAR": "value", ...}}
For "expand", os.environ is replaced (not merged) with exactly "env" for the
duration of that one call via unittest.mock.patch.dict(..., clear=True), then
fully restored — so each entry is hermetic and independent of both the real
process environment and any other entry in the batch.

Output (stdout): a JSON array of results, one per input entry, in order.
"""
import json
import os
import sys
from unittest.mock import patch

from vvaharness.config import _append_merge, _deep_merge, _expand, _replace_merge

_MERGE_OPS = {
    "deep_merge": _deep_merge,
    "replace_merge": _replace_merge,
    "append_merge": _append_merge,
}


def _run_one(entry):
    op = entry["op"]
    if op == "expand":
        with patch.dict(os.environ, entry.get("env", {}), clear=True):
            return _expand(entry["value"])
    return _MERGE_OPS[op](entry["base"], entry["over"])


def main() -> int:
    entries = json.loads(sys.stdin.read())
    print(json.dumps([_run_one(e) for e in entries]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
