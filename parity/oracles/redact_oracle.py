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

"""Parity oracle: batch-redacts strings with the real
vvaharness.report.redact module (imported, never modified) so the Rust
vva-redact port can be cross-checked against it.

Uses redact_counts (not redact()) since it is the thread-safe, side-channel
free variant — no shared `redact.last_counts` state to worry about across
the batch.

Input (stdin): a JSON array of strings.
Output (stdout): a JSON array of {"redacted": ..., "counts": {...}}.
"""
import json
import sys

from vvaharness.report.redact import redact_counts


def main() -> int:
    texts = json.loads(sys.stdin.read())
    out = []
    for t in texts:
        redacted, counts = redact_counts(t)
        out.append({"redacted": redacted, "counts": counts})
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
