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

"""Parity oracle: batch-scores CVSS vectors with the real
vvaharness.report.cvss module (imported, never modified) so the Rust
vva-cvss port can be cross-checked against it.

Input (stdin): a JSON array of vector strings (or nulls).
Output (stdout): a JSON array of {"vector": ..., "score": ..., "rating": ...}
in the same order.
"""
import json
import sys

from vvaharness.report.cvss import rating, score


def main() -> int:
    vectors = json.loads(sys.stdin.read())
    out = []
    for v in vectors:
        s = score(v)
        out.append({"vector": v, "score": s, "rating": rating(s)})
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
