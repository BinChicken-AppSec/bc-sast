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

"""Parity oracle: batch-scores fix-validation gate sets with the real
vvaharness.validation.scoring module (imported, never modified) so the
Rust bc-validation-scoring port can be cross-checked against it.

Replaces the previous `python3 -m vvaharness.validation.scoring` CLI
invocation, which stopped working once that package dropped its
`__main__.py` entrypoint — this oracle calls the same public
`score_fix`/`derive_merge_readiness` functions directly instead.

Input (stdin): {"findings": [{"tracking_id": ..., "gates": [{"gate_name":
..., "status": ...}, ...]}, ...]}.
Output (stdout): {"findings": [{"fix_status": ..., "raw_score": ...,
"merge_readiness": ...}, ...]} in the same order.
"""
import json
import sys

from vvaharness.validation.scoring import derive_merge_readiness, score_fix


def main() -> int:
    payload = json.loads(sys.stdin.read())
    out = []
    for finding in payload["findings"]:
        score = score_fix(finding["gates"])
        out.append(
            {
                "fix_status": score.fix_status.value,
                "raw_score": score.raw_score,
                "merge_readiness": derive_merge_readiness(score).value,
            }
        )
    print(json.dumps({"findings": out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
