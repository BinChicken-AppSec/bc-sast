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
`__main__.py` entrypoint — this oracle calls the public API directly.

Written against v1.4.0, where two things moved. `ValidationScore.fix_status`
is now `.decision`, carrying a `Decision` whose values are snake_case
identifiers (`fixed`, `partially_fixed`, `not_fixed`, `inconclusive`) rather
than v1.2.0's display strings. And `derive_merge_readiness(score)` became
`merge_readiness_for(verdict, policy)` on `vvaharness.models.derive`: it
takes a ceiling from the decision, then lets conditions and the score band
lower it, never raise it. The policy is not optional in practice — passing
none silently uses `ScoringPolicy()`'s 0.85/0.60 thresholds instead of the
0.80/0.50 the fix score was produced under — so `FIX_POLICY` is passed
explicitly here, which is what both of upstream's own call sites do.

The verdict is built with no conditions, because a scoring-only comparison
has none to report; upstream caps at `ready_with_conditions` when they are
present, which is a report-assembly concern rather than a scoring one.

Input (stdin): {"findings": [{"tracking_id": ..., "gates": [{"gate_name":
..., "status": ...}, ...]}, ...]}.
Output (stdout): {"findings": [{"decision": ..., "raw_score": ...,
"merge_readiness": ...}, ...]} in the same order, each value exactly as
upstream renders it. The Rust side maps its own labels into this space
rather than either side adopting the other's spelling.
"""
import json
import sys

from vvaharness.models import Verdict
from vvaharness.models.derive import merge_readiness_for
from vvaharness.validation.scoring import FIX_POLICY, score_fix


def main() -> int:
    payload = json.loads(sys.stdin.read())
    out = []
    for finding in payload["findings"]:
        score = score_fix(finding["gates"])
        # `raw_score` is a weighted mean of per-status multipliers, so it is
        # already within Verdict.score's 0..1 bound. It is passed unclamped
        # on purpose: if that ever stops holding, this should fail loudly
        # rather than quietly score a different number than upstream did.
        verdict = Verdict(
            decision=score.decision,
            rationale="parity oracle",
            score=score.raw_score,
        )
        out.append(
            {
                "decision": score.decision.value,
                "raw_score": score.raw_score,
                "merge_readiness": merge_readiness_for(verdict, FIX_POLICY).value,
            }
        )
    print(json.dumps({"findings": out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
