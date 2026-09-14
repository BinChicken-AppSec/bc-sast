#!/usr/bin/env python3
"""Regenerate `crates/bc-pricing/data/models-dev-prices.json`.

The crate embeds a trimmed copy of the models.dev catalogue with
`include_str!`, so a price refresh has to arrive as a reviewable diff in
version control rather than as silent drift from a network fetch at scan
time. This script produces that diff.

Usage
-----

Fetch the live catalogue and rewrite the vendored file in place::

    python3 crates/bc-pricing/scripts/refresh_prices.py

Trim a snapshot already on disk, which is also how the file is rebuilt
without network access::

    python3 crates/bc-pricing/scripts/refresh_prices.py --from-file api.json

Write somewhere else, or print to stdout, to inspect before committing::

    python3 crates/bc-pricing/scripts/refresh_prices.py --out /tmp/prices.json
    python3 crates/bc-pricing/scripts/refresh_prices.py --out -

Then review `git diff` on the vendored file and run
`cargo test -p bc-pricing`, whose `vendored_file_fully_deserializes` test
fails loudly if a refresh introduced a shape this crate cannot parse.

Standard library only, by the project's dependency policy in
`docs/supply-chain.md`. Nothing here is on the scanner's runtime path.

What gets trimmed and why
-------------------------

The upstream catalogue is roughly 4.3 MB and mostly describes things a
cost calculation does not use: display names, descriptions, modalities,
knowledge cutoffs, context limits, tool-call and reasoning capability
flags. Only four rate classes survive, matching the four token counts the
scanner actually meters: `input`, `output`, `cache_read`, `cache_write`.
Audio and separately-billed reasoning rates are dropped because this
scanner sends no audio and its providers bill reasoning tokens as output.

Every provider is kept. See the module documentation in
`crates/bc-pricing/src/lib.rs` for that decision.

Rates are converted from the upstream unit (US dollars per million
tokens, serialized as a JSON float) to an exact integer: picodollars per
token, which is the same number scaled by 10**6. Upstream values carry at
most six decimal places of real precision, so the conversion is lossless
for every genuine rate, and it removes float artifacts such as
`0.0024499999999999995` that upstream serialized from its own arithmetic.
Doing the conversion here means the Rust side parses integers and never
touches a float.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import urllib.request
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

SOURCE_URL = "https://models.dev/api.json"
SOURCE_LICENSE = "MIT"
SOURCE_LICENSE_URL = "https://github.com/sst/models.dev/blob/dev/LICENSE"
GENERATOR = "crates/bc-pricing/scripts/refresh_prices.py"
RATE_UNIT = "picodollars per token (integer, 1e-12 USD); upstream USD per million tokens times 10**6"

DEFAULT_OUT = Path(__file__).resolve().parent.parent / "data" / "models-dev-prices.json"

# The four rate classes the scanner meters. Anything else upstream
# publishes (input_audio, output_audio, reasoning) is dropped.
RATE_KEYS = ("input", "output", "cache_read", "cache_write")

# USD per million tokens -> picodollars per token.
RATE_SCALE = Decimal(10) ** 6


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310
        return response.read().decode("utf-8")


def to_picodollars(value: Decimal) -> int:
    """Scale one upstream rate to an integer, rounding half away from zero.

    Rounding only ever moves a float artifact back onto the decimal the
    publisher meant. Upstream rates with real precision have at most six
    decimal places, and those land on an integer exactly.
    """
    return int((value * RATE_SCALE).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def rates_of(cost: dict) -> dict:
    out = {}
    for key in RATE_KEYS:
        value = cost.get(key)
        if value is not None:
            out[key] = to_picodollars(Decimal(value))
    return out


def trim_model(cost: dict) -> dict | None:
    """Return the trimmed price entry for one model, or None to drop it."""
    if "input" not in cost or "output" not in cost:
        # Every entry the crate stores must have both, so a partial cost
        # object is dropped rather than half-priced. A dropped model reads
        # back as "unpriced", which is the honest answer.
        return None
    entry = rates_of(cost)
    tiers = []
    for tier in cost.get("tiers") or []:
        threshold = (tier.get("tier") or {}).get("size")
        if (tier.get("tier") or {}).get("type") != "context" or threshold is None:
            # Only context-size tiers exist upstream today. Anything else
            # would need a pricing rule this crate does not implement, so
            # refuse to guess.
            continue
        if "input" not in tier or "output" not in tier:
            continue
        tiers.append({"above": int(threshold), **rates_of(tier)})
    if tiers:
        # Ascending, so the file reads in the order the thresholds apply.
        # The crate does not rely on this ordering, but a reviewer does.
        entry["tiers"] = sorted(tiers, key=lambda t: t["above"])
    # `context_over_200k` is deliberately not carried across. In the
    # captured snapshot it was present on 382 models and was, in every
    # single case, byte-for-byte the same rates as the model's first
    # `tiers` entry. It is a legacy duplicate of the tier list, and
    # storing both would let the two disagree after a refresh.
    return entry


def build(catalogue: dict, captured: str) -> dict:
    providers: dict[str, dict] = {}
    for provider_id in sorted(catalogue):
        models: dict[str, dict] = {}
        for model_id in sorted(catalogue[provider_id].get("models") or {}):
            cost = catalogue[provider_id]["models"][model_id].get("cost")
            if not cost:
                continue
            entry = trim_model(cost)
            if entry is not None:
                models[model_id] = entry
        if models:
            providers[provider_id] = models
    return {
        "meta": {
            "source": SOURCE_URL,
            "source_license": SOURCE_LICENSE,
            "source_license_url": SOURCE_LICENSE_URL,
            "captured": captured,
            "generator": GENERATOR,
            "rate_unit": RATE_UNIT,
            "providers": len(providers),
            "models": sum(len(m) for m in providers.values()),
        },
        "providers": providers,
    }


def render(table: dict) -> str:
    """Serialize with one model per line.

    A model whose price changed is then exactly one changed line in the
    diff, which is the whole point of vendoring the file instead of
    fetching it at scan time.
    """
    lines = ["{", '  "meta": {']
    meta = table["meta"]
    for i, (key, value) in enumerate(meta.items()):
        comma = "" if i == len(meta) - 1 else ","
        lines.append(f"    {json.dumps(key)}: {json.dumps(value)}{comma}")
    lines.append("  },")
    lines.append('  "providers": {')
    providers = table["providers"]
    for i, provider_id in enumerate(providers):
        models = providers[provider_id]
        lines.append(f"    {json.dumps(provider_id)}: {{")
        for j, model_id in enumerate(models):
            body = json.dumps(models[model_id], separators=(",", ":"))
            comma = "" if j == len(models) - 1 else ","
            lines.append(f"      {json.dumps(model_id)}: {body}{comma}")
        lines.append("    }" + ("" if i == len(providers) - 1 else ","))
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate the vendored models.dev price table.",
    )
    parser.add_argument(
        "--from-file",
        metavar="PATH",
        help=f"trim this local copy of {SOURCE_URL} instead of fetching it",
    )
    parser.add_argument(
        "--out",
        metavar="PATH",
        default=str(DEFAULT_OUT),
        help='output path, or "-" for stdout (default: the vendored file)',
    )
    parser.add_argument(
        "--captured",
        metavar="YYYY-MM-DD",
        help="capture date to record (default: today, UTC)",
    )
    args = parser.parse_args(argv)

    if args.from_file:
        raw = Path(args.from_file).read_text(encoding="utf-8")
    else:
        raw = fetch(SOURCE_URL)

    # parse_float=Decimal keeps the upstream text exactly as published, so
    # the scaling step sees the real decimal rather than a float that has
    # already lost the last digit.
    catalogue = json.loads(raw, parse_float=Decimal)
    captured = args.captured or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    rendered = render(build(catalogue, captured))

    if args.out == "-":
        sys.stdout.write(rendered)
    else:
        Path(args.out).write_text(rendered, encoding="utf-8")
        print(f"wrote {args.out} ({len(rendered)} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
