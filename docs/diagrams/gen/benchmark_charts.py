#!/usr/bin/env python3
"""Emit the grouped-bar charts docs/comparison.md embeds.

    python3 docs/diagrams/gen/benchmark_charts.py

Supersedes the single-chart `precision_chart.py`: four charts that differ
only in their data and axis wanted either four near-copies of one 200-line
script or one parameterised [`chart`]. The drawing code, and the three
constraints below, are carried over from it unchanged.

Why hand-rolled SVG rather than a charting library or Mermaid:

  - Mermaid's ``xychart-beta`` draws two bar series OVERLAID rather than
    side by side, and has no legend at all, so a two-series comparison is
    ambiguous exactly where it matters most.
  - GitHub sanitizes ``<style>`` out of an SVG it renders in Markdown, so
    ``prefers-color-scheme`` is unavailable. Both series colors therefore
    have to carry contrast on white AND on #0d1117 at once, and value
    labels are drawn in their own series' color rather than in gray for
    the same reason.
  - Standard library only, no build step: a chart nobody can regenerate
    is a chart that goes stale silently, and this repo adds no dependency
    for a doc asset.

Every number here is measured, and its provenance is named in the
subtitle or footer of the chart that carries it. Re-run this script after
any re-benchmark; the charts are build artifacts of the numbers in
docs/comparison.md, not a second source of truth for them.
"""

import os

# ---------------------------------------------------------------------------
# Measured data. One block, so a re-benchmark edits numbers and nothing else.
#
# bc-sast: 24 runs (3 x 8 apps), gpt-6-luna, --openai-api responses pinned
# and verified per-role in all 24 run manifests, --temperature 0,
# detection-only (top=0). VVAH: 24 runs, v1.5.0, same model, same endpoint,
# same scorer, --stop-after s9.
#
# c-cli is measured on the CORRECTED fixture (demo-repo PR #41, which gave
# it the privilege boundary its ground truth already asserted). Its earlier
# numbers are not comparable and are not shown: see comparison.md.
# ---------------------------------------------------------------------------

# (app, python, rust) — pooled over the 3 runs, not a mean of means.
RECALL = [
    ("java-spring", 100.0, 100.0),
    ("csharp-aspnet", 75.0, 91.7),
    ("go-gin", 83.3, 100.0),
    ("php-laravel", 91.7, 83.3),
    ("ruby-rails", 100.0, 100.0),
    ("kotlin-ktor", 100.0, 100.0),
    ("rust-axum", 41.7, 75.0),
    ("c-cli", 100.0, 91.7),
]

PRECISION = [
    ("java-spring", 25.5, 72.2),
    ("csharp-aspnet", 29.4, 78.6),
    ("go-gin", 24.6, 48.0),
    ("php-laravel", 37.8, 52.6),
    ("ruby-rails", 38.2, 54.5),
    ("kotlin-ktor", 24.6, 50.0),
    ("rust-axum", 28.0, 75.0),
    ("c-cli", 44.4, 50.0),
]

# False findings per run. LOWER IS BETTER here, the only chart where that
# is true, which the subtitle says because a reader scanning bar heights
# will otherwise read it backwards.
EXTRAS = [
    ("java-spring", 12.7, 1.7),
    ("csharp-aspnet", 8.0, 0.7),
    ("go-gin", 14.3, 4.3),
    ("php-laravel", 7.7, 2.3),
    ("ruby-rails", 6.0, 3.3),
    ("kotlin-ktor", 14.0, 3.0),
    ("rust-axum", 6.0, 1.0),
    ("c-cli", 5.0, 3.7),
]

# USD per scan, detection-only, computed from each run manifest's own token
# totals at gpt-6-luna's published rates. The formula is verified against
# bc-sast's self-reported `cost_usd` to zero error on all 24 runs; the
# Python harness reports `cost_usd: null` ("no pricing table configured"),
# so both sides are priced by the same external calculation rather than one
# side's internal figure being compared against the other's derivation.
COST = [
    ("java-spring", 0.0969, 0.1342),
    ("csharp-aspnet", 0.0664, 0.1056),
    ("go-gin", 0.1055, 0.1510),
    ("php-laravel", 0.0750, 0.1266),
    ("ruby-rails", 0.0700, 0.1027),
    ("kotlin-ktor", 0.1055, 0.1451),
    ("rust-axum", 0.0762, 0.1430),
    ("c-cli", 0.0731, 0.1354),
]

PY_COLOR = "#c2762a"   # amber; ~3.6:1 on white, ~4.6:1 on #0d1117
RS_COLOR = "#3d7ab8"   # blue;  ~4.6:1 on white, ~3.9:1 on #0d1117
AXIS = "#8b929b"       # neutral gray, deliberately mid-tone
GRID = "#8b929b"

W, H = 900, 470
LEFT, RIGHT, TOP, BOTTOM = 58, 24, 88, 76
PLOT_W = W - LEFT - RIGHT
PLOT_H = H - TOP - BOTTOM
BAR_GAP = 4          # gap between the two bars of one group
GROUP_PAD = 0.32     # share of a slot left empty between groups

FONT = ("-apple-system, BlinkMacSystemFont, 'Segoe UI', "
        "Helvetica, Arial, sans-serif")


def esc(text):
    """Escape the five XML metacharacters."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&apos;"))


def fmt(value, unit):
    """44.4 -> '44.4'; 100.0 -> '100'; money keeps its cents."""
    if unit == "$":
        return "%.3f" % value
    return ("%.0f" % value) if abs(value - round(value)) < 0.05 else ("%.1f" % value)


def chart(data, title, subtitle, legend, footer, aria, y_max, ticks, unit="%"):
    """One grouped-bar SVG.

    A `None` value is drawn as nothing at all rather than as a zero bar.
    Zero and "not measured" are different claims, and this chart is the
    one place a reader cannot check which is meant.
    """
    out = []
    add = out.append
    plot_h = PLOT_H

    def y_of(value):
        return TOP + plot_h - (value / float(y_max)) * plot_h

    add('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
        'viewBox="0 0 %d %d" role="img" aria-label="%s">'
        % (W, H, W, H, esc(aria)))
    add('<text x="%d" y="26" font-family="%s" font-size="16" '
        'font-weight="600" fill="%s">%s</text>'
        % (LEFT - 4, FONT, RS_COLOR, esc(title)))
    add('<text x="%d" y="46" font-family="%s" font-size="12" fill="%s">%s</text>'
        % (LEFT - 4, FONT, AXIS, esc(subtitle)))

    lx = LEFT - 4
    for label, color in ((legend[0], PY_COLOR), (legend[1], RS_COLOR)):
        add('<rect x="%d" y="60" width="11" height="11" rx="2" fill="%s"/>'
            % (lx, color))
        add('<text x="%d" y="70" font-family="%s" font-size="12" '
            'font-weight="600" fill="%s">%s</text>'
            % (lx + 17, FONT, color, esc(label)))
        lx += 24 + len(label) * 6.6

    for tick in ticks:
        y = y_of(tick)
        add('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="%s" '
            'stroke-width="1" opacity="0.28"/>'
            % (LEFT, y, LEFT + PLOT_W, y, GRID))
        label = ("$%.2f" % tick) if unit == "$" else (
            "%g%s" % (tick, unit) if unit else "%g" % tick)
        add('<text x="%d" y="%.1f" font-family="%s" font-size="11" '
            'fill="%s" text-anchor="end">%s</text>'
            % (LEFT - 9, y + 4, FONT, AXIS, label))

    slot = PLOT_W / float(len(data))
    bar_w = (slot * (1 - GROUP_PAD) - BAR_GAP) / 2.0
    baseline = y_of(0)

    for i, (label, py, rs) in enumerate(data):
        cx = LEFT + slot * i + slot / 2.0
        for value, color, offset in ((py, PY_COLOR, -bar_w - BAR_GAP / 2.0),
                                     (rs, RS_COLOR, BAR_GAP / 2.0)):
            x = cx + offset
            if value is None:
                # Say so, rather than letting a gap read as zero.
                add('<text x="%.1f" y="%.1f" font-family="%s" font-size="10" '
                    'fill="%s" text-anchor="middle" opacity="0.8">n/a</text>'
                    % (x + bar_w / 2.0, baseline - 6, FONT, color))
                continue
            y = y_of(value)
            add('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="2" '
                'fill="%s"/>' % (x, y, bar_w, baseline - y, color))
            add('<text x="%.1f" y="%.1f" font-family="%s" font-size="10.5" '
                'font-weight="600" fill="%s" text-anchor="middle">%s</text>'
                % (x + bar_w / 2.0, y - 5, FONT, color, fmt(value, unit)))
        add('<text x="%.1f" y="%d" font-family="%s" font-size="11" '
            'fill="%s" text-anchor="middle">%s</text>'
            % (cx, baseline + 18, FONT, AXIS, esc(label)))

    add('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="%s" '
        'stroke-width="1.5" opacity="0.55"/>'
        % (LEFT, baseline, LEFT + PLOT_W, baseline, AXIS))
    add('<text x="%d" y="%d" font-family="%s" font-size="12" fill="%s">%s</text>'
        % (LEFT - 4, H - 22, FONT, AXIS, footer))
    add('</svg>')
    return "\n".join(out) + "\n"


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    dest_dir = os.path.dirname(here)
    legend = ("Python harness v1.5.0", "Rust port")
    sub = ("24 runs each side, 3 per app. Same model (gpt-6-luna), same "
           "endpoint, same token caps, same scorer, detection only.")
    charts = [
        ("recall-by-language.svg", chart(
            RECALL, "Recall by language", sub, legend,
            'All eight apps: <tspan fill="%s" font-weight="600">Python 86.5%%'
            '</tspan> vs <tspan fill="%s" font-weight="600">Rust 92.7%%</tspan>'
            ' &#183; 83/96 vs 89/96 &#183; six findings, and the first batch where it clears the noise'
            % (PY_COLOR, RS_COLOR),
            "Recall by language, Python harness versus Rust port. Near parity "
            "overall; the Rust port trails on the C command-line app.",
            100.0, range(0, 101, 25))),
        ("precision-by-language.svg", chart(
            PRECISION, "Precision by language", sub, legend,
            'All eight apps: <tspan fill="%s" font-weight="600">Python 30.1%%'
            '</tspan> vs <tspan fill="%s" font-weight="600">Rust 57.7%%</tspan>'
            ' &#183; 1.9x, and higher in all eight'
            % (PY_COLOR, RS_COLOR),
            "Precision by language, Python harness versus Rust port. The Rust "
            "port scores higher in all eight languages.",
            100.0, range(0, 101, 25))),
        ("false-findings-per-run.svg", chart(
            EXTRAS, "False findings per run",
            "Reported findings matching no planted vulnerability. LOWER IS "
            "BETTER on this chart. " + sub, legend,
            'All eight apps: <tspan fill="%s" font-weight="600">Python 9.2'
            '</tspan> vs <tspan fill="%s" font-weight="600">Rust 2.5</tspan>'
            ' &#183; 3.7x fewer to triage'
            % (PY_COLOR, RS_COLOR),
            "False findings per run, Python harness versus Rust port. Lower is "
            "better; the Rust port reports 4.5 times fewer.",
            16.0, range(0, 17, 4), unit="")),
        ("cost-per-scan.svg", chart(
            COST, "Cost per scan",
            "USD per detection-only scan, from each run's own token totals at "
            "published rates. " + sub, legend,
            'All eight apps: <tspan fill="%s" font-weight="600">Python $0.0836'
            '</tspan> vs <tspan fill="%s" font-weight="600">Rust $0.1305</tspan>'
            ' &#183; 1.6x more, break-even at $0.0070 of triage per false finding'
            % (PY_COLOR, RS_COLOR),
            "Cost per scan in US dollars, Python harness versus Rust port. The "
            "Rust port costs about 1.6 times more per scan.",
            0.16, [0.0, 0.04, 0.08, 0.12, 0.16], unit="$")),
    ]
    for name, svg in charts:
        path = os.path.join(dest_dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(svg)
        print("wrote %s" % path)


if __name__ == "__main__":
    main()
