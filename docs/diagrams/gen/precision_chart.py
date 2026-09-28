#!/usr/bin/env python3
"""Emit docs/diagrams/precision-by-language.svg — a grouped bar chart.

Mermaid's ``xychart-beta`` draws two bar series overlaid rather than
side by side, and has no legend at all, so a two-series comparison is
ambiguous exactly where it matters most. This script draws the same data
as properly grouped bars with a legend and value labels.

Standard library only, no third-party dependency, no build step:

    python3 docs/diagrams/gen/precision_chart.py

Colors are chosen to carry enough contrast on both GitHub's light and
dark backgrounds, because GitHub sanitizes ``<style>`` out of an SVG it
renders in Markdown, so ``prefers-color-scheme`` is not available. Value
labels are drawn in their own series' color rather than in gray for the
same reason.

The numbers are the measured results from docs/comparison.md. Precision
here is matched findings over ALL findings reported, scored by
polyglot/score.py against hand-written ground truth.
"""

import os

# (app label, python precision %, rust precision %)
DATA = [
    ("java-spring",   44.4, 100.0),
    ("csharp-aspnet", 71.4,  75.0),
    ("go-gin",        50.0,  60.0),
    ("php-laravel",   42.9,  75.0),
    ("ruby-rails",    50.0,  60.0),
    ("kotlin-ktor",   26.7,  57.1),
    ("rust-axum",     33.3,  54.5),
    ("c-cli",         60.0,  71.4),
]

TOTAL_PY = 44.2
TOTAL_RS = 66.1

PY_COLOR = "#c2762a"   # amber; ~3.6:1 on white, ~4.6:1 on #0d1117
RS_COLOR = "#3d7ab8"   # blue;  ~4.6:1 on white, ~3.9:1 on #0d1117
AXIS = "#8b929b"       # neutral gray, deliberately mid-tone
GRID = "#8b929b"

W, H = 900, 470
LEFT, RIGHT, TOP, BOTTOM = 58, 24, 88, 76
PLOT_W = W - LEFT - RIGHT
PLOT_H = H - TOP - BOTTOM
Y_MAX = 100.0
BAR_GAP = 4          # gap between the two bars of one group
GROUP_PAD = 0.32     # share of a slot left empty between groups

FONT = ("-apple-system, BlinkMacSystemFont, 'Segoe UI', "
        "Helvetica, Arial, sans-serif")


def esc(text):
    """Escape the five XML metacharacters."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&apos;"))


def y_of(value):
    """Data value -> SVG y coordinate."""
    return TOP + PLOT_H - (value / Y_MAX) * PLOT_H


def fmt(value):
    """44.4 -> '44.4'; 100.0 -> '100'."""
    return ("%.0f" % value) if abs(value - round(value)) < 0.05 else ("%.1f" % value)


def build():
    out = []
    add = out.append

    add('<svg xmlns="http://www.w3.org/2000/svg" '
        'width="%d" height="%d" viewBox="0 0 %d %d" '
        'role="img" aria-label="Precision by language, Python harness versus '
        'Rust port. The Rust port scores higher in all eight languages.">'
        % (W, H, W, H))

    # Title and subtitle.
    add('<text x="%d" y="26" font-family="%s" font-size="16" '
        'font-weight="600" fill="%s">Precision by language</text>'
        % (LEFT - 4, FONT, RS_COLOR))
    add('<text x="%d" y="46" font-family="%s" font-size="12" fill="%s">'
        'Matched findings as a share of all findings reported. '
        'Same model, same targets, same scorer.</text>'
        % (LEFT - 4, FONT, AXIS))

    # Legend.
    lx = LEFT - 4
    for label, color in (("Python harness v1.2.0", PY_COLOR),
                          ("Rust port", RS_COLOR)):
        add('<rect x="%d" y="60" width="11" height="11" rx="2" fill="%s"/>'
            % (lx, color))
        add('<text x="%d" y="70" font-family="%s" font-size="12" '
            'font-weight="600" fill="%s">%s</text>'
            % (lx + 17, FONT, color, esc(label)))
        lx += 24 + len(label) * 6.6

    # Y gridlines and labels.
    for tick in range(0, 101, 25):
        y = y_of(tick)
        add('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="%s" '
            'stroke-width="1" opacity="0.28"/>'
            % (LEFT, y, LEFT + PLOT_W, y, GRID))
        add('<text x="%d" y="%.1f" font-family="%s" font-size="11" '
            'fill="%s" text-anchor="end">%d%%</text>'
            % (LEFT - 9, y + 4, FONT, AXIS, tick))

    # Bars.
    slot = PLOT_W / float(len(DATA))
    bar_w = (slot * (1 - GROUP_PAD) - BAR_GAP) / 2.0
    baseline = y_of(0)

    for i, (label, py, rs) in enumerate(DATA):
        cx = LEFT + slot * i + slot / 2.0
        for value, color, offset in ((py, PY_COLOR, -bar_w - BAR_GAP / 2.0),
                                      (rs, RS_COLOR, BAR_GAP / 2.0)):
            x = cx + offset
            y = y_of(value)
            add('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="2" '
                'fill="%s"/>' % (x, y, bar_w, baseline - y, color))
            add('<text x="%.1f" y="%.1f" font-family="%s" font-size="10.5" '
                'font-weight="600" fill="%s" text-anchor="middle">%s</text>'
                % (x + bar_w / 2.0, y - 5, FONT, color, fmt(value)))

        add('<text x="%.1f" y="%d" font-family="%s" font-size="11" '
            'fill="%s" text-anchor="middle">%s</text>'
            % (cx, baseline + 18, FONT, AXIS, esc(label)))

    # Baseline.
    add('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="%s" '
        'stroke-width="1.5" opacity="0.55"/>'
        % (LEFT, baseline, LEFT + PLOT_W, baseline, AXIS))

    # Footer: the aggregate, which is the number that survives run-to-run noise.
    add('<text x="%d" y="%d" font-family="%s" font-size="12" fill="%s">'
        'All eight apps: <tspan fill="%s" font-weight="600">Python %s%%</tspan>'
        ' vs <tspan fill="%s" font-weight="600">Rust %s%%</tspan>'
        ' &#183; recall is a tie at 28/32 each.</text>'
        % (LEFT - 4, H - 22, FONT, AXIS,
           PY_COLOR, fmt(TOTAL_PY), RS_COLOR, fmt(TOTAL_RS)))

    add('</svg>')
    return "\n".join(out) + "\n"


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    dest = os.path.join(os.path.dirname(here), "precision-by-language.svg")
    with open(dest, "w", encoding="utf-8") as handle:
        handle.write(build())
    print("wrote %s" % dest)


if __name__ == "__main__":
    main()
