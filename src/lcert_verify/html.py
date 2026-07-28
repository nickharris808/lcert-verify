"""A self-contained HTML report — one file, no network, no dependencies.

Verification is a visual field in practice: the question is rarely "did it pass"
but "how close was it, and where". A per-locus margin chart answers that in a way
a table of numbers does not, and it survives being pasted into a slide.

Two rules the chart obeys, both load-bearing rather than decorative:

**Colour never carries the meaning.** Safe and violating are green and red, which
is the one pair red-green colour blindness collapses (measured ΔE 4.1, well under
the ΔE 8 floor). So the encoding is geometric first: a margin is signed, and a
violating locus points the other way from the zero baseline. Colour, a texture
fill, a text label, and the table below all say the same thing independently.

**An abstention never renders as a pass.** The header badge shows the verdict
verbatim, and `UNVERIFIED` gets the warning treatment and its reason, exactly as
in the SARIF and JUnit emitters.
"""
from __future__ import annotations

import html as _html
from typing import Dict, List, Optional, Tuple

from .report import verdict_meta

_STATUS = {"good": "#0ca30c", "critical": "#d03b3b"}

_CSS = """
:root { color-scheme: light dark; }
.viz-root {
  color-scheme: light;
  --surface-1: #fcfcfb; --plane: #f9f9f7;
  --text-primary: #0b0b0b; --text-secondary: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --ring: rgba(11,11,11,0.10);
  --good: #0ca30c; --critical: #d03b3b; --warning: #fab219;
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) .viz-root {
    color-scheme: dark;
    --surface-1: #1a1a19; --plane: #0d0d0d;
    --text-primary: #ffffff; --text-secondary: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
  }
}
:root[data-theme="dark"] .viz-root {
  color-scheme: dark;
  --surface-1: #1a1a19; --plane: #0d0d0d;
  --text-primary: #ffffff; --text-secondary: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --axis: #383835; --ring: rgba(255,255,255,0.10);
}
body { margin: 0; background: var(--plane); color: var(--text-primary);
       font: 14px/1.5 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif; }
.wrap { max-width: 940px; margin: 0 auto; padding: 32px 20px 64px; }
h1 { font-size: 20px; margin: 0 0 4px; font-weight: 650; }
h2 { font-size: 15px; margin: 28px 0 2px; font-weight: 600; }
.sub { color: var(--text-secondary); margin: 0 0 24px; }
.card { background: var(--surface-1); border: 1px solid var(--ring);
        border-radius: 10px; padding: 18px 20px; margin: 14px 0; }
.badge { display: inline-flex; align-items: center; gap: 8px; font-weight: 650;
         border-radius: 999px; padding: 5px 13px; font-size: 13px;
         border: 1px solid var(--ring); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
        color: var(--text-secondary); word-break: break-all; }
.kv { display: flex; gap: 28px; flex-wrap: wrap; margin-top: 12px; }
.kv div span { display: block; color: var(--muted); font-size: 11px;
               text-transform: uppercase; letter-spacing: .05em; }
.kv div b { font-size: 17px; font-weight: 600; }
table { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 13px; }
th, td { text-align: left; padding: 5px 10px 5px 0; border-bottom: 1px solid var(--grid); }
th { color: var(--muted); font-weight: 600; font-size: 11px;
     text-transform: uppercase; letter-spacing: .05em; }
td.num { font-family: ui-monospace, Menlo, monospace; text-align: right; }
.err { color: var(--critical); }
.note { color: var(--text-secondary); font-size: 13px; margin: 8px 0 0; }
.bar:hover rect.mark { stroke: var(--surface-1); stroke-width: 2; }
details > summary { cursor: pointer; color: var(--text-secondary); font-size: 13px;
                    margin-top: 10px; }
"""


def _esc(x) -> str:
    return _html.escape(str(x), quote=True)


def _loci(cert: Dict) -> Tuple[List[Dict], str, str]:
    """Per-locus ``{margin, cls}`` rows, the unit, and what "safe" means.

    For the lithography gate this defers to :mod:`lcert_verify.explain`, which
    already computes the classification the verdict is derived from — including
    ``straddling``, a third state that is neither safe nor refuted. Inventing a
    simpler two-state margin here would have drawn a chart that disagreed with
    the verdict beside it.
    """
    loci = cert.get("loci") or {}
    if "lo" in loci and "hi" in loci:                       # LCERT-BOUND-1
        thr = float(cert.get("threshold", 0.0))
        below = cert.get("direction") == "below"
        lo = [float(x) for x in loci["lo"]]
        hi = [float(x) for x in loci["hi"]]
        rows = []
        for j in range(len(lo)):
            m = (thr - hi[j]) if below else (lo[j] - thr)
            rows.append({"margin": m, "cls": "safe" if m > 0 else "unsafe"})
        return rows, str(cert.get("unit", "")), str(cert.get("direction", ""))

    if "ae0" in loci and "I_hi" in loci:                    # lithography gate
        from .explain import explain_certificate
        try:
            ex = explain_certificate(cert, limit=10 ** 9)
        except (KeyError, TypeError, ValueError):
            return [], "", ""
        rows = [{"margin": float(r["margin_lo"]), "cls": r["class"]}
                for r in ex.get("loci", ex.get("rows", []))]
        return rows, "intensity", "below"
    return [], "", ""


_CLS_FILL = {"safe": "var(--good)", "straddling": "warn", "unsafe": "crit"}


def _chart(rows: List[Dict], unit: str, cid: str) -> str:
    """A signed bar chart around a zero baseline.

    The sign is the encoding: a locus that does not clear the threshold has a
    negative margin and its bar points left. Colour, a hatch fill, a direct label
    and the table each repeat that independently, because green and red are the
    one pair red-green colour blindness collapses.
    """
    if not rows:
        return '<p class="note">No loci — nothing was bounded here.</p>'
    n = len(rows)
    span = max(max(abs(r["margin"]) for r in rows), 1e-12)
    w, row, gap, pad = 620, 16, 2, 8
    h = n * (row + gap) + pad * 2 + 20
    zero = w * 0.42
    right, left = w - zero - 96, zero - 96
    parts = [f'<svg viewBox="0 0 {w} {h}" width="100%" height="{h}" role="img" '
             f'aria-label="Per-locus margin over {n} loci. Bars left of the '
             f'baseline do not clear the threshold." style="display:block">',
             '<defs>'
             + "".join(
                 f'<pattern id="{tag}-{cid}" width="6" height="6" '
                 f'patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
                 f'<rect width="6" height="6" fill="{col}"/>'
                 f'<line x1="0" y1="0" x2="0" y2="6" stroke="var(--surface-1)" '
                 f'stroke-width="2"/></pattern>'
                 for tag, col in (("crit", "#d03b3b"), ("warn", "#fab219")))
             + '</defs>']
    for i, r in enumerate(rows):
        m, cls = r["margin"], r["cls"]
        y = pad + i * (row + gap)
        length = max(abs(m) / span * (right if m >= 0 else left), 2.0)
        x = zero if m >= 0 else zero - length
        fill = _CLS_FILL.get(cls, "crit")
        if fill in ("crit", "warn"):
            fill = f"url(#{fill}-{cid})"
        label = f"{m:+.4g}" + ("" if cls == "safe" else f"  {cls}")
        parts.append(
            f'<g class="bar"><title>locus {i}: margin {m:+.6g} {_esc(unit)} '
            f'— {_esc(cls)}</title>'
            f'<rect class="mark" x="{x:.1f}" y="{y}" width="{length:.1f}" '
            f'height="{row}" rx="4" fill="{fill}"/>'
            f'<text x="{(x + length + 6) if m >= 0 else (x - 6):.1f}" '
            f'y="{y + row - 3}" font-size="11" fill="var(--text-secondary)" '
            f'text-anchor="{"start" if m >= 0 else "end"}">{_esc(label)}</text></g>')
    parts.append(f'<line x1="{zero}" y1="{pad - 4}" x2="{zero}" y2="{h - 24}" '
                 f'stroke="var(--axis)" stroke-width="1"/>')
    # Anchored at the extremes so nothing collides with the centred zero label.
    parts.append(f'<text x="2" y="{h - 6}" font-size="11" fill="var(--muted)" '
                 f'text-anchor="start">← does not clear</text>')
    parts.append(f'<text x="{zero}" y="{h - 6}" font-size="11" fill="var(--muted)" '
                 f'text-anchor="middle">0 = threshold</text>')
    parts.append(f'<text x="{w - 2}" y="{h - 6}" font-size="11" fill="var(--muted)" '
                 f'text-anchor="end">margin'
                 f'{" (" + _esc(unit) + ")" if unit else ""} →</text>')
    parts.append("</svg>")
    return "".join(parts)


def to_html(res: Dict, bundle: Optional[Dict] = None, source: str = "bundle") -> str:
    """Render a verification result as a single self-contained HTML document."""
    ok, level, summary = verdict_meta(res.get("verdict"))
    # SARIF levels are none/note/warning/error; the first two both mean "nothing
    # to report", which for a verdict means it stood up.
    colour = {"none": "var(--good)", "note": "var(--good)",
              "warning": "var(--warning)", "error": "var(--critical)"}.get(
                  level, "var(--critical)")
    icon = {"none": "\u2713", "note": "\u2713", "warning": "?",
            "error": "\u2717"}.get(level, "\u2717")
    bundle = bundle or {}

    certs: List[Tuple[str, Dict]] = []
    for key in ("gate_certs", "image_bound_certs", "resource_floor_certs",
                "interval_bound_certs"):
        for c in bundle.get(key) or []:
            certs.append((key, c))

    body = ['<div class="viz-root"><div class="wrap">',
            '<h1>lcert-verify report</h1>',
            f'<p class="sub mono">{_esc(source)}</p>',
            '<div class="card">',
            f'<span class="badge" style="color:{colour}">'
            f'<span aria-hidden="true">{icon}</span>{_esc(res.get("verdict"))}</span>',
            f'<p class="note">{_esc(summary)}</p>']
    if res.get("fingerprint"):
        body.append(f'<p class="mono">fingerprint {_esc(res["fingerprint"])}</p>')
    body.append('<div class="kv">'
                f'<div><span>certificates</span><b>{res.get("n_certificates", 0)}</b></div>'
                f'<div><span>gated loci</span><b>{res.get("n_gated_loci", 0)}</b></div>'
                f'<div><span>trust anchor</span><b>{_esc(res.get("trust_anchor", "NONE"))}'
                f'</b></div></div>')
    if res.get("errors"):
        body.append("<ul>" + "".join(f'<li class="err">{_esc(e)}</li>'
                                     for e in res["errors"]) + "</ul>")
    body.append("</div>")

    for i, (kind, cert) in enumerate(certs):
        rows_, unit, direction = _loci(cert)
        rec = cert.get("recorded") or {}
        admit = rec.get("admit", rec.get("interval_admit"))
        body.append(f'<div class="card"><h2>{_esc(cert.get("name", "?"))}'
                    f'</h2><p class="sub">{_esc(kind)}'
                    + (f" · {_esc(cert.get('quantity'))}" if cert.get("quantity") else "")
                    + (f" · safe is <b>{_esc(direction)}</b> the threshold"
                       if direction else "")
                    + (f' · <b style="color:'
                       f'{"var(--good)" if admit else "var(--critical)"}">'
                       f'{"ADMITTED" if admit else "NOT ADMITTED"}</b>'
                       if admit is not None else "") + "</p>")
        body.append(_chart(rows_, unit, f"c{i}"))
        if rows_:
            rows = "".join(
                f"<tr><td>{j}</td><td class='num'>{r['margin']:+.6g}</td>"
                f"<td>{_esc(r['cls'])}</td></tr>"
                for j, r in enumerate(rows_))
            body.append('<details><summary>Table view — the same numbers, for '
                        'screen readers, copying, and print</summary>'
                        f'<table><thead><tr><th>locus</th><th>margin'
                        f'{" (" + _esc(unit) + ")" if unit else ""}</th>'
                        f'<th>status</th></tr></thead><tbody>{rows}</tbody></table>'
                        '</details>')
        body.append("</div>")

    if not certs:
        body.append('<div class="card"><p class="note">This bundle carries no '
                    'certificates, so there is nothing to chart.</p></div>')

    body.append('<p class="note">A margin is the signed distance from the '
                'threshold: negative means the locus does not clear it. '
                '<b>straddling</b> is a third state — the enclosure spans the '
                'boundary, so neither answer is established. Colour repeats the '
                'classification, it does not carry it: green and red are the pair '
                'red-green colour blindness collapses, so the direction of the '
                'bar, the hatch fill, the direct labels and the table each say it '
                'independently.</p>')
    body.append("</div></div>")

    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>lcert-verify — {_esc(res.get('verdict'))}</title>"
            f"<style>{_CSS}</style></head><body>"
            + "".join(body) + "</body></html>\n")
