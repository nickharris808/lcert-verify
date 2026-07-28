"""Explain a verdict per locus, so a rejection is actionable rather than opaque.

``verify_bundle`` answers "is this certificate sound?". When the answer is no, the
next question is always "where, and by how much?". This module answers that from
the certificate's own numbers — it computes nothing new and asserts nothing the
verdict did not already establish.
"""
from __future__ import annotations

from typing import Dict, List

from ._verifier import _down, _up, rederive_gate_verdict


def explain_certificate(cert: dict, *, limit: int = 20) -> dict:
    """Per-locus breakdown of why a certificate reached its verdict.

    Returns the same classification the verdict is derived from, plus the margin
    arithmetic for each locus, so a reader can see how close a locus was to the
    boundary rather than only which side of it fell.
    """
    thr = float(cert["thr"])
    dd = float(cert["delta_dose"])
    K = float(cert["K"])
    K_lo, K_hi = _down(_down(K)), _up(_up(K))
    loci = cert["loci"]
    rows: List[Dict] = []

    for j, ae0 in enumerate(loci["ae0"]):
        I_lo, I_hi, ae0 = float(loci["I_lo"][j]), float(loci["I_hi"][j]), float(ae0)
        sub = ae0 < thr
        he, le = (1.0 + dd) * I_hi, (1.0 - dd) * I_lo
        he_lo, he_hi = _down(he), _up(he)
        le_lo, le_hi = _down(le), _up(le)
        if sub:
            m_lo, m_hi = _down(thr - he_hi), _up(thr - he_lo)
            in_lo, in_hi = he_lo, he_hi
        else:
            m_lo, m_hi = _down(le_lo - thr), _up(le_hi - thr)
            in_lo, in_hi = le_lo, le_hi
        Kin_lo = _down(K_lo * max(in_lo, 0.0))
        Kin_hi = _up(K_hi * max(in_hi, 0.0))
        safe = (m_lo > 0.0) and (_down(m_lo * m_lo) >= Kin_hi)
        unsafe = (m_hi <= 0.0) or (_up(m_hi * m_hi) < Kin_lo)
        cls = "safe" if safe else ("unsafe" if unsafe else "straddling")

        # How much margin was needed, versus how much there was.
        need = Kin_hi ** 0.5 if Kin_hi > 0 else 0.0
        rows.append({
            "index": j, "class": cls, "branch": "sub-threshold" if sub else "super-threshold",
            "I_lo": I_lo, "I_hi": I_hi, "ae0": ae0,
            "margin_lo": m_lo, "margin_hi": m_hi,
            "margin_needed": need,
            "shortfall": None if safe else round(need - m_lo, 12),
        })

    red = rederive_gate_verdict(cert)
    worst = sorted((r for r in rows if r["class"] != "safe"),
                   key=lambda r: (r["shortfall"] is None, -(r["shortfall"] or 0)))
    return {
        "name": cert.get("name", "?"),
        "verdict": "ADMIT" if red["interval_admit"] else "REJECT",
        "counts": {k: red[k] for k in
                   ("n_loci", "n_certainly_safe", "n_certainly_unsafe", "n_straddle")},
        "binding_loci": worst[:limit],
        "n_binding": len(worst),
        "rows": rows,
    }


def format_explanation(exp: dict, *, limit: int = 10) -> str:
    """Human-readable rendering, with the actionable part first."""
    c = exp["counts"]
    out = [
        f"certificate {exp['name']!r} -> {exp['verdict']}",
        f"  {c['n_loci']} loci: {c['n_certainly_safe']} safe, "
        f"{c['n_certainly_unsafe']} unsafe, {c['n_straddle']} straddling",
    ]
    if exp["verdict"] == "ADMIT":
        out.append("  every gated locus cleared its margin; nothing is binding.")
        return "\n".join(out)

    out.append("")
    out.append(f"  {exp['n_binding']} locus/loci prevented admission. Worst first:")
    out.append(f"    {'idx':>6}  {'class':<11} {'margin':>12} {'needed':>12} {'short by':>12}")
    for r in exp["binding_loci"][:limit]:
        short = "-" if r["shortfall"] is None else f"{r['shortfall']:.6g}"
        out.append(f"    {r['index']:>6}  {r['class']:<11} {r['margin_lo']:>12.6g} "
                   f"{r['margin_needed']:>12.6g} {short:>12}")
    if exp["n_binding"] > limit:
        out.append(f"    ... and {exp['n_binding'] - limit} more")
    out.append("")
    out.append("  A 'straddling' locus is one the interval arithmetic cannot resolve either")
    out.append("  way — it is refused in the safe direction. Reducing its intensity")
    out.append("  uncertainty, or raising the photon budget, is what moves it.")
    return "\n".join(out)
