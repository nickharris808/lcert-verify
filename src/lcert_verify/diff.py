"""Compare two bundles: what changed, and did it help.

The question anyone iterating on a design actually asks is not "does this
verify" but "is it better than last time". That needs a comparison that says
which loci changed class and which way the margins moved.

One rule throughout: **a diff is not a verdict.** It reports movement between two
artifacts and nothing more. If either side does not verify, that is stated and
the comparison is still shown — but ``regressed`` is computed only from what both
sides actually establish, never from a bundle that failed to check.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from .builder import bundle_fingerprint

IMPROVED, REGRESSED, UNCHANGED = "IMPROVED", "REGRESSED", "UNCHANGED"


def _certs(bundle: Dict) -> Dict[str, Dict]:
    """Every certificate in a bundle, keyed by ``kind/name``."""
    out: Dict[str, Dict] = {}
    for key in ("gate_certs", "image_bound_certs", "resource_floor_certs",
                "interval_bound_certs"):
        for c in bundle.get(key) or []:
            out[f"{key}/{c.get('name', '?')}"] = c
    return out


def _admit(cert: Dict) -> Optional[bool]:
    rec = cert.get("recorded") or {}
    for k in ("admit", "interval_admit"):
        if k in rec:
            return bool(rec[k])
    return None


def _margin(cert: Dict) -> Optional[float]:
    rec = cert.get("recorded") or {}
    v = rec.get("worst_margin")
    return float(v) if isinstance(v, (int, float)) else None


def _n_loci(cert: Dict) -> int:
    loci = cert.get("loci") or {}
    for k in ("ae0", "lo", "I_lo"):
        if isinstance(loci.get(k), list):
            return len(loci[k])
    return 0


def diff_bundles(dir_a, dir_b, *, anchor_a: str = "", anchor_b: str = "") -> Dict:
    """Compare two bundle directories.

    Anchors are optional here and their absence is reported rather than ignored:
    a diff between two unanchored bundles compares two documents of unknown
    provenance, which is worth knowing before acting on it.
    """
    from . import verify_bundle

    res_a = verify_bundle(dir_a, anchor_a)
    res_b = verify_bundle(dir_b, anchor_b)
    a, b = _read(dir_a), _read(dir_b)

    ca, cb = _certs(a), _certs(b)
    rows: List[Dict] = []
    for key in sorted(set(ca) | set(cb)):
        left, right = ca.get(key), cb.get(key)
        row = {"certificate": key,
               "in_a": left is not None, "in_b": right is not None,
               "admit_a": _admit(left) if left else None,
               "admit_b": _admit(right) if right else None,
               "margin_a": _margin(left) if left else None,
               "margin_b": _margin(right) if right else None,
               "loci_a": _n_loci(left) if left else 0,
               "loci_b": _n_loci(right) if right else 0}
        row["change"] = _classify(row)
        rows.append(row)

    comparable = res_a["ok"] and res_b["ok"]
    regressed = [r for r in rows if r["change"] == REGRESSED]
    improved = [r for r in rows if r["change"] == IMPROVED]
    return {
        "a": {"dir": str(dir_a), "verdict": res_a["verdict"],
              "fingerprint": res_a.get("fingerprint", "")},
        "b": {"dir": str(dir_b), "verdict": res_b["verdict"],
              "fingerprint": res_b.get("fingerprint", "")},
        "comparable": comparable,
        "rows": rows,
        "n_improved": len(improved), "n_regressed": len(regressed),
        "n_added": sum(1 for r in rows if not r["in_a"]),
        "n_removed": sum(1 for r in rows if not r["in_b"]),
        "identical": _same_bytes(dir_a, dir_b),
        "caveat": "" if comparable else (
            "at least one side did not verify, so the movement below describes "
            "two documents rather than two established results"),
    }


def _same_bytes(dir_a, dir_b) -> bool:
    """Byte-identity, without assuming either bundle exists."""
    try:
        return bundle_fingerprint(dir_a) == bundle_fingerprint(dir_b)
    except OSError:
        return False


def _read(d) -> Dict:
    import json
    from pathlib import Path
    try:
        obj = json.loads((Path(d) / "bundle.json").read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else {}
    except (OSError, ValueError):
        return {}


def _classify(row: Dict) -> str:
    """Which way did this certificate move?

    Admission dominates margin: losing admission is a regression however the
    numbers moved, and gaining it is an improvement.
    """
    if not row["in_a"]:
        return IMPROVED if row["admit_b"] else REGRESSED
    if not row["in_b"]:
        return REGRESSED
    if row["admit_a"] != row["admit_b"]:
        return IMPROVED if row["admit_b"] else REGRESSED
    ma, mb = row["margin_a"], row["margin_b"]
    if ma is None or mb is None or ma == mb:
        return UNCHANGED
    return IMPROVED if mb > ma else REGRESSED


def format_diff(d: Dict) -> str:
    lines = [f"A  {d['a']['dir']}   {d['a']['verdict']}",
             f"B  {d['b']['dir']}   {d['b']['verdict']}", ""]
    if d["identical"]:
        lines.append("The two bundles are byte-identical.")
        return "\n".join(lines)
    if d["caveat"]:
        lines += [f"NOTE: {d['caveat']}", ""]
    lines.append(f"{'certificate':38} {'A':>10} {'B':>10}  change")
    for r in d["rows"]:
        def cell(admit, margin, present):
            if not present:
                return "absent"
            tag = "admit" if admit else ("reject" if admit is not None else "-")
            return f"{tag}{'' if margin is None else f' {margin:+.4g}'}"
        lines.append(f"{r['certificate'][:38]:38} "
                     f"{cell(r['admit_a'], r['margin_a'], r['in_a']):>10} "
                     f"{cell(r['admit_b'], r['margin_b'], r['in_b']):>10}  "
                     f"{r['change']}")
    lines += ["", f"{d['n_improved']} improved, {d['n_regressed']} regressed, "
                  f"{d['n_added']} added, {d['n_removed']} removed"]
    return "\n".join(lines)
