"""Report emitters: one verification result, several output formats.

This module exists so that every consumer — the CLI, the MCP server, a CI job, a
future HTTP service — renders the *same* result object rather than each
re-deriving what a verdict means. Adding a format means adding one function here,
not touching every call site.

Every emitter preserves the abstention discipline: `UNVERIFIED` must never be
rendered as a pass in any format. Where a format has only pass/fail (JUnit), an
abstention is a failure with the reason attached, never a success.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Dict

# Verdict -> (is_success, SARIF level, one-line human summary)
_VERDICT_META: Dict[str, tuple] = {
    "VERIFIED": (True, "none",
                 "verdict re-derived from the certificate's own numbers and anchored"),
    "VERIFIED-VACUOUS": (True, "note",
                         "consistent and anchored, but no locus carried a proof obligation"),
    "INTERNALLY-CONSISTENT": (True, "note",
                              "checks passed; trust anchor deliberately waived"),
    "UNVERIFIED": (False, "warning",
                   "ABSTAINED: no trust anchor, so no assertion can be made"),
    "VACUOUS": (False, "warning", "the bundle certifies nothing"),
    "REFUTED": (False, "error", "a check failed"),
}


def verdict_meta(verdict: str) -> tuple:
    return _VERDICT_META.get(verdict, (False, "error", "unrecognised verdict"))


def to_json(res: dict, *, indent: int = 2) -> str:
    """Full result as JSON. The canonical machine format."""
    return json.dumps(res, indent=indent, sort_keys=True, default=str)


def to_jsonl(res: dict, *, source: str = "") -> str:
    """One line per certificate — convenient for streaming into a log pipeline."""
    ok, level, summary = verdict_meta(res.get("verdict", ""))
    rows = [{
        "source": source,
        "verdict": res.get("verdict"),
        "ok": res.get("ok"),
        "level": level,
        "trust_anchor": res.get("trust_anchor"),
        "n_certificates": res.get("n_certificates"),
        "n_gated_loci": res.get("n_gated_loci"),
        "fingerprint": res.get("fingerprint"),
        "summary": summary,
    }]
    for e in res.get("errors", []):
        rows.append({"source": source, "verdict": res.get("verdict"), "error": e})
    return "\n".join(json.dumps(r, sort_keys=True) for r in rows)


def to_sarif(res: dict, *, source: str = "bundle.json", tool_version: str = "1.0.0") -> str:
    """SARIF 2.1.0 — renders in GitHub code scanning and most IDE problem panes.

    An abstention is emitted at `warning` level with the reason, never suppressed:
    a reader scanning the Security tab must see that no assertion was made.
    """
    ok, level, summary = verdict_meta(res.get("verdict", ""))
    results = []
    if not ok:
        for e in res.get("errors", []) or [summary]:
            results.append({
                "ruleId": f"lcert/{(res.get('verdict') or 'UNKNOWN').lower()}",
                "level": level,
                "message": {"text": e},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": source}}}],
            })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "lcert-verify",
                "version": tool_version,
                "informationUri": "https://github.com/nickharris808/lcert-verify",
                "rules": [{
                    "id": f"lcert/{v.lower()}",
                    "name": v,
                    "shortDescription": {"text": m[2]},
                    "defaultConfiguration": {"level": m[1]},
                } for v, m in _VERDICT_META.items()],
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": bool(ok),
                "exitCodeDescription": summary,
            }],
        }],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


def to_junit(res: dict, *, source: str = "bundle.json") -> str:
    """JUnit XML — appears in the test report of essentially every CI system.

    JUnit has no 'abstained' state. An abstention is therefore a **failure** with
    the reason attached: reporting it as a pass would be exactly the confident
    wrong answer this project exists to avoid.
    """
    ok, _level, summary = verdict_meta(res.get("verdict", ""))
    suite = ET.Element("testsuite", {
        "name": "lcert-verify", "tests": "1",
        "failures": "0" if ok else "1", "errors": "0",
        "skipped": "0",
    })
    case = ET.SubElement(suite, "testcase", {
        "classname": "lcert-verify", "name": f"verify {source}",
    })
    if not ok:
        # `.get(k, default)` does not help when the key is present and None, and
        # ElementTree refuses to serialise None. A result with no verdict is
        # exactly the case that must still render, so coerce.
        f = ET.SubElement(case, "failure", {
            "type": str(res.get("verdict") or "UNKNOWN"), "message": str(summary),
        })
        f.text = "\n".join(res.get("errors", []) or [summary])
    ET.SubElement(suite, "system-out").text = (
        f"verdict={res.get('verdict')} trust_anchor={res.get('trust_anchor')} "
        f"certificates={res.get('n_certificates')} gated_loci={res.get('n_gated_loci')} "
        f"fingerprint={res.get('fingerprint')}")
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            + ET.tostring(suite, encoding="unicode"))


EMITTERS = {"json": to_json, "jsonl": to_jsonl, "sarif": to_sarif, "junit": to_junit}


def emit(res: dict, fmt: str, **kw) -> str:
    if fmt not in EMITTERS:
        raise ValueError(f"unknown format {fmt!r}; choose from {sorted(EMITTERS)}")
    fn = EMITTERS[fmt]
    if fmt == "json":
        return fn(res)
    return fn(res, **{k: v for k, v in kw.items()
                      if k in fn.__code__.co_varnames})
