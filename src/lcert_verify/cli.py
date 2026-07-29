"""``lcert-verify <bundle_dir> [expected_sha256] [options]``.

Exit codes are a taxonomy, so CI can branch on *why* a check failed:

    0  VERIFIED / VERIFIED-VACUOUS / INTERNALLY-CONSISTENT
    1  REFUTED — a re-derived verdict disagreed with the recorded one
    2  REFUTED — integrity: fingerprint, manifest, Merkle root or commitment
    3  VACUOUS — the bundle certifies nothing
    4  UNVERIFIED — no trust anchor supplied, so no assertion can be made
    5  usage error
"""
from __future__ import annotations

import argparse
import sys

from . import (INTERNALLY_CONSISTENT, UNVERIFIED, VACUOUS, VERIFIED,
               VERIFIED_VACUOUS, verify_bundle)
from ._verifier import SCOPE

EXIT_OK, EXIT_VERDICT, EXIT_INTEGRITY, EXIT_VACUOUS, EXIT_UNANCHORED, EXIT_USAGE = 0, 1, 2, 3, 4, 5

_INTEGRITY_MARKERS = ("fingerprint", "manifest", "merkle", "commitment",
                      "canonical", "not valid json", "missing", "non-finite")


def _exit_code(res) -> int:
    v = res["verdict"]
    if v in (VERIFIED, VERIFIED_VACUOUS, INTERNALLY_CONSISTENT):
        return EXIT_OK
    if v == UNVERIFIED:
        return EXIT_UNANCHORED
    if v == VACUOUS:
        return EXIT_VACUOUS
    blob = " ".join(res.get("errors", [])).lower()
    return EXIT_INTEGRITY if any(m in blob for m in _INTEGRITY_MARKERS) else EXIT_VERDICT


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="lcert-verify",
        description="Re-derive an LCERT-1 certificate's verdict. Abstains rather than "
                    "asserting when a trust anchor is absent.",
        epilog="`lcert-verify serve --help` runs it as an HTTP service instead.")
    ap.add_argument("bundle_dir", nargs="?")
    ap.add_argument("expected_sha256", nargs="?", default="",
                    help="bundle fingerprint obtained OUT OF BAND — the trust anchor")
    ap.add_argument("--no-anchor", action="store_true",
                    help="accept the weaker internal-consistency check on purpose")
    ap.add_argument("--allow-empty", action="store_true",
                    help="permit a bundle that certifies nothing")
    ap.add_argument("--json", action="store_true", help="machine-readable output (JSON)")
    ap.add_argument("--format",
                    choices=["text", "json", "jsonl", "sarif", "junit", "html"],
                    default=None,
                    help="output format. sarif renders in GitHub code scanning; "
                         "junit appears in any CI test report; html is a "
                         "self-contained page with a per-locus margin chart")
    ap.add_argument("--diff", metavar="OTHER_BUNDLE", default=None,
                    help="compare against another bundle: which certificates "
                         "changed class and which way the margins moved")
    ap.add_argument("--diff-anchor", default="",
                    help="trust anchor for the bundle given to --diff")
    ap.add_argument("-o", "--output", default=None,
                    help="write the report to this file instead of stdout")
    ap.add_argument("--stream", action="store_true",
                    help="verify one certificate at a time, for bundles too large "
                         "to hold in memory. Needs the anchor; gives the same verdict")
    ap.add_argument("--scope", action="store_true", help="print what is and is not checked")
    ap.add_argument("--explain", action="store_true",
                    help="show, per locus, which ones prevented admission and by how much")

    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        from .serve import main as serve_main
        return serve_main(argv[1:])

    a = ap.parse_args(argv)

    if a.scope:
        print(SCOPE)
        if not a.bundle_dir:
            return EXIT_OK
    if not a.bundle_dir:
        ap.print_usage(sys.stderr)
        return EXIT_USAGE

    if a.diff:
        from .diff import diff_bundles, format_diff
        d = diff_bundles(a.bundle_dir, a.diff, anchor_a=a.expected_sha256,
                         anchor_b=a.diff_anchor)
        if a.format in ("json", "jsonl"):
            import json as _j
            print(_j.dumps(d, indent=2 if a.format == "json" else None, sort_keys=True))
        else:
            print(format_diff(d))
        # A diff reports movement; it is not a verdict. Non-zero only when
        # something got worse, so it is usable as a regression gate.
        return 1 if d["n_regressed"] else EXIT_OK

    if a.stream:
        from .stream import verify_bundle_streaming
        res = verify_bundle_streaming(a.bundle_dir, a.expected_sha256,
                                      require_certs=not a.allow_empty,
                                      require_anchor=not a.no_anchor)
    else:
        res = verify_bundle(a.bundle_dir, a.expected_sha256,
                            require_certs=not a.allow_empty,
                            require_anchor=not a.no_anchor)

    fmt = a.format or ("json" if a.json else "text")
    if fmt == "html":
        import json as _json
        from pathlib import Path as _P
        from .html import to_html
        try:
            b = _json.loads((_P(a.bundle_dir) / "bundle.json").read_text())
        except (OSError, ValueError):
            b = {}
        out = to_html(res, b, source=str(a.bundle_dir))
        if a.output:
            _P(a.output).write_text(out, encoding="utf-8")
            print(f"wrote html report to {a.output}")
        else:
            print(out, end="")
        return _exit_code(res)
    if fmt != "text":
        from .report import emit
        out = emit(res, fmt, source=str(a.bundle_dir))
        if a.output:
            from pathlib import Path as _P
            _P(a.output).write_text(out + "\n")
            print(f"wrote {fmt} report to {a.output}")
        else:
            print(out)
        return _exit_code(res)

    print(f"bundle fingerprint: sha256:{res['fingerprint']}")
    print(f"trust anchor:       {res['trust_anchor']}")
    print(f"certificates:       {res['n_certificates']}  "
          f"(gated loci: {res['n_gated_loci']})")
    for e in res["errors"]:
        print(f"  - {e}")
    if a.explain:
        import json as _json
        from pathlib import Path as _Path
        from .explain import explain_certificate, format_explanation
        try:
            b = _json.loads((_Path(a.bundle_dir) / "bundle.json").read_text())
        except Exception:
            b = None
        for cert in (b or {}).get("gate_certs", []):
            print()
            print(format_explanation(explain_certificate(cert)))
        print()

    print(f"VERDICT: {res['verdict']}")
    if res["verdict"] == UNVERIFIED:
        print("         (abstained — this is NOT a failure of the certificate, it is a "
              "refusal to assert without evidence)")
    return _exit_code(res)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
