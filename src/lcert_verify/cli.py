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
import json
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
                    "asserting when a trust anchor is absent.")
    ap.add_argument("bundle_dir", nargs="?")
    ap.add_argument("expected_sha256", nargs="?", default="",
                    help="bundle fingerprint obtained OUT OF BAND — the trust anchor")
    ap.add_argument("--no-anchor", action="store_true",
                    help="accept the weaker internal-consistency check on purpose")
    ap.add_argument("--allow-empty", action="store_true",
                    help="permit a bundle that certifies nothing")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--scope", action="store_true", help="print what is and is not checked")

    a = ap.parse_args(argv if argv is not None else sys.argv[1:])

    if a.scope:
        print(SCOPE)
        if not a.bundle_dir:
            return EXIT_OK
    if not a.bundle_dir:
        ap.print_usage(sys.stderr)
        return EXIT_USAGE

    res = verify_bundle(a.bundle_dir, a.expected_sha256,
                        require_certs=not a.allow_empty,
                        require_anchor=not a.no_anchor)

    if a.json:
        print(json.dumps(res, indent=2, sort_keys=True))
        return _exit_code(res)

    print(f"bundle fingerprint: sha256:{res['fingerprint']}")
    print(f"trust anchor:       {res['trust_anchor']}")
    print(f"certificates:       {res['n_certificates']}  "
          f"(gated loci: {res['n_gated_loci']})")
    for e in res["errors"]:
        print(f"  - {e}")
    print(f"VERDICT: {res['verdict']}")
    if res["verdict"] == UNVERIFIED:
        print("         (abstained — this is NOT a failure of the certificate, it is a "
              "refusal to assert without evidence)")
    return _exit_code(res)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
