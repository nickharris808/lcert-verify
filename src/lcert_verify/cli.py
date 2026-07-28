"""Command line: ``lcert-verify <bundle_dir> [expected_sha256] [--scope] [--allow-empty]``.

Wraps the frozen standalone verifier, whose ``main`` follows the C convention of
taking the program name as ``argv[0]``, and adds the vacuity guard: a bundle
carrying no certificates is a failure unless ``--allow-empty`` is given.
"""
from __future__ import annotations

import sys

from . import verify_bundle
from ._verifier import SCOPE

PROG = "lcert-verify"
USAGE = (f"usage: {PROG} <bundle_dir> [expected_sha256] [--scope] [--allow-empty]")


def main(argv=None) -> int:
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    allow_empty = "--allow-empty" in argv
    show_scope = "--scope" in argv
    args = [a for a in argv if not a.startswith("--")]

    if show_scope:
        print(SCOPE)
        if not args:
            return 0
    if not args:
        print(USAGE)
        return 1

    res = verify_bundle(args[0], args[1] if len(args) > 1 else "",
                        require_certs=not allow_empty)
    print(f"bundle fingerprint: sha256:{res['fingerprint']}")
    print(f"certificates checked: {res.get('n_certificates', 0)}")
    for e in res["errors"]:
        print(f"FAIL: {e}")
    print("VERDICT: PASS" if res["ok"] else "VERDICT: FAIL")
    return 0 if res["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
