"""Verify a bundle without holding all of it in memory at once.

`verify_bundle` parses `bundle.json` into Python objects. That is fine until the
loci arrays get large: a locus is a handful of floats, each a 24-byte Python
object inside a list, so peak memory runs roughly **9x the file size**. Measured,
an 800,000-locus bundle is 22 MB on disk and 210 MB resident.

This module walks the document incrementally and verifies **one certificate at a
time**, discarding each before reading the next. Peak memory becomes the file
plus the largest single certificate, rather than the file plus everything.

**When it helps, and when it does not.** Both numbers below are the same 22 MB
file with the same 800,000 loci, differing only in how they are grouped:

| Shape | Ordinary | Streaming |
|---|---|---|
| 100 certificates x 8,000 loci | 214 MB | **50 MB** |
| 1 certificate x 800,000 loci | 210 MB | 189 MB |

The second row is the honest limit: nothing can stream *inside* one certificate,
because its loci arrays have to exist before they can be checked. If your bundles
are one enormous certificate, this module buys you almost nothing, and the fix is
to split the certificate — which the format has always allowed.

Three design choices, all deliberate:

**It is not in the frozen verifier.** `_verifier.py` is one stdlib file small
enough to read in full, and that auditability is the package's headline property.
This module calls the *same* checking functions the ordinary path calls; nothing
about how a certificate is judged is reimplemented, only how it is reached.

**It uses the standard library's own incremental decoder.** An earlier version
scanned bytes by hand to find value boundaries. It was correct and it was four
times slower, because a 22 MB byte-at-a-time Python loop costs more than the
parse it was avoiding. `JSONDecoder.raw_decode` does the same job in C.

**It requires a trust anchor.** The ordinary path also checks that `bundle.json`
round-trips through the canonical serializer, which needs the whole document at
once. Streaming cannot do that, so it does not pretend to: with no fingerprint it
returns `UNVERIFIED`. With one, byte identity is established exactly, which is
strictly stronger than the canonical check — the same argument the JavaScript
implementation already makes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Dict, List

from . import _verifier as V

#: Keys whose values are arrays of certificates, consumed one element at a time.
CERT_ARRAYS = ("gate_certs", "image_bound_certs", "resource_floor_certs",
               "interval_bound_certs")

#: Read size for the fingerprint pass, which is constant-memory at any file size.
CHUNK = 1 << 20

_CHECKERS = {
    "gate_certs": V.verify_gate_certs,
    "image_bound_certs": V.verify_image_bound_certs,
    "resource_floor_certs": V.verify_resource_floor_certs,
    "interval_bound_certs": V.verify_interval_bound_certs,
}

_WS = " \t\r\n"


class ScanError(ValueError):
    """The document is not a JSON object this walker can read."""


def fingerprint(path) -> str:
    """SHA-256 of a file, read in chunks. Constant memory at any size."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def _skip(text: str, i: int) -> int:
    while i < len(text) and text[i] in _WS:
        i += 1
    return i


def walk(text: str, on_certificate) -> Dict:
    """Walk a top-level JSON object, streaming the certificate arrays.

    Returns everything *except* the certificate arrays as an ordinary dict — all
    of it small by construction. Each certificate is handed to
    ``on_certificate(key, cert)`` and then dropped.
    """
    dec = json.JSONDecoder()
    i = _skip(text, 0)
    if not text[i:i + 1] == "{":
        raise ScanError("bundle.json must be a JSON object")
    i += 1
    head: Dict = {}
    while True:
        i = _skip(text, i)
        if i >= len(text):
            raise ScanError("unterminated object")
        if text[i] == "}":
            return head
        if text[i] == ",":
            i += 1
            continue
        if text[i] != '"':
            raise ScanError(f"expected a key at character {i}")
        key, i = dec.raw_decode(text, i)
        i = _skip(text, i)
        if text[i:i + 1] != ":":
            raise ScanError(f"expected ':' after key {key!r}")
        i = _skip(text, i + 1)

        if key in CERT_ARRAYS:
            if text[i] != "[":
                raise ScanError(f"{key} must be an array")
            i += 1
            while True:
                i = _skip(text, i)
                if i >= len(text):
                    raise ScanError(f"unterminated {key} array")
                if text[i] == "]":
                    i += 1
                    break
                if text[i] == ",":
                    i += 1
                    continue
                cert, i = dec.raw_decode(text, i)
                on_certificate(key, cert)
                del cert
        else:
            head[key], i = dec.raw_decode(text, i)


def verify_bundle_streaming(bundle_dir, expected_sha256: str = "", *,
                            require_certs: bool = True,
                            require_anchor: bool = True,
                            progress=None) -> Dict:
    """Streaming counterpart of :func:`lcert_verify.verify_bundle`.

    Same result shape and same verdicts; ``streaming: True`` is added so a caller
    can tell which path produced it. ``progress(n_so_far)`` is called per
    certificate if supplied.
    """
    bundle_dir = Path(bundle_dir)
    bpath = bundle_dir / "bundle.json"
    if not bpath.is_file():
        return _result(["bundle.json missing"], "", 0, 0, expected_sha256,
                       require_certs, require_anchor)

    fp = fingerprint(bpath)
    errors: List[str] = []
    if expected_sha256 and not hmac.compare_digest(fp, expected_sha256.lower()):
        errors.append("bundle fingerprint != expected (out-of-band anchor)")

    try:
        text = bpath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return _result(errors + [f"bundle.json is not readable UTF-8: {exc}"], fp,
                       0, 0, expected_sha256, require_certs, require_anchor)

    counts = {"certs": 0, "loci": 0}

    def on_certificate(key, cert):
        # One certificate at a time, through the SAME checker the ordinary path
        # uses. Nothing about judging a certificate is reimplemented here.
        errors.extend(_CHECKERS[key]({key: [cert]}))
        counts["certs"] += 1
        # An entry that is not an object is not a certificate. The checker above
        # reports it; counting must not be what raises on it.
        loci = cert.get("loci") if isinstance(cert, dict) else None
        if isinstance(loci, dict):
            for lk in ("ae0", "lo"):
                if isinstance(loci.get(lk), list):
                    counts["loci"] += len(loci[lk])
                    break
        if progress:
            progress(counts["certs"])

    try:
        head = walk(text, on_certificate)
    except RecursionError:
        # See the note in _verifier.verify_bundle: a hostile document must be
        # rejected, never allowed to crash the checker.
        return _result(errors + ["bundle.json is nested too deeply to parse — "
                                 "rejected rather than crashed, but nothing about "
                                 "it was established"], fp, counts["certs"],
                       counts["loci"], expected_sha256, require_certs, require_anchor)
    except (ScanError, ValueError) as exc:
        return _result(errors + [f"bundle.json could not be read: {exc}"], fp,
                       counts["certs"], counts["loci"], expected_sha256,
                       require_certs, require_anchor)
    finally:
        del text

    if head.get("format") != V.FORMAT:
        return _result(errors + [f"unsupported format: {head.get('format')!r} "
                                 f"(want {V.FORMAT!r})"], fp, 0, 0,
                       expected_sha256, require_certs, require_anchor)

    errors += V.verify_manifest_and_root(bundle_dir, head)
    errors += V.verify_kpis(bundle_dir, head)

    return _result(errors, fp, counts["certs"], counts["loci"], expected_sha256,
                   require_certs, require_anchor)


def _result(errors, fp, n_certs, n_loci, anchor, require_certs, require_anchor):
    """Assemble the verdict by the same rules the ordinary wrapper uses.

    The verdict names are imported from the package rather than repeated here, so
    the two paths cannot drift apart through a typo. The import is inside the
    function because the package imports this module.
    """
    from . import (
        INTERNALLY_CONSISTENT as V_INTERNAL,
        REFUTED as V_REFUTED,
        UNVERIFIED as V_UNVERIFIED,
        VACUOUS as V_VACUOUS,
        VERIFIED as V_VERIFIED,
        VERIFIED_VACUOUS as V_VERIFIED_VACUOUS,
        _NO_ANCHOR as NO_ANCHOR,
    )
    errors = list(errors)
    internally_consistent = not errors
    if errors:
        verdict, ok = V_REFUTED, False
    elif require_certs and n_certs == 0:
        verdict, ok = V_VACUOUS, False
        errors.append("bundle carries no certificates — nothing was verified. This is a "
                      "vacuous bundle; pass require_certs=False if that is intended.")
    elif not anchor:
        if require_anchor:
            verdict, ok = V_UNVERIFIED, False
            errors.append(NO_ANCHOR)
        else:
            verdict, ok = V_INTERNAL, True
    elif n_loci == 0:
        verdict, ok = V_VERIFIED_VACUOUS, True
    else:
        verdict, ok = V_VERIFIED, True
    return {"ok": ok, "verdict": verdict, "errors": errors, "fingerprint": fp,
            "n_certificates": n_certs, "n_gated_loci": n_loci,
            "trust_anchor": "fingerprint" if anchor else "NONE",
            "internally_consistent": internally_consistent, "streaming": True}
