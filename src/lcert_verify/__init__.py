"""lcert-verify — a zero-trust verifier for LCERT-1 proof-carrying certificates.

The verifier re-derives a certificate's verdict from the primitive quantities the
certificate carries, using only the Python standard library.  It checks internal
consistency and integrity; it does **not** re-run the physics.  See ``SCOPE``.
"""
from ._verifier import (  # noqa: F401
    FORMAT,
    SCOPE,
    check_kappa_K,
    derive_master_salt,
    derive_tile_salts,
    leaf_hash,
    merkle_root,
    outputs_commitment,
    rederive_gate_verdict,
    verify_gate_certs,
    verify_kpis,
    verify_manifest_and_root,
)
from ._verifier import verify_bundle as _verify_bundle_raw
from .builder import bundle_fingerprint, gate_cert, kappa_for_budget, make_bundle  # noqa: F401
from .explain import explain_certificate, format_explanation  # noqa: F401
from .report import emit, to_json, to_jsonl, to_junit, to_sarif  # noqa: F401


# Verdict taxonomy. The distinction that matters: VERIFIED is an assertion, and
# it is only ever reached when the evidence supports it. Everything short of that
# is an abstention or a refutation, never a quiet pass.
VERIFIED = "VERIFIED"                        # anchored, every check passed, something was certified
VERIFIED_VACUOUS = "VERIFIED-VACUOUS"        # anchored and consistent, but zero gated loci
INTERNALLY_CONSISTENT = "INTERNALLY-CONSISTENT"   # checks pass, anchor deliberately waived
UNVERIFIED = "UNVERIFIED"                    # ABSTAIN: no trust anchor, so cannot assert
VACUOUS = "VACUOUS"                          # nothing was certified
REFUTED = "REFUTED"                          # a check actually failed

_NO_ANCHOR = (
    "no trust anchor supplied — the bundle is internally consistent, but internal "
    "consistency cannot distinguish a genuine certificate from a self-consistent "
    "forgery (one where the physics inputs AND the recorded verdict were edited "
    "together). Supply the expected bundle fingerprint, obtained out of band, as the "
    "second argument. To accept the weaker internal-consistency check on purpose, "
    "pass require_anchor=False.")


def verify_bundle(bundle_dir, expected_sha256: str = "", *,
                  require_certs: bool = True, require_anchor: bool = True):
    """Verify a bundle, abstaining rather than asserting when evidence is missing.

    Returns a dict with ``verdict`` (see the taxonomy above), ``ok``,
    ``trust_anchor`` (``"fingerprint"`` or ``"NONE"``), ``internally_consistent``,
    ``n_certificates``, ``n_gated_loci``, ``errors`` and ``fingerprint``.

    **Why an anchor is required by default.** The re-derivation catches any tamper
    that leaves the recorded verdict inconsistent with the shipped bounds. It cannot
    catch a tamper that edits both consistently — that forgery is internally perfect,
    and only a fingerprint obtained out of band refutes it. Reporting such a bundle as
    verified would be asserting something this code did not establish, so it abstains.
    """
    res = dict(_verify_bundle_raw(bundle_dir, expected_sha256))
    errors = list(res.get("errors", []))
    # The raw verifier already parsed bundle.json; reuse its object rather than
    # parsing a multi-megabyte document again. Falls back if it bailed early.
    parsed = res.pop("_parsed", None)
    if not isinstance(parsed, dict):
        parsed = _load_bundle(bundle_dir)
    n_certs = _count_certs(parsed)
    n_loci = _count_gated_loci(parsed)
    nonfinite = _nonfinite_fields(parsed)

    res["n_certificates"] = n_certs
    res["n_gated_loci"] = n_loci
    res["trust_anchor"] = "fingerprint" if expected_sha256 else "NONE"

    if nonfinite:
        errors.append(
            f"non-finite value(s) in {', '.join(nonfinite)} — NaN and Infinity are not "
            f"valid JSON and cannot be canonically committed; the bundle is malformed")

    res["internally_consistent"] = not errors

    if errors:
        res["verdict"] = REFUTED
        res["ok"] = False
    elif require_certs and n_certs == 0:
        res["verdict"] = VACUOUS
        res["ok"] = False
        errors.append(
            "bundle carries no certificates — nothing was verified. This is a vacuous "
            "bundle; pass require_certs=False if that is intended.")
    elif not expected_sha256:
        if require_anchor:
            res["verdict"] = UNVERIFIED
            res["ok"] = False
            errors.append(_NO_ANCHOR)
        else:
            res["verdict"] = INTERNALLY_CONSISTENT
            res["ok"] = True
    elif n_loci == 0:
        # Every check passed, but no locus carried a proof obligation. Saying
        # "VERIFIED" here would sell a guarantee nothing had to earn.
        res["verdict"] = VERIFIED_VACUOUS
        res["ok"] = True
    else:
        res["verdict"] = VERIFIED
        res["ok"] = True

    res["errors"] = errors
    return res


def _load_bundle(bundle_dir):
    """Parse bundle.json once. Returns None if absent, unparseable, or not an object.

    Callers should parse ONCE and pass the result to the helpers below; each of
    them used to re-read and re-parse the file, which cost four full parses of a
    multi-megabyte document per verification.
    """
    import json
    from pathlib import Path
    try:
        b = json.loads((Path(bundle_dir) / "bundle.json").read_text())
    except Exception:
        return None
    # Valid JSON of the wrong shape is not a bundle. Returning it would make every
    # caller re-discover the same AttributeError.
    return b if isinstance(b, dict) else None


def _count_certs(b) -> int:
    """Count certificates of every kind in an already-parsed bundle."""
    if not isinstance(b, dict):
        return 0
    return sum(len(b.get(k) or []) for k in
               ("gate_certs", "image_bound_certs", "resource_floor_certs"))


def _count_gated_loci(b) -> int:
    """Total loci carrying a proof obligation. Zero means nothing had to be proven."""
    if not isinstance(b, dict):
        return 0
    n = 0
    for c in b.get("gate_certs") or []:
        loci = c.get("loci") or {}
        n += len(loci.get("ae0") or [])
    return n


def _nonfinite_fields(b):
    """Names of numeric fields holding NaN/Infinity, which are not valid JSON."""
    import math
    if not isinstance(b, dict):
        return []
    bad = []
    for i, c in enumerate(b.get("gate_certs") or []):
        for k in ("budget", "safety", "n_photons", "kappa", "K", "thr", "delta_dose"):
            v = c.get(k)
            if isinstance(v, float) and not math.isfinite(v):
                bad.append(f"gate_certs[{i}].{k}")
        for k, vals in (c.get("loci") or {}).items():
            if isinstance(vals, list) and any(
                    isinstance(v, float) and not math.isfinite(v) for v in vals):
                bad.append(f"gate_certs[{i}].loci.{k}")
    return bad


__version__ = "1.0.0"
__all__ = [
    "FORMAT", "SCOPE", "verify_bundle", "verify_gate_certs", "verify_kpis",
    "verify_manifest_and_root", "rederive_gate_verdict", "check_kappa_K",
    "derive_master_salt", "derive_tile_salts", "leaf_hash", "merkle_root",
    "outputs_commitment", "make_bundle", "gate_cert", "kappa_for_budget",
    "bundle_fingerprint", "explain_certificate", "format_explanation",
    "emit", "to_json", "to_jsonl", "to_sarif", "to_junit", "__version__",
]
