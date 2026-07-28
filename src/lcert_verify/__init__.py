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


def verify_bundle(bundle_dir, expected_sha256: str = "", *, require_certs: bool = True):
    """Verify a bundle, refusing a vacuous one by default.

    The underlying format check answers "is this bundle internally consistent?".
    A bundle carrying **no certificates at all** is trivially consistent, so a bare
    format check reports success on it — which a reader would mistake for "something
    was certified". An attacker can exploit that by simply deleting the certificates.

    With ``require_certs=True`` (the default) an empty bundle is an error. Pass
    ``require_certs=False`` if you genuinely want the format-only check, and supply
    ``expected_sha256`` — obtained out of band — whenever you can, since it detects
    this and every other whole-file substitution.
    """
    res = dict(_verify_bundle_raw(bundle_dir, expected_sha256))
    n = _count_certs(bundle_dir)
    res["n_certificates"] = n
    if require_certs and n == 0:
        res = dict(res)
        res["errors"] = list(res.get("errors", [])) + [
            "bundle carries no certificates — nothing was verified. This is a "
            "vacuous bundle; pass require_certs=False if that is intended."]
        res["ok"] = False
    return res


def _count_certs(bundle_dir) -> int:
    """Count certificates of every kind carried by a bundle (0 if unreadable)."""
    import json
    from pathlib import Path
    try:
        b = json.loads((Path(bundle_dir) / "bundle.json").read_text())
    except Exception:
        return 0
    return sum(len(b.get(k) or []) for k in
               ("gate_certs", "image_bound_certs", "resource_floor_certs"))
