"""Reference LCERT-1 bundle builder — stdlib only.

A verifier nobody can produce input for is untestable.  This module is the
minimal *reference producer*: it emits a well-formed ``litholab-cert-bundle/1``
directory from certificates and key/value rows you supply, using exactly the
commitment spine the verifier re-derives.

It deliberately does **not** compute any physics.  Producing a *meaningful*
certificate — one whose legs correspond to a real manufacturability, process
window, model-robustness or photon-shot guarantee — requires the certification
engine, which is not part of this package.  What this builder produces is a
structurally valid bundle: correct manifest, Merkle root, outputs commitment and
canonical JSON.  That is what conformance testing needs.
"""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

from . import _verifier as V


def make_bundle(bundle_dir, *, gate_certs=None, kpis=None, prereg=None, seed: int = 149,
                payload_files=None, image_bound_certs=None, resource_floor_certs=None) -> Path:
    """Write a canonical bundle directory; return the path to ``bundle.json``.

    ``prereg`` is any JSON-serializable object recording what was declared
    *before* measurement; it is always copied in and manifest-covered.
    """
    bundle_dir = Path(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    prereg_rel = "preregistration.json"
    (bundle_dir / prereg_rel).write_bytes(V._canon(prereg if prereg is not None else {}) + b"\n")
    files = {prereg_rel: bundle_dir / prereg_rel}

    for rel, src in (payload_files or {}).items():
        dst = bundle_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(Path(src).read_bytes())
        files[rel] = dst

    manifest = {rel: hashlib.sha256(p.read_bytes()).hexdigest()
                for rel, p in sorted(files.items())}

    master_salt = V.derive_master_salt(int(seed))
    rows = sorted(manifest.items())
    salts = V.derive_tile_salts(master_salt, len(rows))
    leaves = [V.leaf_hash(i, salts[i], rel.encode("utf-8") + b"\x00" + bytes.fromhex(h))
              for i, (rel, h) in enumerate(rows)]
    root = V.merkle_root(leaves).hex()

    kpis = list(kpis or [])
    outputs_salt = hmac.new(master_salt, V.DOMAIN_OUT + b"cert-bundle-kpis",
                            hashlib.sha256).digest()

    bundle = {
        "format": V.FORMAT,
        "seed": int(seed),
        "manifest": manifest,
        "merkle_root": root,
        "prereg_file": prereg_rel,
        "preregistration_sha256": manifest[prereg_rel],
        "kpis": kpis,
        "outputs_salt": outputs_salt.hex(),
        "outputs_commitment": V.outputs_commitment(outputs_salt, kpis).hex(),
        "gate_certs": list(gate_certs or []),
    }
    if image_bound_certs:
        bundle["image_bound_certs"] = list(image_bound_certs)
    if resource_floor_certs:
        bundle["resource_floor_certs"] = list(resource_floor_certs)

    out = bundle_dir / "bundle.json"
    out.write_bytes(V._canon(bundle) + b"\n")
    return out


def bundle_fingerprint(bundle_dir) -> str:
    """SHA-256 of ``bundle.json`` — the out-of-band trust anchor."""
    return hashlib.sha256((Path(bundle_dir) / "bundle.json").read_bytes()).hexdigest()


def kappa_for_budget(budget: float, lo: float = 0.0, hi: float = 40.0) -> float:
    """Invert 0.5*erfc(kappa) = budget by bisection, to the tolerance the verifier enforces.

    The verifier does not trust a supplied kappa; it re-runs the erfc round-trip.  This helper
    produces a kappa that survives that check.
    """
    import math
    for _ in range(500):
        mid = 0.5 * (lo + hi)
        if 0.5 * math.erfc(mid) > budget:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def gate_cert(name: str, *, budget: float, safety: float, n_photons: float,
              thr: float, delta_dose: float, loci) -> dict:
    """Assemble a stochastic gate certificate record in LCERT columnar form.

    ``loci`` is an iterable of ``(I_lo, I_hi, ae0)`` triples.  ``kappa`` and ``K`` are derived
    here and re-derived by the verifier; the verdict is likewise re-derived, never supplied --
    which is the entire point of the format.
    """
    kappa = kappa_for_budget(float(budget))
    K = 2.0 * kappa * kappa * float(safety) * float(safety) / float(n_photons)
    rows = [(float(a), float(b), float(c)) for (a, b, c) in loci]
    cert = {
        "name": str(name),
        "budget": float(budget),
        "safety": float(safety),
        "n_photons": float(n_photons),
        "kappa": kappa,
        "K": K,
        "thr": float(thr),
        "delta_dose": float(delta_dose),
        "loci": {
            "I_lo": [r[0] for r in rows],
            "I_hi": [r[1] for r in rows],
            "ae0": [r[2] for r in rows],
        },
    }
    red = V.rederive_gate_verdict(cert)
    cert["recorded"] = dict(red)
    cert["recorded"]["float_admit"] = red["interval_admit"]
    cert["recorded"]["match"] = True
    return cert
