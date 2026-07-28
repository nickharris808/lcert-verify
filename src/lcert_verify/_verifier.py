# BEGIN VERIFIER
# LCERT-1 zero-trust certificate verifier — stdlib only (hashlib, hmac, json, math, sys, pathlib).
# Run:  python -I -S verify_bundle.py <bundle_dir> [expected_bundle_sha256] [--scope]
# Exit: 0 = all checks pass, 1 = any failure.  See --scope for what is and is not checked.
import hashlib
import hmac
import json
import math
import sys
from pathlib import Path

FORMAT = "litholab-cert-bundle/1"
DOMAIN_LEAF = b"LITHOZK-leaf-v1"
DOMAIN_NODE = b"LITHOZK-node-v1"
DOMAIN_SALT = b"LITHOZK-tile-salt-v1"
DOMAIN_MASTER = b"LITHOZK-master-v1"
DOMAIN_PAD = b"LITHOZK-pad-v1"
DOMAIN_OUT = b"LITHOZK-outputs-v1"

SCOPE = (
    "Zero-trust verifier: checks certificate INTERNAL consistency and integrity — (1) canonical-JSON "
    "round-trip + format version; (2) SHA-256 manifest + Merkle root over payload files (domain-separated, "
    "HMAC-salted leaves, duplicate-last-odd levels); (3) outputs-commitment over KPI rows + preregistration-"
    "SHA cross-binding; (4) per-locus interval-gate verdict re-derivation from shipped bounds under "
    "math.nextafter outward rounding, with the kappa/K reduction re-checked via math.erfc (no shipped "
    "transcendental is trusted). It does NOT re-derive the physics: the shipped I_lo/I_hi/ae0 bounds are "
    "trusted-as-committed inputs whose provenance is the bundle SHA-256 fingerprint, compared out of band. "
    "THREAT MODEL: the verdict re-derivation catches INCONSISTENT tampering (edited bounds vs recorded "
    "verdict); a SELF-CONSISTENT false-bounds tamper (bounds + verdict edited together) is caught ONLY by "
    "the out-of-band fingerprint, which is the load-bearing anchor. Shipped salts make commitments "
    "binding-only (not hiding) here. Simulator-relative; not silicon.")


def _sha(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _canon(obj) -> bytes:
    # allow_nan=False: NaN/Infinity are NOT valid JSON. Emitting them produces a
    # document strict parsers (including every browser) reject, which would make a
    # certificate verifiable by one implementation and not another. Refuse instead.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def derive_master_salt(seed: int) -> bytes:
    return _sha(DOMAIN_MASTER, int(seed).to_bytes(8, "big", signed=False))


def derive_tile_salts(master_salt: bytes, n: int) -> list:
    return [hmac.new(master_salt, DOMAIN_SALT + i.to_bytes(4, "big"), hashlib.sha256).digest()
            for i in range(n)]


def leaf_hash(index: int, salt: bytes, leaf_bytes: bytes) -> bytes:
    return _sha(DOMAIN_LEAF, index.to_bytes(4, "big"), salt, leaf_bytes)


def merkle_root(leaves: list) -> bytes:
    if not leaves:
        return _sha(DOMAIN_PAD)
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [_sha(DOMAIN_NODE, level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def outputs_commitment(outputs_salt: bytes, outputs) -> bytes:
    return _sha(DOMAIN_OUT, outputs_salt, _canon(outputs))


def _down(x: float) -> float:
    return math.nextafter(x, -math.inf)


def _up(x: float) -> float:
    return math.nextafter(x, math.inf)


def check_kappa_K(budget: float, safety: float, n_photons: float, kappa: float, K: float) -> list:
    """Re-derive the transcendental constants instead of trusting them.

    kappa must satisfy the erfc round-trip |0.5*erfc(kappa) - budget| < 1e-12 (math.erfc, stdlib),
    and K must equal 2.0*kappa*kappa*safety*safety/n_photons recomputed in the committed operation
    order (bit-identical float64 — same ops, same order as the reference producer).
    """
    errs = []
    if not abs(0.5 * math.erfc(kappa) - budget) < 1e-12:
        errs.append("kappa fails the erfc round-trip against budget")
    K_re = 2.0 * kappa * kappa * float(safety) * float(safety) / float(n_photons)
    if K_re != K:
        errs.append("K does not recompute bit-identically from (kappa, safety, n_photons)")
    return errs


def rederive_gate_verdict(cert: dict) -> dict:
    """Per-locus re-derivation of the interval-gate classification and verdict.

    Frozen semantics of the reference interval gate: outward-rounded
    margin / i_noise intervals per the sub/super-threshold branch, K widened 2 ULP each way,
    certainly_safe = (m_lo > 0) and (down(m_lo*m_lo) >= Kin_hi),
    certainly_unsafe = (m_hi <= 0) or (up(m_hi*m_hi) < Kin_lo),
    ADMIT iff no certainly-unsafe locus and no straddle (straddle -> safe-direction REJECT);
    zero loci -> trivially ADMIT + stable (the committed convention).
    """
    thr = float(cert["thr"])
    d = float(cert["delta_dose"])
    K = float(cert["K"])
    K_lo, K_hi = _down(_down(K)), _up(_up(K))
    loci = cert["loci"]
    I_lo_l, I_hi_l, ae0_l = loci["I_lo"], loci["I_hi"], loci["ae0"]
    n = len(ae0_l)
    n_safe = n_unsafe = n_straddle = 0
    for j in range(n):
        I_lo, I_hi, ae0 = float(I_lo_l[j]), float(I_hi_l[j]), float(ae0_l[j])
        sub = ae0 < thr
        he = (1.0 + d) * I_hi
        le = (1.0 - d) * I_lo
        he_lo, he_hi = _down(he), _up(he)
        le_lo, le_hi = _down(le), _up(le)
        if sub:
            m_lo = _down(thr - he_hi)
            m_hi = _up(thr - he_lo)
            in_lo, in_hi = he_lo, he_hi
        else:
            m_lo = _down(le_lo - thr)
            m_hi = _up(le_hi - thr)
            in_lo, in_hi = le_lo, le_hi
        Kin_lo = _down(K_lo * max(in_lo, 0.0))
        Kin_hi = _up(K_hi * max(in_hi, 0.0))
        safe = (m_lo > 0.0) and (_down(m_lo * m_lo) >= Kin_hi)
        unsafe = (m_hi <= 0.0) or (_up(m_hi * m_hi) < Kin_lo)
        if safe:
            n_safe += 1
        elif unsafe:
            n_unsafe += 1
        else:
            n_straddle += 1
    if n == 0:
        interval_admit, stable = True, True
    elif n_unsafe > 0:
        interval_admit, stable = False, bool(n_straddle == 0)
    elif n_straddle == 0:
        interval_admit, stable = True, True
    else:
        interval_admit, stable = False, False
    return {"interval_admit": interval_admit, "stable": stable, "n_loci": n,
            "n_certainly_safe": n_safe, "n_certainly_unsafe": n_unsafe, "n_straddle": n_straddle}


def verify_gate_certs(bundle: dict) -> list:
    errs = []
    for cert in bundle.get("gate_certs", []):
        name = cert.get("name", "?")
        errs += [f"[{name}] {e}" for e in check_kappa_K(
            float(cert["budget"]), float(cert["safety"]), float(cert["n_photons"]),
            float(cert["kappa"]), float(cert["K"]))]
        red = rederive_gate_verdict(cert)
        rec = cert["recorded"]
        for key, val in red.items():
            if rec.get(key) != val:
                errs.append(f"[{name}] recorded {key}={rec.get(key)!r} but re-derived {val!r}")
        if rec.get("match") != (red["interval_admit"] == rec.get("float_admit")):
            errs.append(f"[{name}] recorded match flag inconsistent with verdicts")
    return errs


def rederive_resource_floor(cert: dict) -> dict:
    """Zero-dependency re-derivation of a patterning-resource-floor certificate.

    Recompute, from the recorded PRIMITIVE inputs only (na, wavelength, i_peak, i_edge, gap, N*,
    feature_count, and the disclosed buyer-adjustable ResourceModel constants), the full minimum-dose
    impossibility chain in the committed operation order (identical to
    the reference certified worst-hotspot survival floor +
    patterning_resource_floor.certified_resource_floor):

        slope_max = 2*pi*(2*na/lambda)*i_peak                  (Bernstein band-limit slope cap)
        sigma_min = sqrt(i_edge/N*)/slope_max                  (Cramer-Rao / band-limit edge-jitter floor)
        p_fail_lb = min(0.5, 0.5*erfc((gap/2)/(sigma_min*sqrt2)))   (the capped per-locus lower bound)
        yield_ceiling = (1 - p_fail_lb)^max(1, M)              (single-worst-locus, NOT the union bound)
        dose*    = N*/(photospeed * gap^2)                     (mJ/cm^2)
        source_W = dose*·1e-3·field_area·fields·wph/(3600·transmission·efficiency)   (watts)
        cost*    = cost_per_wafer / max(yield_ceiling·dies, 1e-9)                     (USD/good die)

    erfc/sqrt/exp are stdlib and identical, so the re-derivation is bit-faithful; the caller compares
    to the recorded values with a relative tolerance (outward rounding on the transcendental step)."""
    na = float(cert["na"]); lam = float(cert["wavelength_nm"]); i_peak = float(cert["i_peak"])
    i_edge = float(cert["i_edge"]); gap = float(cert["gap_nm"]); N = float(cert["n_star"])
    M = float(cert["feature_count"])
    slope_max = 2.0 * math.pi * (2.0 * na / lam) * i_peak
    sigma_min = math.sqrt(i_edge / N) / slope_max
    p_erfc = 0.5 * math.erfc((gap * 0.5) / (sigma_min * math.sqrt(2.0)))
    p = min(0.5, p_erfc)
    y = (1.0 - p) ** max(1.0, M)
    ps = float(cert["photospeed_ph_per_mJcm2_per_nm2"])
    dose = N / (ps * gap * gap)
    source_W = (dose * 1e-3 * float(cert["field_area_cm2"]) * float(cert["fields_per_wafer"])
                * float(cert["wafers_per_hour"])
                / (3600.0 * float(cert["source_to_wafer_transmission"])
                   * float(cert["dose_efficiency"])))
    good = max(y * float(cert["dies_per_wafer"]), 1e-9)
    cost = float(cert["cost_per_wafer_usd"]) / good
    return {"p_fail_lb": p, "yield_ceiling": y, "dose_star_mJcm2": dose,
            "source_power_star_W": source_W, "cost_per_die_floor_usd": cost,
            "slope_max": slope_max, "sigma_min_nm": sigma_min}


def _rel_close(a: float, b: float, tol: float = 1e-9) -> bool:
    """Outward-rounded agreement: |a-b| within `tol` relative to the larger magnitude (>=1 floor)."""
    return abs(a - b) <= tol * max(1.0, abs(a), abs(b))


def verify_resource_floor_certs(bundle: dict) -> list:
    """Re-derive every resource_floor_cert stdlib-only and reject any recorded output that does not
    match, and any N* that does not actually reach its yield_target (the floor must be a valid
    minimum).  Any tamper — union-bound yield, understated noise, shrunken N*, perturbed model
    constant, dropped 0.5 cap — perturbs a re-derived quantity and is caught here."""
    errs = []
    for cert in bundle.get("resource_floor_certs", []):
        name = cert.get("name", "?")
        try:
            red = rederive_resource_floor(cert)
        except (ValueError, ZeroDivisionError, KeyError, OverflowError) as e:
            errs.append(f"[{name}] re-derivation failed: {e}")
            continue
        rec = cert.get("recorded", {})
        for key in ("p_fail_lb", "yield_ceiling", "dose_star_mJcm2", "source_power_star_W",
                    "cost_per_die_floor_usd"):
            if key not in rec:
                errs.append(f"[{name}] recorded {key} missing")
            elif not _rel_close(float(rec[key]), float(red[key])):
                errs.append(f"[{name}] recorded {key}={rec[key]!r} != re-derived {red[key]!r}")
        # the impossibility must be a valid minimum: at the recorded N* the ceiling reaches the target
        if float(red["yield_ceiling"]) < float(cert["yield_target"]) - 1e-9:
            errs.append(f"[{name}] recorded N* does not reach yield_target "
                        f"(re-derived ceiling {red['yield_ceiling']!r} < {cert['yield_target']!r})")
    return errs


def _interval_square_s(lo: float, hi: float) -> tuple:
    """Exact scalar interval square of ``[lo, hi]``, outward-rounded — the scalar mirror of
    the reference interval-square routine.  Same ops => bit-identical results
    (Float-Determinism Lemma)."""
    lo2, hi2 = lo * lo, hi * hi
    if lo >= 0.0:
        sq_lo = lo2
    elif hi <= 0.0:
        sq_lo = hi2
    else:
        sq_lo = 0.0
    sq_hi = hi2 if hi2 > lo2 else lo2
    return _down(sq_lo), _up(sq_hi)


def rederive_image_bound(cert: dict) -> tuple:
    """Re-derive ``[I_lo, I_hi]`` per gated locus from the shipped affine primitives, stdlib-only, in
    the committed kernel order — the scalar mirror of ``nn_verify.ibp_aerial_bounds``.

    The affine coherent field is exact under the box (radius ``Rr_k``/``Ri_k`` shipped as ALREADY-
    SUMMED scalars, so no ``fsum``-vs-numpy reduction-order ambiguity); only ``|.|^2`` is non-linear
    and even there the exact interval square is taken.  ``lam_k >= 0`` preserves the enclosure."""
    p = cert["primitives"]
    bias = float(p["bias"])
    lam = [float(v) for v in p["lam"]]
    Rr = [float(v) for v in p["Rr"]]
    Ri = [float(v) for v in p["Ri"]]
    cr = p["cr"]; ci = p["ci"]                          # each K x n_loci
    K = len(lam)
    n = len(cert["loci"]["ae0"])
    los, his = [], []
    for j in range(n):
        I_lo = bias; I_hi = bias
        for k in range(K):
            crj = float(cr[k][j]); cij = float(ci[k][j])
            r2_lo, r2_hi = _interval_square_s(_down(crj - Rr[k]), _up(crj + Rr[k]))
            i2_lo, i2_hi = _interval_square_s(_down(cij - Ri[k]), _up(cij + Ri[k]))
            mag2_lo = _down(r2_lo + i2_lo)
            mag2_hi = _up(r2_hi + i2_hi)
            I_lo = _down(I_lo + _down(lam[k] * mag2_lo))
            I_hi = _up(I_hi + _up(lam[k] * mag2_hi))
        los.append(I_lo); his.append(I_hi)
    return los, his


def verify_image_bound_certs(bundle: dict) -> list:
    """Re-derive every LCERT-IMG-1 enclosure stdlib-only and reject any recorded bound that is TIGHTER
    than the re-derivation (the false-ADMIT attack), any kappa/K that does not recompute, and any
    recorded interval-gate verdict that does not re-derive from the recorded enclosure.

    Containment is EXACT: the scalar re-derivation is bit-identical to the numpy producer (same ops,
    same order, shipped scalar radii), so a faithfully-recorded enclosure re-derives exactly and any
    narrowing (even 1 ULP toward admit) trips ``E_ENCLOSURE_TOO_TIGHT``."""
    errs = []
    for cert in bundle.get("image_bound_certs", []):
        name = cert.get("name", "?")
        errs += [f"[{name}] {e}" for e in check_kappa_K(
            float(cert["budget"]), float(cert["safety"]), float(cert["n_photons"]),
            float(cert["kappa"]), float(cert["K"]))]
        try:
            re_lo, re_hi = rederive_image_bound(cert)
        except (KeyError, IndexError, ValueError, TypeError, OverflowError) as e:
            errs.append(f"[{name}] enclosure re-derivation failed: {e}")
            continue
        rec_lo = cert["loci"]["I_lo"]; rec_hi = cert["loci"]["I_hi"]
        if len(re_lo) != len(rec_lo) or len(re_hi) != len(rec_hi):
            errs.append(f"[{name}] E_LOCUS_COUNT: recorded {len(rec_lo)} vs re-derived {len(re_lo)}")
            continue
        too_tight = False
        for j in range(len(re_lo)):
            if float(rec_lo[j]) > re_lo[j] or float(rec_hi[j]) < re_hi[j]:
                errs.append(f"[{name}] E_ENCLOSURE_TOO_TIGHT: recorded locus {j} narrower than "
                            f"re-derived ([{rec_lo[j]},{rec_hi[j]}] vs [{re_lo[j]},{re_hi[j]}])")
                too_tight = True
                break
        if too_tight:
            continue
        red = rederive_gate_verdict({"thr": float(cert["thr"]), "delta_dose": float(cert["delta_dose"]),
                                     "K": float(cert["K"]), "loci": cert["loci"]})
        rec = cert.get("recorded", {})
        for key, val in red.items():
            if rec.get(key) != val:
                errs.append(f"[{name}] recorded {key}={rec.get(key)!r} but re-derived {val!r}")
    return errs


def verify_manifest_and_root(bundle_dir: Path, bundle: dict) -> list:
    errs = []
    manifest = bundle.get("manifest", {})
    for rel, want in sorted(manifest.items()):
        p = bundle_dir / rel
        if not p.is_file():
            errs.append(f"manifest file missing: {rel}")
            continue
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        if got != want:
            errs.append(f"manifest hash mismatch: {rel}")
    rows = sorted(manifest.items())
    master_salt = derive_master_salt(int(bundle["seed"]))
    salts = derive_tile_salts(master_salt, len(rows))
    leaves = [leaf_hash(i, salts[i], rel.encode("utf-8") + b"\x00" + bytes.fromhex(h))
              for i, (rel, h) in enumerate(rows)]
    if not hmac.compare_digest(merkle_root(leaves).hex(), bundle["merkle_root"]):
        errs.append("merkle root does not recompute")
    return errs


def verify_kpis(bundle_dir: Path, bundle: dict) -> list:
    errs = []
    kpis = bundle.get("kpis", [])
    salt = bytes.fromhex(bundle["outputs_salt"])
    if not hmac.compare_digest(outputs_commitment(salt, kpis).hex(), bundle["outputs_commitment"]):
        errs.append("outputs commitment does not recompute over the KPI rows")
    prereg_rel = bundle.get("prereg_file")
    if prereg_rel:
        p = bundle_dir / prereg_rel
        if not p.is_file():
            errs.append(f"prereg file missing: {prereg_rel}")
        else:
            prereg_sha = hashlib.sha256(p.read_bytes()).hexdigest()
            if bundle.get("preregistration_sha256") != prereg_sha:
                errs.append("bundle preregistration_sha256 != hash of shipped prereg file")
            for row in kpis:
                if "preregistration_sha256" in row and row["preregistration_sha256"] != prereg_sha:
                    errs.append(f"KPI row {row.get('id','?')} prereg SHA mismatch")
    return errs


def verify_bundle(bundle_dir, expected_sha256: str = "") -> dict:
    """Run every check; return {'ok': bool, 'errors': [...], 'fingerprint': hex}."""
    bundle_dir = Path(bundle_dir)
    bpath = bundle_dir / "bundle.json"
    errs = []
    if not bpath.is_file():
        return {"ok": False, "errors": ["bundle.json missing"], "fingerprint": ""}
    raw = bpath.read_bytes()
    fingerprint = hashlib.sha256(raw).hexdigest()
    if expected_sha256 and not hmac.compare_digest(fingerprint, expected_sha256.lower()):
        errs.append("bundle fingerprint != expected (out-of-band anchor)")
    try:
        bundle = json.loads(raw)
    except ValueError:
        return {"ok": False, "errors": ["bundle.json is not valid JSON"], "fingerprint": fingerprint}
    if not isinstance(bundle, dict):
        # Valid JSON, wrong shape. Crashing on hostile input is a denial of service
        # and an unhelpful failure; reject cleanly instead.
        return {"ok": False, "fingerprint": fingerprint, "errors": [
            f"bundle.json must be a JSON object, got {type(bundle).__name__}"]}
    if bundle.get("format") != FORMAT:
        errs.append(f"unsupported format: {bundle.get('format')!r} (want {FORMAT!r})")
        return {"ok": False, "errors": errs, "fingerprint": fingerprint}
    if _canon(bundle) != raw.strip():
        errs.append("bundle.json is not canonical JSON (round-trip differs)")
    errs += verify_manifest_and_root(bundle_dir, bundle)
    errs += verify_kpis(bundle_dir, bundle)
    errs += verify_gate_certs(bundle)
    errs += verify_resource_floor_certs(bundle)
    errs += verify_image_bound_certs(bundle)
    # `_parsed` is returned so callers need not parse bundle.json a second time.
    # It is stripped by the public wrapper and is not part of the result contract.
    return {"ok": not errs, "errors": errs, "fingerprint": fingerprint, "_parsed": bundle}


def main(argv) -> int:
    args = [a for a in argv[1:] if a != "--scope"]
    if "--scope" in argv[1:]:
        print(SCOPE)
        if not args:
            return 0
    if not args:
        print("usage: verify_bundle.py <bundle_dir> [expected_bundle_sha256] [--scope]")
        return 1
    expected = args[1] if len(args) > 1 else ""
    res = verify_bundle(args[0], expected)
    print(f"bundle fingerprint: sha256:{res['fingerprint']}")
    for e in res["errors"]:
        print(f"FAIL: {e}")
    print("VERDICT: PASS" if res["ok"] else "VERDICT: FAIL")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
# END VERIFIER
