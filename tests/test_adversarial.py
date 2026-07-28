"""Adversarial regression suite.

The governing oracle for every test here:

    NO INPUT MAY PRODUCE A CONFIDENT-LOOKING ANSWER THAT IS WRONG.

A verifier is allowed to say ADMIT, REJECT, or "I cannot tell". It is never
allowed to say ADMIT when it has not earned it. When in doubt, refuse.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import lcert_verify as L
from lcert_verify import _verifier as V

SAFE = [(0.10, 0.11, 0.05), (0.09, 0.10, 0.04)]
STRADDLE = [(0.29, 0.31, 0.05)]


def _bundle(loci, tmp, thr=0.30, dd=0.02):
    cert = L.gate_cert("x", budget=0.05, safety=1.5, n_photons=100.0,
                       thr=thr, delta_dose=dd, loci=loci)
    L.make_bundle(tmp, gate_certs=[cert], kpis=[], prereg={"declared": "before"})
    return Path(tmp)


def _rewrite(d: Path, fn):
    b = json.loads((d / "bundle.json").read_text())
    fn(b)
    (d / "bundle.json").write_bytes(V._canon(b) + b"\n")
    return b


def _self_consistent_forgery(d: Path):
    """Edit the physics AND recompute the verdict so the two agree.

    This is the strongest forgery the format admits: every internal check passes,
    because the attacker did the arithmetic correctly on fabricated inputs.
    """
    def fn(b):
        c = b["gate_certs"][0]
        c["loci"]["I_lo"] = [0.10] * len(c["loci"]["ae0"])
        c["loci"]["I_hi"] = [0.11] * len(c["loci"]["ae0"])
        red = V.rederive_gate_verdict(c)
        c["recorded"] = dict(red)
        c["recorded"]["float_admit"] = red["interval_admit"]
        c["recorded"]["match"] = True
    return _rewrite(d, fn)


# ---------------------------------------------------------------- THE headline

def test_self_consistent_forgery_is_not_silently_accepted(tmp_path):
    """A forgery that survives every internal check must NOT read as verified.

    Without an out-of-band anchor the verifier cannot distinguish this from a
    genuine certificate. It must therefore ABSTAIN rather than assert.
    """
    d = _bundle(STRADDLE, tmp_path)
    rec = json.loads((d / "bundle.json").read_text())["gate_certs"][0]["recorded"]
    assert rec["interval_admit"] is False
    _self_consistent_forgery(d)

    res = L.verify_bundle(d)
    assert res["verdict"] != "VERIFIED", (
        "a self-consistent forgery was reported as VERIFIED — the verifier "
        "asserted something it did not earn")
    assert res["verdict"] == "UNVERIFIED"
    assert res["trust_anchor"] == "NONE"
    assert any("anchor" in e.lower() or "fingerprint" in e.lower() for e in res["errors"])


def test_anchored_verification_detects_the_same_forgery(tmp_path):
    """With the anchor supplied, the forgery is positively caught."""
    d = _bundle(SAFE, tmp_path)
    good_fp = L.bundle_fingerprint(d)
    _self_consistent_forgery(d)
    res = L.verify_bundle(d, good_fp)
    assert res["verdict"] == "REFUTED"
    assert res["ok"] is False


def test_genuine_bundle_with_anchor_is_verified(tmp_path):
    """The honest path must still reach a positive verdict."""
    d = _bundle(SAFE, tmp_path)
    res = L.verify_bundle(d, L.bundle_fingerprint(d))
    assert res["verdict"] == "VERIFIED"
    assert res["trust_anchor"] == "fingerprint"
    assert res["ok"] is True


def test_unanchored_genuine_bundle_abstains_not_passes(tmp_path):
    """Even an honest bundle cannot be *verified* without an anchor."""
    d = _bundle(SAFE, tmp_path)
    res = L.verify_bundle(d)
    assert res["verdict"] == "UNVERIFIED"
    assert res["ok"] is False
    assert res["internally_consistent"] is True     # the weaker fact IS reported


def test_require_anchor_false_is_an_explicit_opt_out(tmp_path):
    """Opting out is allowed, but the result still says the anchor was absent."""
    d = _bundle(SAFE, tmp_path)
    res = L.verify_bundle(d, require_anchor=False)
    assert res["ok"] is True
    assert res["verdict"] == "INTERNALLY-CONSISTENT"
    assert res["trust_anchor"] == "NONE"


def test_wrong_anchor_is_refuted(tmp_path):
    d = _bundle(SAFE, tmp_path)
    res = L.verify_bundle(d, "ab" * 32)
    assert res["verdict"] == "REFUTED" and res["ok"] is False


# ---------------------------------------------------------------- vacuity

def test_vacuous_bundle_never_reads_as_verified(tmp_path):
    L.make_bundle(tmp_path, gate_certs=[], kpis=[], prereg={})
    fp = L.bundle_fingerprint(tmp_path)
    res = L.verify_bundle(tmp_path, fp)
    assert res["verdict"] != "VERIFIED"
    assert res["n_certificates"] == 0


def test_soundness_flag_is_not_asserted_on_empty_input(tmp_path):
    """A certificate with zero loci is trivially 'admit'; it must not be sold as
    a positive result without saying it certified nothing."""
    d = _bundle([], tmp_path)
    res = L.verify_bundle(d, L.bundle_fingerprint(d))
    cert = json.loads((d / "bundle.json").read_text())["gate_certs"][0]
    assert cert["recorded"]["n_loci"] == 0
    assert res["n_gated_loci"] == 0
    assert res["verdict"] == "VERIFIED-VACUOUS"


# ---------------------------------------------------------------- malformed

@pytest.mark.parametrize("payload", [
    b"", b"{", b"not json", b"\x00\x01\x02", b"[]", b"null", b'{"format":"other/1"}',
])
def test_malformed_bundle_never_verifies(payload, tmp_path):
    (tmp_path / "bundle.json").write_bytes(payload)
    res = L.verify_bundle(tmp_path)
    assert res["ok"] is False and res["verdict"] != "VERIFIED"


def test_missing_bundle_file(tmp_path):
    res = L.verify_bundle(tmp_path)
    assert res["ok"] is False and "missing" in " ".join(res["errors"]).lower()


def test_deleted_payload_is_caught(tmp_path):
    d = _bundle(SAFE, tmp_path)
    fp = L.bundle_fingerprint(d)
    (d / "preregistration.json").unlink()
    res = L.verify_bundle(d, fp)
    assert res["ok"] is False


# ---------------------------------------------------------------- OOD physics

@pytest.mark.parametrize("bad", [float("inf"), float("-inf")])
def test_non_finite_intensity_is_refused(bad, tmp_path):
    d = _bundle(SAFE, tmp_path)
    with pytest.raises(ValueError):
        _rewrite(d, lambda b: b["gate_certs"][0]["loci"].__setitem__("I_hi", [bad, bad]))


def test_nan_intensity_is_refused(tmp_path):
    d = _bundle(SAFE, tmp_path)
    with pytest.raises(ValueError):
        _rewrite(d, lambda b: b["gate_certs"][0]["loci"].__setitem__("I_hi", [float("nan")] * 2))


@pytest.mark.parametrize("loci,label", [
    ([(0.10, 0.11, 0.05)] * 3, "all safe"),
    ([(0.29, 0.31, 0.05)] * 3, "all straddling"),
    ([(0.50, 0.60, 0.05)] * 3, "all unsafe"),
])
def test_uniform_populations_do_not_crash(loci, label, tmp_path):
    d = _bundle(loci, tmp_path)
    res = L.verify_bundle(d, L.bundle_fingerprint(d))
    assert res["verdict"] in ("VERIFIED", "VERIFIED-VACUOUS")


def test_extreme_dose_and_threshold(tmp_path):
    for thr, dd in [(0.0, 0.0), (1.0, 0.0), (0.30, 1.0), (0.30, 2.0)]:
        d = Path(tempfile.mkdtemp())
        b = _bundle(SAFE, d, thr=thr, dd=dd)
        res = L.verify_bundle(b, L.bundle_fingerprint(b))
        assert res["ok"] is True, f"thr={thr} dd={dd}"


# ---------------------------------------------------------------- enormous

def test_large_locus_count(tmp_path):
    d = _bundle([(0.10, 0.11, 0.05)] * 20000, tmp_path)
    res = L.verify_bundle(d, L.bundle_fingerprint(d))
    assert res["ok"] is True and res["n_gated_loci"] == 20000


# ---------------------------------------------------------------- CLI

def _cli(args):
    return subprocess.run([sys.executable, "-m", "lcert_verify.cli", *args],
                          capture_output=True, text=True)


def test_cli_does_not_print_pass_without_an_anchor(tmp_path):
    d = _bundle(SAFE, tmp_path)
    r = _cli([str(d)])
    assert "VERDICT: PASS" not in r.stdout, "CLI printed PASS with no trust anchor"
    assert "UNVERIFIED" in r.stdout
    assert r.returncode != 0


def test_cli_states_the_missing_precondition(tmp_path):
    d = _bundle(SAFE, tmp_path)
    out = _cli([str(d)]).stdout
    assert "trust anchor" in out.lower() or "fingerprint" in out.lower()


def test_cli_passes_when_anchored(tmp_path):
    d = _bundle(SAFE, tmp_path)
    r = _cli([str(d), L.bundle_fingerprint(d)])
    assert r.returncode == 0 and "VERDICT: VERIFIED" in r.stdout


def test_cli_forgery_with_anchor_is_refuted(tmp_path):
    d = _bundle(SAFE, tmp_path)
    fp = L.bundle_fingerprint(d)
    _self_consistent_forgery(d)
    r = _cli([str(d), fp])
    assert r.returncode != 0 and "REFUTED" in r.stdout


def test_cli_exit_codes_are_distinct(tmp_path):
    d = _bundle(SAFE, tmp_path)
    assert _cli([str(d), L.bundle_fingerprint(d)]).returncode == 0
    assert _cli([str(d)]).returncode == 4                       # unanchored
    assert _cli([str(d), "ab" * 32]).returncode == 2            # integrity
    L.make_bundle(tmp_path / "empty", gate_certs=[], kpis=[], prereg={})
    assert _cli([str(tmp_path / "empty"),
                 L.bundle_fingerprint(tmp_path / "empty")]).returncode == 3   # vacuous
