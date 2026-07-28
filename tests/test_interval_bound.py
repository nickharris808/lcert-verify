"""LCERT-BOUND-1 — the domain-agnostic certificate kind.

This kind exists so the format is adoptable outside lithography: you supply
per-locus intervals for whatever quantity your analysis bounds, and the verifier
re-derives the admission verdict from them.

The line it must hold: claiming *more* margin than the numbers support is
rejected; claiming less is merely conservative and is allowed.
"""
from __future__ import annotations

import json

import pytest

import lcert_verify as L
from lcert_verify import _verifier as V


def _bundle(tmp_path, cert):
    L.make_bundle(tmp_path, interval_bound_certs=[cert], kpis=[], prereg={"t": 1})
    return tmp_path


def _rewrite(d, mutate):
    b = json.loads((d / "bundle.json").read_text())
    mutate(b)
    (d / "bundle.json").write_bytes(V._canon(b) + b"\n")
    return L.verify_bundle(d, L.bundle_fingerprint(d))


THERMAL = dict(quantity="junction temperature", unit="K", threshold=358.15,
               direction="below", loci=[(340.0, 351.2), (338.4, 349.9)])


# ---------------------------------------------------------------- the happy path

def test_a_safe_certificate_verifies(tmp_path):
    d = _bundle(tmp_path, L.interval_bound_cert("thermal", **THERMAL))
    res = L.verify_bundle(d, L.bundle_fingerprint(d))
    assert res["verdict"] == "VERIFIED"
    assert res["n_certificates"] == 1 and res["n_gated_loci"] == 2


def test_the_verdict_is_derived_not_supplied():
    c = L.interval_bound_cert("thermal", **THERMAL)
    assert c["recorded"] == {"admit": True, "n_violating": 0, "n_loci": 2,
                             "worst_margin": pytest.approx(6.95)}


def test_a_violating_locus_is_recorded_as_such():
    c = L.interval_bound_cert("t", quantity="q", unit="u", threshold=358.15,
                              direction="below", loci=[(340.0, 351.2), (359.0, 361.0)])
    assert c["recorded"]["admit"] is False and c["recorded"]["n_violating"] == 1


def test_the_above_direction_works_the_other_way():
    c = L.interval_bound_cert("yield", quantity="yield", unit="frac", threshold=0.85,
                              direction="above", loci=[(0.91, 0.94), (0.88, 0.90)])
    assert c["recorded"]["admit"] is True
    bad = L.interval_bound_cert("yield", quantity="yield", unit="frac", threshold=0.85,
                                direction="above", loci=[(0.80, 0.94)])
    assert bad["recorded"]["admit"] is False


def test_a_locus_exactly_on_the_threshold_is_violating():
    """Zero margin is not margin. The comparison is `<= 0`, deliberately."""
    c = L.interval_bound_cert("edge", quantity="q", unit="u", threshold=350.0,
                              direction="below", loci=[(340.0, 350.0)])
    assert c["recorded"]["admit"] is False


def test_zero_loci_does_not_admit(tmp_path):
    """Nothing was bounded, so nothing was earned."""
    c = L.interval_bound_cert("empty", quantity="q", unit="u", threshold=1.0,
                              direction="below", loci=[])
    assert c["recorded"]["admit"] is False
    d = _bundle(tmp_path, c)
    assert L.verify_bundle(d, L.bundle_fingerprint(d))["n_gated_loci"] == 0


# ---------------------------------------------------------------- the attacks

def test_overstating_the_margin_is_refuted(tmp_path):
    d = _bundle(tmp_path, L.interval_bound_cert("thermal", **THERMAL))
    res = _rewrite(d, lambda b: b["interval_bound_certs"][0]["recorded"].update(
        worst_margin=50.0))
    assert res["verdict"] == "REFUTED"
    assert any("E_MARGIN_OVERSTATED" in e for e in res["errors"])


def test_understating_the_margin_is_allowed(tmp_path):
    """Conservatism is not a lie. A producer may round its own claim down."""
    d = _bundle(tmp_path, L.interval_bound_cert("thermal", **THERMAL))
    res = _rewrite(d, lambda b: b["interval_bound_certs"][0]["recorded"].update(
        worst_margin=0.5))
    assert res["verdict"] == "VERIFIED"


def test_editing_a_locus_to_hide_a_violation_is_refuted(tmp_path):
    d = _bundle(tmp_path, L.interval_bound_cert("thermal", **THERMAL))
    res = _rewrite(d, lambda b: b["interval_bound_certs"][0]["loci"]["hi"].__setitem__(
        0, 400.0))
    assert res["verdict"] == "REFUTED"
    assert any("recorded admit" in e for e in res["errors"])


def test_a_flipped_admit_is_refuted(tmp_path):
    c = L.interval_bound_cert("t", quantity="q", unit="u", threshold=358.15,
                              direction="below", loci=[(359.0, 361.0)])
    d = _bundle(tmp_path, c)
    res = _rewrite(d, lambda b: b["interval_bound_certs"][0]["recorded"].update(
        admit=True, n_violating=0))
    assert res["verdict"] == "REFUTED"


@pytest.mark.parametrize("mutate,needle", [
    (lambda c: c.update(direction="sideways"), "direction must be"),
    (lambda c: c["loci"]["lo"].__setitem__(0, 999.0), "E_INVERTED_INTERVAL"),
    (lambda c: c["loci"]["lo"].pop(), "E_LOCUS_COUNT"),
    (lambda c: c.update(threshold="warm"), "malformed"),
    (lambda c: c["recorded"].update(worst_margin="lots"), "not a finite number"),
    (lambda c: c["recorded"].update(n_loci=99), "recorded n_loci"),
])
def test_malformed_or_dishonest_certificates_are_refuted(tmp_path, mutate, needle):
    d = _bundle(tmp_path, L.interval_bound_cert("thermal", **THERMAL))
    res = _rewrite(d, lambda b: mutate(b["interval_bound_certs"][0]))
    assert res["verdict"] == "REFUTED"
    assert any(needle in e for e in res["errors"]), res["errors"]


def test_the_producer_refuses_an_inverted_interval_at_source():
    with pytest.raises(ValueError, match="encloses nothing"):
        L.interval_bound_cert("x", quantity="q", unit="u", threshold=1.0,
                              direction="below", loci=[(2.0, 1.0)])


def test_the_producer_refuses_an_unknown_direction():
    with pytest.raises(ValueError, match="below.*above"):
        L.interval_bound_cert("x", quantity="q", unit="u", threshold=1.0,
                              direction="whichever", loci=[(0.0, 1.0)])


# ---------------------------------------------------------------- the boundary

def test_the_certificate_kind_computes_no_physics():
    """The moat boundary, as a test rather than a promise.

    This kind is arithmetic over numbers the producer supplies. If it ever grew a
    physical model — an imaging kernel, a solver, a fitted coefficient — it would
    stop being a thing anyone can check without trusting us.
    """
    import inspect
    src = inspect.getsource(V.verify_interval_bound_certs)
    for forbidden in ("erfc", "exp", "sqrt", "fft", "kernel", "convolve",
                      "numpy", "scipy"):
        assert forbidden not in src.lower(), (
            f"the domain-agnostic checker mentions {forbidden!r}; it is supposed "
            f"to re-derive a comparison, not model anything")


def test_it_travels_with_the_other_kinds(tmp_path):
    """A bundle may mix kinds; all of them are counted and all are checked."""
    gate = L.gate_cert("litho", budget=0.05, safety=1.5, n_photons=100.0,
                       thr=0.30, delta_dose=0.02, loci=[(0.10, 0.11, 0.05)])
    bound = L.interval_bound_cert("thermal", **THERMAL)
    L.make_bundle(tmp_path, gate_certs=[gate], interval_bound_certs=[bound],
                  kpis=[], prereg={})
    res = L.verify_bundle(tmp_path, L.bundle_fingerprint(tmp_path))
    assert res["verdict"] == "VERIFIED"
    assert res["n_certificates"] == 2 and res["n_gated_loci"] == 3


def test_an_unanchored_bound_certificate_still_abstains(tmp_path):
    d = _bundle(tmp_path, L.interval_bound_cert("thermal", **THERMAL))
    assert L.verify_bundle(d)["verdict"] == "UNVERIFIED"
