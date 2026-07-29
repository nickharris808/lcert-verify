"""Streaming verification must give exactly the ordinary path's answer.

A faster or smaller answer that is a different answer is not an improvement. Every
test here compares the two paths on the same bytes and asserts the whole result,
not the headline.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

import lcert_verify as L
from lcert_verify import _verifier as V
from lcert_verify.stream import ScanError, fingerprint, verify_bundle_streaming, walk

COMPARED = ("ok", "verdict", "errors", "fingerprint", "n_certificates",
            "n_gated_loci", "trust_anchor", "internally_consistent")


def _both(d, anchor="", **kw):
    return L.verify_bundle(d, anchor, **kw), verify_bundle_streaming(d, anchor, **kw)


def _assert_agree(a, b, label=""):
    for k in COMPARED:
        assert a[k] == b[k], f"{label}: {k} differs — ordinary {a[k]!r}, streaming {b[k]!r}"


def _bundle(tmp_path, n_certs=1, n_loci=3, kinds=("gate",)):
    gates, bounds = [], []
    for c in range(n_certs):
        if "gate" in kinds:
            gates.append(L.gate_cert(
                f"g{c}", budget=0.05, safety=1.5, n_photons=100.0, thr=0.30,
                delta_dose=0.02,
                loci=[(0.10 + i * 1e-4, 0.11 + i * 1e-4, 0.05) for i in range(n_loci)]))
        if "bound" in kinds:
            bounds.append(L.interval_bound_cert(
                f"b{c}", quantity="q", unit="K", threshold=358.15, direction="below",
                loci=[(340.0, 351.2 + i * 1e-3) for i in range(n_loci)]))
    L.make_bundle(tmp_path, gate_certs=gates, interval_bound_certs=bounds,
                  kpis=[{"key": "n", "value": n_certs}], prereg={"declared": True})
    return tmp_path, L.bundle_fingerprint(tmp_path)


# ---------------------------------------------------------------- agreement

@pytest.mark.parametrize("n_certs,n_loci,kinds", [
    (1, 3, ("gate",)),
    (5, 4, ("gate",)),
    (3, 2, ("bound",)),
    (4, 3, ("gate", "bound")),
    (1, 1, ("gate", "bound")),
])
def test_streaming_agrees_with_the_ordinary_path(tmp_path, n_certs, n_loci, kinds):
    d, fp = _bundle(tmp_path, n_certs, n_loci, kinds)
    _assert_agree(*_both(d, fp), label=f"{n_certs}x{n_loci}{kinds}")


def test_they_agree_when_abstaining(tmp_path):
    d, _ = _bundle(tmp_path)
    a, b = _both(d)                       # no anchor
    _assert_agree(a, b)
    assert a["verdict"] == "UNVERIFIED"


def test_they_agree_when_the_anchor_is_wrong(tmp_path):
    d, _ = _bundle(tmp_path)
    a, b = _both(d, "ab" * 32)
    _assert_agree(a, b)
    assert a["verdict"] == "REFUTED"


def test_they_agree_on_a_vacuous_bundle(tmp_path):
    L.make_bundle(tmp_path, gate_certs=[], kpis=[], prereg={})
    fp = L.bundle_fingerprint(tmp_path)
    a, b = _both(tmp_path, fp)
    _assert_agree(a, b)
    assert a["verdict"] == "VACUOUS"


def test_they_agree_when_the_anchor_is_deliberately_waived(tmp_path):
    d, _ = _bundle(tmp_path)
    a, b = _both(d, require_anchor=False)
    _assert_agree(a, b)
    assert a["verdict"] == "INTERNALLY-CONSISTENT"


def test_they_agree_on_a_missing_bundle(tmp_path):
    _assert_agree(*_both(tmp_path / "nope"))


# ---------------------------------------------------------------- forgeries

@pytest.mark.parametrize("mutate,label", [
    (lambda b: b["gate_certs"][0]["recorded"].update(interval_admit=False), "flipped admit"),
    (lambda b: b["gate_certs"][0]["loci"]["I_hi"].__setitem__(0, 9.0), "edited intensity"),
    (lambda b: b["gate_certs"][0].update(n_photons=1e9), "inflated photons"),
    (lambda b: b.update(merkle_root="0" * 64), "broken root"),
    (lambda b: b["manifest"].update({"gone.json": "0" * 64}), "manifest lists a missing file"),
    (lambda b: b["kpis"].append({"key": "sneaked", "value": 1}), "kpi added after commitment"),
])
def test_streaming_catches_the_same_forgeries(tmp_path, mutate, label):
    d, _ = _bundle(tmp_path, n_certs=2)
    b = json.loads((d / "bundle.json").read_text())
    mutate(b)
    (d / "bundle.json").write_bytes(V._canon(b) + b"\n")
    fp = L.bundle_fingerprint(d)
    a, s = _both(d, fp)
    _assert_agree(a, s, label=label)
    assert a["verdict"] == "REFUTED", label


def test_streaming_catches_a_forgery_in_the_last_certificate(tmp_path):
    """Streaming stops holding earlier certificates; it must still check later ones."""
    d, _ = _bundle(tmp_path, n_certs=6)
    b = json.loads((d / "bundle.json").read_text())
    b["gate_certs"][-1]["recorded"]["interval_admit"] = False
    (d / "bundle.json").write_bytes(V._canon(b) + b"\n")
    fp = L.bundle_fingerprint(d)
    a, s = _both(d, fp)
    _assert_agree(a, s)
    assert s["verdict"] == "REFUTED"


# ---------------------------------------------------------------- malformed input

@pytest.mark.parametrize("raw", [
    b"", b"not json", b"[1,2,3]", b'"a string"', b"{", b'{"format":}',
    b'{"format" "litho-cert"}', b'{"gate_certs": [', b'{"gate_certs": {}}',
    b"\x00\x01\x02", b'{"format": "litho-cert-bundle/1", "gate_certs": [}]}',
])
def test_malformed_documents_are_rejected_by_both_paths(tmp_path, raw):
    (tmp_path / "bundle.json").write_bytes(raw)
    fp = fingerprint(tmp_path / "bundle.json")
    a, b = _both(tmp_path, fp)
    assert a["ok"] is False and b["ok"] is False
    assert b["verdict"] in ("REFUTED", "VACUOUS"), b["verdict"]


def test_a_hostile_document_does_not_hang_or_explode(tmp_path):
    """Deep nesting must be refused, not recursed into."""
    (tmp_path / "bundle.json").write_bytes(b'{"a": ' + b"[" * 5000 + b"]" * 5000 + b"}")
    r = verify_bundle_streaming(tmp_path, fingerprint(tmp_path / "bundle.json"))
    assert r["ok"] is False


# ---------------------------------------------------------------- the walker

def test_the_walker_streams_certificates_and_keeps_the_rest():
    seen = []
    head = walk('{"format": "x", "gate_certs": [{"n": 1}, {"n": 2}], "kpis": []}',
                lambda k, c: seen.append((k, c)))
    assert head == {"format": "x", "kpis": []}
    assert seen == [("gate_certs", {"n": 1}), ("gate_certs", {"n": 2})]


def test_an_empty_certificate_array_is_fine():
    assert walk('{"gate_certs": [], "format": "x"}', lambda k, c: None) == {"format": "x"}


@pytest.mark.parametrize("text,msg", [
    ("[1]", "must be a JSON object"),
    ('{"gate_certs": 5}', "must be an array"),
    ('{"a" 1}', "expected ':'"),
    ("{", "unterminated"),
    ('{"gate_certs": [', "unterminated"),
    ("{1: 2}", "expected a key"),
])
def test_the_walker_refuses_rather_than_guessing(text, msg):
    with pytest.raises((ScanError, ValueError), match=msg):
        walk(text, lambda k, c: None)


def test_whitespace_and_key_order_do_not_matter():
    a = walk('{"format":"x","gate_certs":[{"n":1}]}', lambda k, c: None)
    b = walk('  {\n  "gate_certs" : [ { "n" : 1 } ] ,\n  "format" : "x"\n}\n',
             lambda k, c: None)
    assert a == b


def test_strings_containing_braces_do_not_confuse_the_walker():
    seen = []
    head = walk('{"note": "a } b ] c \\" d", "gate_certs": [{"name": "x}]"}]}',
                lambda k, c: seen.append(c))
    assert head["note"] == 'a } b ] c " d'
    assert seen == [{"name": "x}]"}]


# ---------------------------------------------------------------- fingerprint

def test_chunked_fingerprint_matches_the_ordinary_one(tmp_path):
    d, fp = _bundle(tmp_path, n_certs=3, n_loci=50)
    assert fingerprint(d / "bundle.json") == fp
    assert fingerprint(d / "bundle.json") == L.bundle_fingerprint(d)


def test_progress_is_reported_per_certificate(tmp_path):
    d, fp = _bundle(tmp_path, n_certs=4)
    seen = []
    verify_bundle_streaming(d, fp, progress=seen.append)
    assert seen == [1, 2, 3, 4]


def test_the_result_says_which_path_produced_it(tmp_path):
    d, fp = _bundle(tmp_path)
    assert verify_bundle_streaming(d, fp)["streaming"] is True
    assert "streaming" not in L.verify_bundle(d, fp)


# ---------------------------------------------------------------- CLI

def test_cli_stream_flag_agrees_with_the_default(tmp_path):
    d, fp = _bundle(tmp_path, n_certs=3)

    def run(*extra):
        return subprocess.run([sys.executable, "-m", "lcert_verify.cli", str(d), fp,
                               "--format", "json", *extra],
                              capture_output=True, text=True)

    a, b = run(), run("--stream")
    assert a.returncode == b.returncode == 0
    ja, jb = json.loads(a.stdout), json.loads(b.stdout)
    for k in ("verdict", "ok", "errors"):
        assert ja[k] == jb[k]


def test_cli_stream_still_abstains_without_an_anchor(tmp_path):
    d, _ = _bundle(tmp_path)
    r = subprocess.run([sys.executable, "-m", "lcert_verify.cli", str(d), "--stream"],
                       capture_output=True, text=True)
    assert r.returncode == 4 and "UNVERIFIED" in r.stdout
