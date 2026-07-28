"""`--diff` and `--format html`.

A diff reports movement between two artifacts; it is never a verdict. The HTML
report must not let colour carry meaning, and must not render an abstention as a
pass.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys

import pytest

import lcert_verify as L
from lcert_verify.diff import IMPROVED, REGRESSED, UNCHANGED, diff_bundles, format_diff
from lcert_verify.html import to_html


def _bundle(d, hi, extra=None, gate=False):
    certs = [L.interval_bound_cert("thermal", quantity="T", unit="K",
                                   threshold=358.15, direction="below",
                                   loci=[(340.0, hi)])]
    if extra is not None:
        certs.append(extra)
    gates = [L.gate_cert("litho", budget=0.05, safety=1.5, n_photons=100.0,
                         thr=0.30, delta_dose=0.02,
                         loci=[(0.10, 0.11, 0.05), (0.29, 0.31, 0.05)])] if gate else []
    L.make_bundle(d, gate_certs=gates, interval_bound_certs=certs, kpis=[], prereg={})
    return d, L.bundle_fingerprint(d)


# ---------------------------------------------------------------- diff

def test_a_wider_margin_is_an_improvement(tmp_path):
    a, fa = _bundle(tmp_path / "a", 351.2)
    b, fb = _bundle(tmp_path / "b", 344.0)
    d = diff_bundles(a, b, anchor_a=fa, anchor_b=fb)
    assert d["n_improved"] == 1 and d["n_regressed"] == 0
    assert d["rows"][0]["change"] == IMPROVED


def test_losing_admission_is_a_regression_however_the_numbers_moved(tmp_path):
    a, fa = _bundle(tmp_path / "a", 351.2)
    b, fb = _bundle(tmp_path / "b", 400.0)
    d = diff_bundles(a, b, anchor_a=fa, anchor_b=fb)
    assert d["n_regressed"] == 1 and d["rows"][0]["change"] == REGRESSED


def test_an_identical_bundle_says_so(tmp_path):
    a, fa = _bundle(tmp_path / "a", 351.2)
    d = diff_bundles(a, a, anchor_a=fa, anchor_b=fa)
    assert d["identical"] and "byte-identical" in format_diff(d)


def test_added_and_removed_certificates_are_counted(tmp_path):
    extra = L.interval_bound_cert("emi", quantity="E", unit="dB", threshold=40.0,
                                  direction="below", loci=[(10.0, 30.0)])
    a, fa = _bundle(tmp_path / "a", 351.2)
    b, fb = _bundle(tmp_path / "b", 351.2, extra=extra)
    fwd = diff_bundles(a, b, anchor_a=fa, anchor_b=fb)
    assert fwd["n_added"] == 1 and fwd["n_removed"] == 0
    back = diff_bundles(b, a, anchor_a=fb, anchor_b=fa)
    assert back["n_removed"] == 1 and back["n_regressed"] == 1, (
        "dropping a certificate is a regression, not a neutral change")


def test_an_unchanged_certificate_is_not_reported_as_movement(tmp_path):
    a, fa = _bundle(tmp_path / "a", 351.2, gate=True)
    b, fb = _bundle(tmp_path / "b", 351.2, gate=True)
    d = diff_bundles(a, b, anchor_a=fa, anchor_b=fb)
    assert all(r["change"] == UNCHANGED for r in d["rows"])


def test_an_unverifiable_side_is_flagged_not_silently_compared(tmp_path):
    a, fa = _bundle(tmp_path / "a", 351.2)
    b, _ = _bundle(tmp_path / "b", 344.0)
    d = diff_bundles(a, b, anchor_a=fa)          # b unanchored
    assert d["comparable"] is False
    assert "did not verify" in d["caveat"]
    assert "NOTE:" in format_diff(d)


def test_diff_exits_non_zero_only_on_a_regression(tmp_path):
    a, fa = _bundle(tmp_path / "a", 351.2)
    b, fb = _bundle(tmp_path / "b", 344.0)
    c, fc = _bundle(tmp_path / "c", 400.0)

    def run(x, fx):
        return subprocess.run(
            [sys.executable, "-m", "lcert_verify.cli", str(a), fa,
             "--diff", str(x), "--diff-anchor", fx],
            capture_output=True, text=True)

    assert run(b, fb).returncode == 0
    assert run(c, fc).returncode == 1


def test_a_missing_bundle_does_not_crash_the_diff(tmp_path):
    a, fa = _bundle(tmp_path / "a", 351.2)
    d = diff_bundles(a, tmp_path / "nope", anchor_a=fa)
    assert d["comparable"] is False


# ---------------------------------------------------------------- html

@pytest.fixture
def report(tmp_path):
    a, fa = _bundle(tmp_path / "a", 359.0, gate=True)
    res = L.verify_bundle(a, fa)
    return to_html(res, json.loads((a / "bundle.json").read_text()), source="demo"), res


def test_the_report_is_self_contained(report):
    html, _ = report
    assert html.startswith("<!doctype html>")
    for external in ("http://", "https://", "<script", "src=", "@import"):
        assert external not in html, f"report reaches for {external}"


def test_colour_never_carries_the_meaning_alone(report):
    """Green and red collapse under deuteranopia, so every state is said 3 more ways."""
    html, _ = report
    assert "<table" in html, "no table view"
    assert "url(#crit-" in html, "no texture fill on the failing bars"
    assert "unsafe" in html, "no direct textual label"
    assert "<title>" in html, "no per-bar accessible name"


def test_both_themes_are_defined(report):
    html, _ = report
    assert 'prefers-color-scheme: dark' in html
    assert ':root[data-theme="dark"]' in html, "a theme toggle must beat the OS setting"


def test_bars_stay_inside_the_viewbox(report):
    html, _ = report
    found = 0
    for m in re.finditer(r'class="mark" x="([-\d.]+)"[^>]*width="([\d.]+)"', html):
        x, w = float(m.group(1)), float(m.group(2))
        assert 0 <= x and x + w <= 620, f"bar overflows: x={x} w={w}"
        found += 1
    assert found > 0, "no bars were drawn"


def test_axis_labels_do_not_collide(report):
    """Three labels share the bottom row; they must be anchored apart."""
    html, _ = report
    anchors = re.findall(
        r'<text x="([-\d.]+)" y="\d+" font-size="11" fill="var\(--muted\)" '
        r'text-anchor="(\w+)"', html)
    assert any(b == "start" and float(a) < 10 for a, b in anchors)
    assert any(b == "end" and float(a) > 600 for a, b in anchors)


def test_an_abstention_is_not_rendered_as_a_pass(tmp_path):
    a, _ = _bundle(tmp_path / "a", 344.0)
    res = L.verify_bundle(a)                       # no anchor
    html = to_html(res, json.loads((a / "bundle.json").read_text()))
    assert "UNVERIFIED" in html
    assert "var(--warning)" in html, "an abstention must not wear the pass colour"
    assert "var(--good)" not in html.split("</span>")[0]


def test_a_bundle_with_no_certificates_says_so(tmp_path):
    L.make_bundle(tmp_path, gate_certs=[], kpis=[], prereg={})
    res = L.verify_bundle(tmp_path, L.bundle_fingerprint(tmp_path))
    html = to_html(res, json.loads((tmp_path / "bundle.json").read_text()))
    assert "nothing to chart" in html


def test_the_chart_agrees_with_the_verdict_it_sits_beside(tmp_path):
    """The chart defers to `explain`, so it cannot contradict the verdict."""
    from lcert_verify.explain import explain_certificate
    from lcert_verify.html import _loci
    cert = L.gate_cert("g", budget=0.05, safety=1.5, n_photons=100.0, thr=0.30,
                       delta_dose=0.02,
                       loci=[(0.10, 0.11, 0.05), (0.29, 0.31, 0.05),
                             (0.298, 0.302, 0.05)])
    rows, _, _ = _loci(cert)
    expected = [r["class"] for r in explain_certificate(cert, limit=10 ** 9)["rows"]]
    assert [r["cls"] for r in rows] == expected


def test_html_escaping(tmp_path):
    cert = L.interval_bound_cert("<script>x</script>", quantity="q&q", unit="u",
                                 threshold=1.0, direction="below", loci=[(0.0, 0.5)])
    L.make_bundle(tmp_path, interval_bound_certs=[cert], kpis=[], prereg={})
    res = L.verify_bundle(tmp_path, L.bundle_fingerprint(tmp_path))
    html = to_html(res, json.loads((tmp_path / "bundle.json").read_text()))
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


def test_cli_writes_an_html_file(tmp_path):
    a, fa = _bundle(tmp_path / "a", 344.0)
    out = tmp_path / "r.html"
    r = subprocess.run([sys.executable, "-m", "lcert_verify.cli", str(a), fa,
                        "--format", "html", "-o", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert out.read_text().startswith("<!doctype html>")
