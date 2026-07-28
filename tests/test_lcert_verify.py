"""Conformance + tamper battery for lcert-verify.

Every test builds a real bundle with the reference builder and runs the real
verifier over it.  The tamper tests are the load-bearing ones: a verifier that
accepts everything passes the happy path too.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


import lcert_verify as L

# A locus is (I_lo, I_hi, ae0).  Sub-threshold loci with a comfortable margin certify;
# loci straddling the threshold do not.
SAFE_LOCI = [(0.10, 0.11, 0.05), (0.09, 0.10, 0.04), (0.12, 0.13, 0.06)]
UNSAFE_LOCI = [(0.10, 0.11, 0.05), (0.29, 0.31, 0.05)]

PREREG = {"criterion": "worst-locus survival", "budget": 0.05, "declared": "before measurement"}


def _bundle(tmp_path: Path, loci=SAFE_LOCI, name="clip_a"):
    cert = L.gate_cert(name, budget=0.05, safety=1.5, n_photons=100.0,
                       thr=0.30, delta_dose=0.02, loci=loci)
    L.make_bundle(tmp_path, gate_certs=[cert],
                  kpis=[{"key": "worst_pfail_upper", "value": 0.0041}],
                  prereg=PREREG, seed=149)
    return tmp_path


def test_roundtrip_verifies(tmp_path):
    d = _bundle(tmp_path)
    res = L.verify_bundle(d)
    assert res["ok"] is True, res["errors"]
    assert res["errors"] == []


def test_verdict_is_rederived_not_trusted(tmp_path):
    """The verifier recomputes the verdict; it must reject a forged one."""
    d = _bundle(tmp_path)
    b = json.loads((d / "bundle.json").read_text())
    assert b["gate_certs"][0]["recorded"]["interval_admit"] is True
    b["gate_certs"][0]["recorded"]["interval_admit"] = False
    (d / "bundle.json").write_bytes(json.dumps(b).encode())
    res = L.verify_bundle(d)
    assert res["ok"] is False
    assert any("interval_admit" in e for e in res["errors"])


def test_unsafe_loci_do_not_admit(tmp_path):
    """A locus straddling the threshold must not produce an affirmative verdict."""
    cert = L.gate_cert("clip_bad", budget=0.05, safety=1.5, n_photons=100.0,
                       thr=0.30, delta_dose=0.02, loci=UNSAFE_LOCI)
    assert cert["recorded"]["interval_admit"] is False
    L.make_bundle(tmp_path, gate_certs=[cert], kpis=[], prereg=PREREG)
    assert L.verify_bundle(tmp_path)["ok"] is True  # honestly recorded REJECT still verifies


def test_tamper_kappa_rejected(tmp_path):
    d = _bundle(tmp_path)
    b = json.loads((d / "bundle.json").read_text())
    b["gate_certs"][0]["kappa"] = b["gate_certs"][0]["kappa"] * 1.01
    (d / "bundle.json").write_bytes(json.dumps(b).encode())
    res = L.verify_bundle(d)
    assert res["ok"] is False
    assert any("kappa" in e or "K does not recompute" in e for e in res["errors"])


def test_tamper_K_rejected(tmp_path):
    d = _bundle(tmp_path)
    b = json.loads((d / "bundle.json").read_text())
    b["gate_certs"][0]["K"] = b["gate_certs"][0]["K"] * (1.0 + 1e-9)
    (d / "bundle.json").write_bytes(json.dumps(b).encode())
    res = L.verify_bundle(d)
    assert res["ok"] is False


def test_tamper_payload_breaks_manifest(tmp_path):
    d = _bundle(tmp_path)
    (d / "preregistration.json").write_bytes(b'{"criterion": "moved the goalposts"}\n')
    res = L.verify_bundle(d)
    assert res["ok"] is False
    assert any("manifest" in e.lower() or "sha256" in e.lower() for e in res["errors"])


def test_tamper_merkle_root_rejected(tmp_path):
    d = _bundle(tmp_path)
    b = json.loads((d / "bundle.json").read_text())
    b["merkle_root"] = "00" * 32
    (d / "bundle.json").write_bytes(json.dumps(b).encode())
    res = L.verify_bundle(d)
    assert res["ok"] is False
    assert any("root" in e.lower() for e in res["errors"])


def test_tamper_kpi_breaks_outputs_commitment(tmp_path):
    d = _bundle(tmp_path)
    b = json.loads((d / "bundle.json").read_text())
    b["kpis"] = [{"key": "worst_pfail_upper", "value": 0.0000001}]
    (d / "bundle.json").write_bytes(json.dumps(b).encode())
    res = L.verify_bundle(d)
    assert res["ok"] is False
    assert any("commitment" in e.lower() for e in res["errors"])


def test_expected_fingerprint_enforced(tmp_path):
    d = _bundle(tmp_path)
    good = L.bundle_fingerprint(d)
    assert L.verify_bundle(d, good)["ok"] is True
    assert L.verify_bundle(d, "de" * 32)["ok"] is False


def test_kappa_roundtrip_precision():
    """kappa_for_budget must land inside the tolerance the verifier enforces."""
    import math
    for budget in (0.05, 0.01, 0.001, 1e-6):
        k = L.kappa_for_budget(budget)
        assert abs(0.5 * math.erfc(k) - budget) < 1e-12
        assert L.check_kappa_K(budget, 1.5, 100.0, k,
                               2.0 * k * k * 1.5 * 1.5 / 100.0) == []


def test_empty_loci_is_trivially_admit():
    cert = L.gate_cert("empty", budget=0.05, safety=1.5, n_photons=100.0,
                       thr=0.30, delta_dose=0.0, loci=[])
    assert cert["recorded"]["interval_admit"] is True
    assert cert["recorded"]["n_loci"] == 0


def test_runs_isolated_with_no_site_packages(tmp_path):
    """The headline property: verifies under `python -I -S`, no third-party imports."""
    d = _bundle(tmp_path)
    standalone = Path(L.__file__).parent / "_verifier.py"
    out = subprocess.run([sys.executable, "-I", "-S", str(standalone), str(d)],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr


def test_isolated_run_fails_on_tamper(tmp_path):
    d = _bundle(tmp_path)
    b = json.loads((d / "bundle.json").read_text())
    b["gate_certs"][0]["recorded"]["interval_admit"] = False
    (d / "bundle.json").write_bytes(json.dumps(b).encode())
    standalone = Path(L.__file__).parent / "_verifier.py"
    out = subprocess.run([sys.executable, "-I", "-S", str(standalone), str(d)],
                         capture_output=True, text=True)
    assert out.returncode == 1


def test_scope_is_published():
    """The package must state what it does NOT check."""
    assert "physics" in L.SCOPE.lower() or "not" in L.SCOPE.lower()
    assert len(L.SCOPE) > 100


# ---------- installed entry point ----------
# These exist because the console script shipped broken once: the wrapper stripped
# argv[0], which the frozen verifier's main() expects. Unit tests on the library
# could not see it.

def test_cli_wrapper_verifies_a_good_bundle(tmp_path, capsys):
    from lcert_verify.cli import main as cli_main
    d = _bundle(tmp_path)
    assert cli_main([str(d)]) == 0
    assert "VERDICT: PASS" in capsys.readouterr().out


def test_cli_wrapper_rejects_a_tampered_bundle(tmp_path, capsys):
    from lcert_verify.cli import main as cli_main
    from lcert_verify import _verifier as V
    d = _bundle(tmp_path)
    b = json.loads((d / "bundle.json").read_text())
    b["gate_certs"][0]["recorded"]["interval_admit"] = False
    (d / "bundle.json").write_bytes(V._canon(b) + b"\n")
    assert cli_main([str(d)]) == 1
    assert "VERDICT: FAIL" in capsys.readouterr().out


def test_cli_wrapper_accepts_expected_fingerprint(tmp_path):
    from lcert_verify.cli import main as cli_main
    d = _bundle(tmp_path)
    assert cli_main([str(d), L.bundle_fingerprint(d)]) == 0
    assert cli_main([str(d), "ab" * 32]) == 1


def test_cli_wrapper_scope_flag(tmp_path, capsys):
    from lcert_verify.cli import main as cli_main
    assert cli_main(["--scope"]) == 0
    assert len(capsys.readouterr().out) > 100


def test_cli_wrapper_no_args_is_usage(tmp_path):
    from lcert_verify.cli import main as cli_main
    assert cli_main([]) == 1


def test_console_script_end_to_end(tmp_path):
    """Run the installed entry point exactly as a shell user would."""
    d = _bundle(tmp_path)
    r = subprocess.run([sys.executable, "-m", "lcert_verify.cli", str(d)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "VERDICT: PASS" in r.stdout


# ---------- vacuity guard ----------
# An adversarial pass found that stripping every certificate from a bundle left it
# trivially consistent, so the format check reported success — which a reader would
# read as "something was certified". These pin the fix.

def test_empty_bundle_is_refused_by_default(tmp_path):
    L.make_bundle(tmp_path, gate_certs=[], kpis=[], prereg={"x": 1})
    res = L.verify_bundle(tmp_path)
    assert res["ok"] is False
    assert res["n_certificates"] == 0
    assert any("no certificates" in e for e in res["errors"])


def test_empty_bundle_allowed_when_explicitly_requested(tmp_path):
    L.make_bundle(tmp_path, gate_certs=[], kpis=[], prereg={"x": 1})
    assert L.verify_bundle(tmp_path, require_certs=False)["ok"] is True


def test_stripping_certificates_is_caught(tmp_path):
    """The original attack: delete the certificates from a good bundle."""
    from lcert_verify import _verifier as V
    d = _bundle(tmp_path)
    assert L.verify_bundle(d)["ok"] is True
    b = json.loads((d / "bundle.json").read_text())
    b["gate_certs"] = []
    (d / "bundle.json").write_bytes(V._canon(b) + b"\n")
    assert L.verify_bundle(d)["ok"] is False


def test_certificate_count_is_reported(tmp_path):
    d = _bundle(tmp_path)
    assert L.verify_bundle(d)["n_certificates"] == 1


def test_cli_reports_count_and_refuses_empty(tmp_path, capsys):
    from lcert_verify.cli import main as cli_main
    L.make_bundle(tmp_path, gate_certs=[], kpis=[], prereg={})
    assert cli_main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "certificates checked: 0" in out and "VERDICT: FAIL" in out
    assert cli_main([str(tmp_path), "--allow-empty"]) == 0


def test_package_exposes_version_and_all():
    """Regression: an earlier edit truncated __init__.py and silently dropped both."""
    assert L.__version__ == "1.0.0"
    assert "verify_bundle" in L.__all__
    for name in L.__all__:
        assert hasattr(L, name), f"__all__ advertises {name} but it is not exported"
