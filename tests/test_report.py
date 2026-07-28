"""Emitter tests.

The load-bearing property across every format: an abstention (`UNVERIFIED`) must
never render as a pass. A format with only pass/fail must report it as a failure.
"""
from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

import lcert_verify as L
from lcert_verify.report import EMITTERS, emit, to_json, to_junit, to_jsonl, to_sarif

SAFE = [(0.10, 0.11, 0.05), (0.09, 0.10, 0.04)]


def _bundle(tmp, loci=SAFE):
    c = L.gate_cert("clip", budget=0.05, safety=1.5, n_photons=100.0,
                    thr=0.30, delta_dose=0.02, loci=loci)
    L.make_bundle(tmp, gate_certs=[c], kpis=[], prereg={"a": 1})
    return Path(tmp)


def _res(tmp, anchored=True):
    d = _bundle(tmp)
    return L.verify_bundle(d, L.bundle_fingerprint(d) if anchored else "")


# ---------------------------------------------------------------- shape

def test_every_emitter_produces_parseable_output(tmp_path):
    res = _res(tmp_path)
    json.loads(to_json(res))
    for line in to_jsonl(res).splitlines():
        json.loads(line)
    json.loads(to_sarif(res))
    ET.fromstring(to_junit(res))


def test_sarif_is_valid_2_1_0(tmp_path):
    s = json.loads(to_sarif(_res(tmp_path)))
    assert s["version"] == "2.1.0"
    assert s["runs"][0]["tool"]["driver"]["name"] == "lcert-verify"
    assert s["runs"][0]["tool"]["driver"]["rules"]


def test_junit_is_wellformed(tmp_path):
    root = ET.fromstring(to_junit(_res(tmp_path)))
    assert root.tag == "testsuite" and root.get("tests") == "1"


# ---------------------------------------------------------------- the discipline

def test_abstention_is_never_a_pass_in_any_format(tmp_path):
    """The property this module exists to guarantee."""
    res = _res(tmp_path, anchored=False)
    assert res["verdict"] == "UNVERIFIED"

    sarif = json.loads(to_sarif(res))
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert sarif["runs"][0]["results"], "SARIF suppressed the abstention entirely"

    junit = ET.fromstring(to_junit(res))
    assert junit.get("failures") == "1"
    assert junit.find(".//failure") is not None

    rows = [json.loads(x) for x in to_jsonl(res).splitlines()]
    assert rows[0]["ok"] is False and rows[0]["level"] == "warning"


def test_abstention_states_the_reason_not_just_the_status(tmp_path):
    res = _res(tmp_path, anchored=False)
    for fmt in ("sarif", "junit", "jsonl"):
        out = emit(res, fmt, source="b.json")
        assert "anchor" in out.lower(), f"{fmt} omitted the reason"


def test_refuted_is_error_level_abstention_is_warning(tmp_path):
    from lcert_verify.report import verdict_meta
    assert verdict_meta("REFUTED")[1] == "error"
    assert verdict_meta("UNVERIFIED")[1] == "warning"
    assert verdict_meta("VERIFIED")[0] is True
    assert verdict_meta("VERIFIED-VACUOUS")[0] is True


def test_vacuous_is_not_a_pass(tmp_path):
    L.make_bundle(tmp_path, gate_certs=[], kpis=[], prereg={})
    res = L.verify_bundle(tmp_path, L.bundle_fingerprint(tmp_path))
    assert json.loads(to_sarif(res))["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert ET.fromstring(to_junit(res)).get("failures") == "1"


def test_unknown_verdict_defaults_to_failure():
    """An unrecognised verdict must never be optimistically treated as success."""
    from lcert_verify.report import verdict_meta
    ok, level, _ = verdict_meta("SOMETHING_NEW")
    assert ok is False and level == "error"


# ---------------------------------------------------------------- CLI

def _cli(args):
    return subprocess.run([sys.executable, "-m", "lcert_verify.cli", *args],
                          capture_output=True, text=True)


@pytest.mark.parametrize("fmt", sorted(EMITTERS))
def test_cli_emits_each_format(fmt, tmp_path):
    d = _bundle(tmp_path)
    r = _cli([str(d), L.bundle_fingerprint(d), "--format", fmt])
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip()


def test_cli_writes_to_a_file(tmp_path):
    d = _bundle(tmp_path)
    out = tmp_path / "r.sarif"
    r = _cli([str(d), L.bundle_fingerprint(d), "--format", "sarif", "-o", str(out)])
    assert r.returncode == 0
    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_cli_format_preserves_exit_code_taxonomy(tmp_path):
    d = _bundle(tmp_path)
    assert _cli([str(d), "--format", "sarif"]).returncode == 4          # unanchored
    assert _cli([str(d), L.bundle_fingerprint(d), "--format", "sarif"]).returncode == 0


def test_unknown_format_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown format"):
        emit(_res(tmp_path), "yaml")
