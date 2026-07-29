"""The adversarial suite: malformed, empty, enormous, out-of-distribution, differential.

The oracle throughout: **no input may produce a confident-looking answer that is
wrong.** A verdict of REFUTED or UNVERIFIED on a strange input is fine. A crash is
not, because it tells the caller nothing. A pass is a defect.

Particular attention to the surfaces added most recently — streaming, the export
formats, the diff, the HTML report and the HTTP service — because those have the
least field exposure.
"""
from __future__ import annotations

import io
import json
import math
import threading
import urllib.error
import urllib.request
import zipfile
from xml.etree import ElementTree as ET

import pytest

import lcert_verify as L
from lcert_verify import _verifier as V
from lcert_verify.diff import diff_bundles
from lcert_verify.html import to_html
from lcert_verify.report import EMITTERS, emit, verdict_meta
from lcert_verify.serve import make_server, status_for
from lcert_verify.stream import fingerprint, verify_bundle_streaming, walk

#: Verdicts meaning "the check was made and it stood". Everything else must be
#: rendered as a non-success by every surface, in every format.
SUCCESS = {"VERIFIED", "VERIFIED-VACUOUS", "INTERNALLY-CONSISTENT"}
ALL_VERDICTS = SUCCESS | {"UNVERIFIED", "VACUOUS", "REFUTED"}

ZWSP = "​"


def _bundle(d, n_certs=2, n_loci=3, kinds=("gate", "bound")):
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
    L.make_bundle(d, gate_certs=gates, interval_bound_certs=bounds,
                  kpis=[{"key": "n", "value": n_certs}], prereg={"declared": True})
    return d, L.bundle_fingerprint(d)


# ============================================================ 1. MALFORMED

MALFORMED = [
    ("empty file", b""),
    ("whitespace", b"   \n\t  "),
    ("NUL bytes", b"\x00\x01\x02\x03"),
    ("invalid utf-8", b'{"format": "\xff\xfe"}'),
    ("BOM then json", b'\xef\xbb\xbf{"format": "x"}'),
    ("truncated object", b'{"format": "litho-cert-bundle/1"'),
    ("truncated array", b'{"gate_certs": [{"name": "a"'),
    ("json array at top level", b"[1, 2, 3]"),
    ("json string at top level", b'"just a string"'),
    ("json number at top level", b"42"),
    ("json null at top level", b"null"),
    ("trailing comma", b'{"format": "x",}'),
    ("single quotes", b"{'format': 'x'}"),
    ("unquoted key", b"{format: 1}"),
    ("NaN literal", b'{"format": "x", "n": NaN}'),
    ("Infinity literal", b'{"format": "x", "n": Infinity}'),
    ("control char in string", b'{"format": "a\x01b"}'),
    ("lone surrogate", b'{"format": "\\ud800"}'),
    ("huge exponent", b'{"format": "x", "n": 1e400}'),
    ("certs not a list", b'{"format": "litho-cert-bundle/1", "gate_certs": {}}'),
    ("cert not an object", b'{"format": "litho-cert-bundle/1", "gate_certs": [1, 2]}'),
]


@pytest.mark.parametrize("label,raw", MALFORMED, ids=[m[0] for m in MALFORMED])
def test_malformed_documents_never_pass_and_never_crash(tmp_path, label, raw):
    (tmp_path / "bundle.json").write_bytes(raw)
    fp = fingerprint(tmp_path / "bundle.json")
    for name, fn in (("ordinary", lambda: L.verify_bundle(tmp_path, fp)),
                     ("streaming", lambda: verify_bundle_streaming(tmp_path, fp))):
        res = fn()                                   # must not raise
        assert res["verdict"] not in SUCCESS, f"{name} passed on {label}"
        assert res["ok"] is False
        assert res["errors"], f"{name} gave no reason on {label}"


@pytest.mark.parametrize("label,raw", MALFORMED, ids=[m[0] for m in MALFORMED])
def test_every_emitter_survives_a_malformed_document(tmp_path, label, raw):
    """A broken input must not break the reporting of that fact."""
    (tmp_path / "bundle.json").write_bytes(raw)
    res = L.verify_bundle(tmp_path, fingerprint(tmp_path / "bundle.json"))
    for fmt in EMITTERS:
        assert emit(res, fmt, source=label).strip()
    to_html(res, {}, source=label)


def test_a_bundle_directory_that_is_a_file(tmp_path):
    (tmp_path / "notadir").write_text("x")
    for fn in (L.verify_bundle, verify_bundle_streaming):
        assert fn(tmp_path / "notadir")["ok"] is False


def test_a_manifest_entry_escaping_the_bundle(tmp_path):
    d, _ = _bundle(tmp_path)
    b = json.loads((d / "bundle.json").read_text())
    b["manifest"]["../../etc/passwd"] = "0" * 64
    (d / "bundle.json").write_bytes(V._canon(b) + b"\n")
    assert L.verify_bundle(d, L.bundle_fingerprint(d))["verdict"] == "REFUTED"


# --- the shape sweep: every certificate array crossed with every hostile shape ---
#
# This found five separate crash-on-hostile-input bugs the first time it ran:
# a non-object certificate, a missing required field, a `recorded` that is not an
# object, a `NaN` literal, and a missing `seed`. Each was a denial of service —
# an exception out of the verifier tells the caller nothing.

CERT_ARRAYS = ["gate_certs", "interval_bound_certs", "image_bound_certs",
               "resource_floor_certs"]

HOSTILE_SHAPES = [
    "1", '"x"', "null", "true", "[]", "{}",
    '{"name":5}',
    '{"loci":5}',
    '{"name":"a","loci":{"ae0":"x"}}',
    '{"name":"a","loci":{"lo":[1],"hi":"x"}}',
    '{"name":"a","budget":"x"}',
    '{"name":"a","recorded":7}',
    '{"name":"a","loci":{"lo":[1,2],"hi":[1]}}',
    '{"name":"a","threshold":"x"}',
    '{"name":"a","direction":"below","threshold":1,'
    '"loci":{"lo":[0],"hi":[0.5]},"recorded":null}',
    '{"name":"a","direction":"below","threshold":1,'
    '"loci":{"lo":[0],"hi":[0.5]},"recorded":[]}',
    '{"name":"a","direction":"below","threshold":1,"loci":null}',
    '{"name":"a","direction":"below","threshold":1,"loci":{"lo":null,"hi":null}}',
]


@pytest.mark.parametrize("array", CERT_ARRAYS)
@pytest.mark.parametrize("shape", HOSTILE_SHAPES)
def test_no_certificate_shape_crashes_or_passes(tmp_path, array, shape):
    (tmp_path / "bundle.json").write_text(
        f'{{"format":"{L.FORMAT}","seed":1,"manifest":{{}},'
        f'"merkle_root":"00","{array}":[{shape}]}}')
    fp = fingerprint(tmp_path / "bundle.json")
    for name, fn in (("ordinary", lambda: L.verify_bundle(tmp_path, fp)),
                     ("streaming", lambda: verify_bundle_streaming(tmp_path, fp))):
        res = fn()                                    # must not raise
        assert res["verdict"] not in SUCCESS, f"{name} passed on {array}:{shape}"
        assert res["errors"]


TOP_LEVEL_SHAPES = [
    ("no seed", '{"format":"%s","manifest":{},"merkle_root":"00"}'),
    ("seed not a number", '{"format":"%s","seed":"abc","manifest":{}}'),
    ("manifest not a dict", '{"format":"%s","seed":1,"manifest":[]}'),
    ("manifest escapes", '{"format":"%s","seed":1,"manifest":{"../x":"aa"}}'),
    ("absolute manifest path", '{"format":"%s","seed":1,"manifest":{"/etc/x":"aa"}}'),
    ("digest not hex", '{"format":"%s","seed":1,"manifest":{"a":"zz"}}'),
    ("digest not a string", '{"format":"%s","seed":1,"manifest":{"a":5}}'),
    ("no merkle root", '{"format":"%s","seed":1,"manifest":{}}'),
    ("kpis not a list", '{"format":"%s","seed":1,"manifest":{},"kpis":5}'),
    ("kpi row not an object",
     '{"format":"%s","seed":1,"manifest":{},"kpis":[1],"prereg_file":"p.json"}'),
    ("salt not hex",
     '{"format":"%s","seed":1,"manifest":{},"outputs_salt":"zz","outputs_commitment":"a"}'),
    ("prereg escapes",
     '{"format":"%s","seed":1,"manifest":{},"prereg_file":"../../etc/passwd"}'),
]


@pytest.mark.parametrize("label,template", TOP_LEVEL_SHAPES,
                         ids=[t[0] for t in TOP_LEVEL_SHAPES])
def test_no_top_level_shape_crashes_or_passes(tmp_path, label, template):
    (tmp_path / "bundle.json").write_text(template % L.FORMAT)
    fp = fingerprint(tmp_path / "bundle.json")
    for name, fn in (("ordinary", lambda: L.verify_bundle(tmp_path, fp)),
                     ("streaming", lambda: verify_bundle_streaming(tmp_path, fp))):
        res = fn()                                    # must not raise
        assert res["verdict"] not in SUCCESS, f"{name} passed on {label}"
        assert res["errors"], f"{name} gave no reason on {label}"


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_json_literals_are_refused(tmp_path, literal):
    """Not valid JSON, but every parser in wide use accepts them.

    The canonical form forbids them, so a document containing one could not be
    re-serialised — which used to raise on the way to the verdict.
    """
    d, _ = _bundle(tmp_path, n_certs=1, kinds=("bound",))
    raw = (d / "bundle.json").read_text().replace('"threshold":358.15',
                                                  f'"threshold":{literal}')
    (d / "bundle.json").write_text(raw)
    fp = L.bundle_fingerprint(d)
    for fn in (L.verify_bundle, verify_bundle_streaming):
        res = fn(d, fp)
        assert res["verdict"] not in SUCCESS
        assert res["errors"]


# ============================================================ 2. EMPTY / DEGENERATE

def test_a_bundle_with_no_certificates_is_vacuous_not_verified(tmp_path):
    L.make_bundle(tmp_path, gate_certs=[], kpis=[], prereg={})
    fp = L.bundle_fingerprint(tmp_path)
    for fn in (L.verify_bundle, verify_bundle_streaming):
        assert fn(tmp_path, fp)["verdict"] == "VACUOUS"


def test_a_certificate_with_no_loci_is_verified_vacuous_not_verified(tmp_path):
    cert = L.gate_cert("empty", budget=0.05, safety=1.5, n_photons=100.0,
                       thr=0.30, delta_dose=0.0, loci=[])
    L.make_bundle(tmp_path, gate_certs=[cert], kpis=[], prereg={})
    fp = L.bundle_fingerprint(tmp_path)
    for fn in (L.verify_bundle, verify_bundle_streaming):
        res = fn(tmp_path, fp)
        assert res["verdict"] == "VERIFIED-VACUOUS"
        assert res["n_gated_loci"] == 0


def test_an_empty_interval_bound_certificate_does_not_admit():
    c = L.interval_bound_cert("e", quantity="q", unit="u", threshold=1.0,
                              direction="below", loci=[])
    assert c["recorded"]["admit"] is False, "nothing was bounded, so nothing was earned"


def test_an_empty_diff_and_an_empty_report(tmp_path):
    L.make_bundle(tmp_path / "a", gate_certs=[], kpis=[], prereg={})
    L.make_bundle(tmp_path / "b", gate_certs=[], kpis=[], prereg={})
    d = diff_bundles(tmp_path / "a", tmp_path / "b")
    assert d["n_regressed"] == 0 and d["rows"] == []
    assert "nothing to chart" in to_html(L.verify_bundle(tmp_path / "a"), {})


# ============================================================ 3. ENORMOUS

@pytest.mark.parametrize("depth", [1_000, 100_000, 500_000])
def test_deep_nesting_is_a_verdict_at_any_depth(tmp_path, depth):
    (tmp_path / "bundle.json").write_bytes(
        b'{"a": ' + b"[" * depth + b"]" * depth + b"}")
    fp = fingerprint(tmp_path / "bundle.json")
    for fn in (L.verify_bundle, verify_bundle_streaming):
        res = fn(tmp_path, fp)
        assert res["verdict"] not in SUCCESS
        assert res["errors"]


def test_a_very_wide_object_does_not_break_the_walker():
    text = "{" + ",".join(f'"k{i}": {i}' for i in range(50_000)) + "}"
    assert len(walk(text, lambda k, c: None)) == 50_000


def test_many_certificates_stream_and_agree(tmp_path):
    d, fp = _bundle(tmp_path, n_certs=200, n_loci=2, kinds=("bound",))
    a, b = L.verify_bundle(d, fp), verify_bundle_streaming(d, fp)
    assert a["verdict"] == b["verdict"] == "VERIFIED"
    assert a["n_certificates"] == b["n_certificates"] == 200
    assert a["n_gated_loci"] == b["n_gated_loci"] == 400


def test_a_very_long_certificate_name_is_escaped_not_truncated(tmp_path):
    name = "x" * 20_000
    cert = L.interval_bound_cert(name, quantity="q", unit="u", threshold=1.0,
                                 direction="below", loci=[(0.0, 0.5)])
    L.make_bundle(tmp_path, interval_bound_certs=[cert], kpis=[], prereg={})
    res = L.verify_bundle(tmp_path, L.bundle_fingerprint(tmp_path))
    assert res["verdict"] == "VERIFIED"
    assert name[:100] in to_html(res, json.loads((tmp_path / "bundle.json").read_text()))


# ============================================================ 4. OUT OF DISTRIBUTION

ODD_NUMBERS = [
    ("nan", float("nan")), ("inf", float("inf")), ("-inf", float("-inf")),
    ("zero", 0.0), ("negative", -1.0), ("tiny", 5e-324),
    ("huge", 1.7976931348623157e308), ("negative zero", -0.0),
]


@pytest.mark.parametrize("label,value", ODD_NUMBERS, ids=[o[0] for o in ODD_NUMBERS])
def test_odd_numbers_in_a_bound_certificate(tmp_path, label, value):
    """Whatever the number, a verdict — never a crash and never an unearned pass."""
    d, _ = _bundle(tmp_path, n_certs=1, kinds=("bound",))
    b = json.loads((d / "bundle.json").read_text())
    b["interval_bound_certs"][0]["threshold"] = value
    try:
        (d / "bundle.json").write_bytes(V._canon(b) + b"\n")
    except ValueError:
        pytest.skip("canonical JSON refuses this value at write time, which is correct")
    res = L.verify_bundle(d, L.bundle_fingerprint(d))
    if res["verdict"] in SUCCESS:
        assert math.isfinite(value), f"{label} was accepted"


HOSTILE_NAMES = [
    "", " ", "\n", "\t", ZWSP, " pad", "../../etc/passwd", "<script>x</script>",
    "'; DROP TABLE --", "café", "café", "\U0001f512", "a" * 5000, "\\", '"',
    "\x00truncate", "%s%n", "{{7*7}}",
]


@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_hostile_certificate_names_do_not_escape_any_surface(tmp_path, name):
    cert = L.interval_bound_cert(name or "x", quantity=name, unit=name, threshold=1.0,
                                 direction="below", loci=[(0.0, 0.5)])
    cert["name"] = name
    L.make_bundle(tmp_path, interval_bound_certs=[cert], kpis=[], prereg={})
    res = L.verify_bundle(tmp_path, L.bundle_fingerprint(tmp_path))
    bundle = json.loads((tmp_path / "bundle.json").read_text())
    html = to_html(res, bundle)
    assert "<script>x</script>" not in html
    ET.fromstring(emit(res, "junit"))            # must stay well-formed XML
    json.loads(emit(res, "sarif"))               # must stay valid JSON


def test_unicode_normalisation_variants_are_different_bundles(tmp_path):
    """`cafe` + combining accent is not the same bytes as `cafe-acute`."""
    a, b = tmp_path / "a", tmp_path / "b"
    for d, name in ((a, "café"), (b, "café")):
        c = L.interval_bound_cert(name, quantity="q", unit="u", threshold=1.0,
                                  direction="below", loci=[(0.0, 0.5)])
        L.make_bundle(d, interval_bound_certs=[c], kpis=[], prereg={})
    assert L.bundle_fingerprint(a) != L.bundle_fingerprint(b)
    assert L.verify_bundle(a, L.bundle_fingerprint(b))["verdict"] == "REFUTED"


@pytest.mark.parametrize("direction", ["below", "above"])
def test_a_locus_exactly_on_the_threshold_never_admits(direction):
    c = L.interval_bound_cert("edge", quantity="q", unit="u", threshold=1.0,
                              direction=direction, loci=[(1.0, 1.0)])
    assert c["recorded"]["admit"] is False, "zero margin is not margin"


def test_one_ulp_either_side_of_the_threshold():
    inside = math.nextafter(1.0, 0.0)
    c_in = L.interval_bound_cert("in", quantity="q", unit="u", threshold=1.0,
                                 direction="below", loci=[(0.0, inside)])
    c_out = L.interval_bound_cert("out", quantity="q", unit="u", threshold=1.0,
                                  direction="below", loci=[(0.0, 1.0)])
    assert c_in["recorded"]["admit"] is True
    assert c_out["recorded"]["admit"] is False


# ============================================================ 5. DIFFERENTIAL

@pytest.mark.parametrize("n_certs,n_loci,kinds", [
    (1, 1, ("gate",)), (1, 1, ("bound",)), (3, 5, ("gate", "bound")),
    (10, 1, ("bound",)), (1, 50, ("gate",)),
])
def test_streaming_and_ordinary_agree_on_the_whole_result(tmp_path, n_certs, n_loci, kinds):
    d, fp = _bundle(tmp_path, n_certs, n_loci, kinds)
    a, b = L.verify_bundle(d, fp), verify_bundle_streaming(d, fp)
    for k in ("ok", "verdict", "errors", "fingerprint", "n_certificates",
              "n_gated_loci", "trust_anchor", "internally_consistent"):
        assert a[k] == b[k], k


@pytest.mark.parametrize("mutate", [
    lambda b: b["gate_certs"][0]["recorded"].update(interval_admit=False),
    lambda b: b["interval_bound_certs"][0]["recorded"].update(worst_margin=1e9),
    lambda b: b["interval_bound_certs"][0]["loci"]["lo"].__setitem__(0, 1e9),
    lambda b: b.update(merkle_root="0" * 64),
    lambda b: b.update(format="something-else/1"),
    lambda b: b["kpis"].append({"key": "x", "value": 1}),
    lambda b: b["manifest"].clear(),
])
def test_streaming_catches_every_forgery_the_ordinary_path_does(tmp_path, mutate):
    d, _ = _bundle(tmp_path, n_certs=2)
    b = json.loads((d / "bundle.json").read_text())
    mutate(b)
    (d / "bundle.json").write_bytes(V._canon(b) + b"\n")
    fp = L.bundle_fingerprint(d)
    a, s = L.verify_bundle(d, fp), verify_bundle_streaming(d, fp)
    assert a["verdict"] == s["verdict"] != "VERIFIED"
    assert a["errors"] == s["errors"]


def test_every_export_format_preserves_the_verdict(tmp_path):
    """No format may turn a non-success into a success, or lose the name."""
    d, fp = _bundle(tmp_path)
    cases = [("anchored", fp, {}), ("abstained", "", {}),
             ("refuted", "ab" * 32, {}), ("waived", "", {"require_anchor": False})]
    for label, anchor, kw in cases:
        res = L.verify_bundle(d, anchor, **kw)
        verdict = res["verdict"]
        success = verdict in SUCCESS

        js = json.loads(emit(res, "json"))
        assert js["verdict"] == verdict and js["ok"] is success, label

        rows = [json.loads(x) for x in emit(res, "jsonl").splitlines()]
        assert rows[0]["verdict"] == verdict and rows[0]["ok"] is success, label

        sarif = json.loads(emit(res, "sarif"))
        assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is success, label
        if not success:
            assert verdict in json.dumps(sarif), f"{label}: SARIF does not name the verdict"

        x = ET.fromstring(emit(res, "junit"))
        assert (x.get("failures") == "0") is success, label
        if not success:
            assert x.find(".//failure").get("type") == verdict, label

        assert verdict in to_html(
            res, json.loads((d / "bundle.json").read_text())), label
        assert (status_for(verdict) < 400) is success, label


@pytest.mark.parametrize("verdict", sorted(ALL_VERDICTS) + ["SOMETHING_NEW", "", None])
def test_no_verdict_is_reported_as_a_success_unless_it_is_one(verdict):
    """Including verdicts that do not exist yet."""
    expected = verdict in SUCCESS
    assert verdict_meta(verdict)[0] is expected
    assert (status_for(verdict) < 400) is expected
    res = {"verdict": verdict, "ok": expected, "errors": []}
    assert json.loads(emit(res, "sarif"))["runs"][0]["invocations"][0][
        "executionSuccessful"] is expected
    assert (ET.fromstring(emit(res, "junit")).get("failures") == "0") is expected


def test_the_diff_never_calls_a_regression_an_improvement(tmp_path):
    """Losing admission is a regression however the numbers moved."""
    good = L.interval_bound_cert("t", quantity="q", unit="u", threshold=10.0,
                                 direction="below", loci=[(0.0, 9.0)])
    bad = L.interval_bound_cert("t", quantity="q", unit="u", threshold=10.0,
                                direction="below", loci=[(0.0, 11.0)])
    L.make_bundle(tmp_path / "a", interval_bound_certs=[good], kpis=[], prereg={})
    L.make_bundle(tmp_path / "b", interval_bound_certs=[bad], kpis=[], prereg={})
    d = diff_bundles(tmp_path / "a", tmp_path / "b",
                     anchor_a=L.bundle_fingerprint(tmp_path / "a"),
                     anchor_b=L.bundle_fingerprint(tmp_path / "b"))
    assert d["n_regressed"] == 1 and d["n_improved"] == 0


# ============================================================ 6. THE SERVICE

@pytest.fixture(scope="module")
def service():
    srv = make_server("127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def _post(base, body, ctype="application/zip", anchor=None, path="/verify"):
    headers = {"Content-Type": ctype}
    if anchor:
        headers["X-LCERT-Anchor"] = anchor
    req = urllib.request.Request(base + path, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


HOSTILE_BODIES = [
    ("empty zip", lambda: _zip({})),
    ("large member", lambda: _zip({"bundle.json": b"0" * (4 << 20)})),
    ("nested traversal", lambda: _zip({"a/../../x": b"x"})),
    ("windows traversal", lambda: _zip({"..\\x": b"x"})),
    ("absolute path", lambda: _zip({"/etc/passwd": b"x"})),
    ("bundle.json as a directory", lambda: _zip({"bundle.json/x": b"x"})),
    ("not a zip", lambda: b"PK\x03\x04 truncated"),
    ("random bytes", lambda: bytes(range(256)) * 40),
]


@pytest.mark.parametrize("label,make", HOSTILE_BODIES, ids=[h[0] for h in HOSTILE_BODIES])
def test_the_service_refuses_hostile_bodies_without_a_success(service, label, make):
    code, body = _post(service, make())
    assert code >= 400, f"{label} got {code}"
    assert json.loads(body).get("verdict") not in SUCCESS, label


def test_the_service_never_returns_200_without_an_anchor(service, tmp_path):
    d, fp = _bundle(tmp_path)
    zipped = _zip({f.name: f.read_bytes() for f in d.iterdir()})
    assert _post(service, zipped)[0] == 428
    assert _post(service, zipped, anchor=fp)[0] == 200


@pytest.mark.parametrize("anchor", ["not-hex", "a" * 63, "z" * 64, "0x" + "a" * 62])
def test_the_service_never_accepts_a_malformed_anchor(service, tmp_path, anchor):
    d, _ = _bundle(tmp_path)
    zipped = _zip({f.name: f.read_bytes() for f in d.iterdir()})
    code, body = _post(service, zipped, anchor=anchor)
    assert code >= 400, anchor
    assert json.loads(body).get("verdict") not in SUCCESS


def test_the_service_does_not_leak_local_paths(service):
    _, body = _post(service, b"garbage", ctype="application/json")
    text = body.decode()
    assert "/tmp" not in text and "lcert-serve" not in text


# ============================================================ 7. NO STATE LEAKS

def test_verifying_twice_gives_the_same_answer(tmp_path):
    d, fp = _bundle(tmp_path, n_certs=3)
    assert L.verify_bundle(d, fp) == L.verify_bundle(d, fp)


def test_a_result_is_not_shared_between_bundles(tmp_path):
    # `_bundle` emits one gate and one bound certificate per `n_certs`.
    a, fa = _bundle(tmp_path / "a", n_certs=1)
    b, fb = _bundle(tmp_path / "b", n_certs=4)
    ra, rb = L.verify_bundle(a, fa), L.verify_bundle(b, fb)
    assert ra["n_certificates"] == 2 and rb["n_certificates"] == 8
    assert L.verify_bundle(a, fa)["n_certificates"] == 2


def test_editing_a_bundle_between_runs_changes_the_answer(tmp_path):
    """A cache keyed on the path alone would pass the first line and fail here."""
    d, fp = _bundle(tmp_path, n_certs=1, kinds=("bound",))
    assert L.verify_bundle(d, fp)["verdict"] == "VERIFIED"
    b = json.loads((d / "bundle.json").read_text())
    b["interval_bound_certs"][0]["recorded"]["admit"] = False
    (d / "bundle.json").write_bytes(V._canon(b) + b"\n")
    new_fp = L.bundle_fingerprint(d)
    assert L.verify_bundle(d, new_fp)["verdict"] == "REFUTED"
    assert verify_bundle_streaming(d, new_fp)["verdict"] == "REFUTED"


def test_the_private_parsed_key_never_reaches_a_caller(tmp_path):
    d, fp = _bundle(tmp_path)
    for res in (L.verify_bundle(d, fp), verify_bundle_streaming(d, fp)):
        assert not any(k.startswith("_") for k in res)


def test_the_emitters_do_not_mutate_the_result(tmp_path):
    d, fp = _bundle(tmp_path)
    res = L.verify_bundle(d, fp)
    before = json.dumps(res, sort_keys=True, default=str)
    for fmt in EMITTERS:
        emit(res, fmt)
    to_html(res, {})
    assert json.dumps(res, sort_keys=True, default=str) == before
