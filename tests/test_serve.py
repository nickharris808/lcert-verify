"""The HTTP service. The status code is the load-bearing part.

A service that returned 200 with `{"verdict": "UNVERIFIED"}` would let a caller
writing `if response.ok:` read an abstention as a pass — the exact failure this
project exists to prevent, in HTTP form.
"""
from __future__ import annotations

import io
import json
import threading
import urllib.error
import urllib.request
import zipfile

import pytest

import lcert_verify as L
from lcert_verify.serve import MAX_BODY, STATUS, make_server, status_for


@pytest.fixture(scope="module")
def service():
    srv = make_server("127.0.0.1", 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    d = tmp_path_factory.mktemp("b") / "bundle"
    cert = L.interval_bound_cert("thermal", quantity="T", unit="K", threshold=358.15,
                                 direction="below", loci=[(340.0, 351.2), (338.4, 349.9)])
    L.make_bundle(d, interval_bound_certs=[cert], kpis=[], prereg={"x": 1})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for f in d.iterdir():
            z.write(f, f.name)
    return d, L.bundle_fingerprint(d), buf.getvalue()


def _post(base, body, ctype="application/zip", anchor=None, path="/verify"):
    headers = {"Content-Type": ctype}
    if anchor:
        headers["X-LCERT-Anchor"] = anchor
    req = urllib.request.Request(base + path, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read()), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), dict(e.headers)


def _get(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


# ---------------------------------------------------------------- the discipline

def test_an_abstention_is_not_a_200(service, bundle):
    _, _, zipped = bundle
    code, body, headers = _post(service, zipped)
    assert code == 428, "an abstention returned a success code"
    assert body["verdict"] == "UNVERIFIED"
    assert body["anchor_supplied"] is False
    assert "out of band" in body["how_to_resolve"].lower()
    assert headers.get("X-LCERT-Verdict") == "UNVERIFIED"


def test_an_anchored_verification_is_a_200(service, bundle):
    _, fp, zipped = bundle
    code, body, _ = _post(service, zipped, anchor=fp)
    assert code == 200 and body["verdict"] == "VERIFIED"
    assert body["n_gated_loci"] == 2


def test_a_refutation_is_a_422(service, bundle):
    _, _, zipped = bundle
    code, body, _ = _post(service, zipped, anchor="ab" * 32)
    assert code == 422 and body["verdict"] == "REFUTED"


def test_every_verdict_maps_to_a_status_and_only_three_are_success():
    for v in ("VERIFIED", "VERIFIED-VACUOUS", "INTERNALLY-CONSISTENT"):
        assert status_for(v) == 200
    for v in ("UNVERIFIED", "VACUOUS", "REFUTED"):
        assert status_for(v) >= 400, v
    assert status_for("UNVERIFIED") == 428, "428 says the anchor is a precondition"
    assert sum(1 for c in STATUS.values() if c == 200) == 3


def test_an_unknown_verdict_is_never_a_success():
    assert status_for("SOMETHING_NEW") >= 400


# ---------------------------------------------------------------- robustness

def test_an_empty_body_is_a_400_not_a_verdict(service):
    code, body, _ = _post(service, b"")
    assert code == 400 and "verdict" not in body


def test_an_oversized_body_is_refused_without_reading_it(service):
    req = urllib.request.Request(service + "/verify", data=b"x",
                                 headers={"Content-Type": "application/zip",
                                          "Content-Length": str(MAX_BODY + 1)})
    req.add_header("Content-Length", str(MAX_BODY + 1))
    try:
        urllib.request.urlopen(req, timeout=10)
        pytest.fail("oversized body was accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 413


def test_a_zip_that_escapes_its_directory_is_refused(service):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../escape.txt", "x")
    code, body, _ = _post(service, buf.getvalue())
    assert code == 400 and "refusing archive entry" in body["error"]


def test_an_absolute_path_in_a_zip_is_refused(service):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("/etc/passwd", "x")
    code, body, _ = _post(service, buf.getvalue())
    assert code == 400 and "refusing" in body["error"]


def test_a_zip_with_no_bundle_is_refused(service):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", "x")
    code, body, _ = _post(service, buf.getvalue())
    assert code == 400 and "no bundle.json" in body["error"]


def test_garbage_is_a_verdict_not_a_crash(service):
    code, body, _ = _post(service, b"\x00\x01\x02 not a zip", ctype="application/json")
    assert code == 422 and body["verdict"] == "REFUTED"


def test_a_bare_bundle_json_says_what_to_do_about_its_payload_files(service, bundle):
    d, fp, _ = bundle
    code, body, _ = _post(service, (d / "bundle.json").read_bytes(),
                          ctype="application/json", anchor=fp)
    assert code == 422
    assert "zip" in body["how_to_resolve"]


# ---------------------------------------------------------------- routes

def test_health_and_scope(service):
    code, body = _get(service, "/health")
    assert code == 200 and body["ok"] is True and body["version"]
    code, body = _get(service, "/scope")
    assert code == 200 and len(body["scope"]) > 100


def test_an_unknown_route_lists_the_real_ones(service):
    code, body = _get(service, "/nope")
    assert code == 404 and "/verify" in " ".join(body["routes"])


def test_posting_to_the_wrong_route_is_a_404(service, bundle):
    _, _, zipped = bundle
    code, _, _ = _post(service, zipped, path="/nope")
    assert code == 404


def test_the_service_does_not_log_bundle_contents():
    """Bundles can be confidential; this is meant for an internal network."""
    import inspect

    from lcert_verify import serve
    src = inspect.getsource(serve.Handler.log_message)
    assert "pass" in src


def test_it_agrees_with_the_library(service, bundle):
    d, fp, zipped = bundle
    _, body, _ = _post(service, zipped, anchor=fp)
    direct = L.verify_bundle(d, fp)
    for k in ("verdict", "ok", "n_certificates", "n_gated_loci", "fingerprint"):
        assert body[k] == direct[k], k
