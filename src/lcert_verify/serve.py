"""An HTTP verification service — standard library only, no dependencies.

Some teams will not add a Python dependency to a signoff flow but will call an
endpoint. This is that endpoint. It runs the same verifier, reaches nothing but
the request body, and writes nothing outside a temporary directory it deletes.

**The status code carries the verdict, so a naive caller cannot misread it.**
That is the whole design. A service that returned 200 with `{"verdict":
"UNVERIFIED"}` would let `if response.ok:` treat an abstention as a pass — the
exact failure this project exists to prevent, in HTTP form. So:

===========================  ======  ===============================================
Verdict                      Status  Why that code
===========================  ======  ===============================================
VERIFIED, VERIFIED-VACUOUS,     200  the check was made and it stood
INTERNALLY-CONSISTENT
UNVERIFIED                      428  Precondition Required — the anchor is a
                                     missing precondition, not a failure of the
                                     bundle
REFUTED, VACUOUS                422  Unprocessable Content — the artifact was
                                     read and does not hold up
too large / malformed      413/400   not a verdict at all
===========================  ======  ===============================================

428 is deliberate rather than 4xx-generic: RFC 6585 defines it for a request that
must be made conditional, and supplying the out-of-band fingerprint is exactly
that condition.

Endpoints:

``GET /health``      liveness, and the version
``GET /scope``       what is and is not checked, verbatim
``POST /verify``     a bundle, as a zip (the whole directory) or as a bare
                     ``bundle.json``. Bundles with payload files must be zipped,
                     because a single document cannot carry them; posting one
                     bare then fails its own manifest, and the reply says so.
"""
from __future__ import annotations

import io
import json
import shutil
import tempfile
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Tuple

from . import SCOPE, __version__, verify_bundle

#: Refuse bodies above this. A verification service that can be made to allocate
#: without bound is a denial of service wearing a useful hat.
MAX_BODY = 256 * 1024 * 1024

#: Verdict -> HTTP status. Anything unknown is a failure, never a pass.
STATUS = {
    "VERIFIED": 200,
    "VERIFIED-VACUOUS": 200,
    "INTERNALLY-CONSISTENT": 200,
    "UNVERIFIED": 428,
    "VACUOUS": 422,
    "REFUTED": 422,
}


def status_for(verdict: str) -> int:
    return STATUS.get(verdict, 422)


def _materialise(body: bytes, content_type: str, dest: Path) -> Tuple[bool, str]:
    """Write the request body out as a bundle directory. ``(ok, error)``."""
    dest.mkdir(parents=True, exist_ok=True)
    if content_type.startswith("application/zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(body)) as z:
                for info in z.infolist():
                    name = info.filename
                    # Refuse traversal and absolute paths rather than sanitising
                    # them: a zip that tries is not one to be helpful about.
                    if name.startswith("/") or ".." in Path(name).parts:
                        return False, f"refusing archive entry {name!r}"
                    if info.is_dir():
                        continue
                    target = dest / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(info) as src, open(target, "wb") as out:
                        shutil.copyfileobj(src, out, length=1 << 20)
        except (zipfile.BadZipFile, OSError) as exc:
            return False, f"not a readable zip: {exc}"
        if not (dest / "bundle.json").is_file():
            # Allow one wrapping directory, which is what `zip -r` produces.
            inner = [p for p in dest.iterdir() if (p / "bundle.json").is_file()]
            if len(inner) == 1:
                for p in inner[0].iterdir():
                    p.rename(dest / p.name)
            else:
                return False, "archive contains no bundle.json"
        return True, ""

    # Otherwise: the bundle.json document itself.
    (dest / "bundle.json").write_bytes(body)
    return True, ""


class Handler(BaseHTTPRequestHandler):
    server_version = f"lcert-verify/{__version__}"

    def _send(self, code: int, payload: dict, ctype="application/json"):
        body = json.dumps(payload, indent=2, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if "verdict" in payload:
            self.send_header("X-LCERT-Verdict", str(payload["verdict"]))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):                                   # noqa: N802
        if self.path.rstrip("/") in ("/health", ""):
            return self._send(200, {"ok": True, "service": "lcert-verify",
                                    "version": __version__})
        if self.path.rstrip("/") == "/scope":
            return self._send(200, {"scope": SCOPE})
        return self._send(404, {"error": f"no route {self.path!r}",
                                "routes": ["/health", "/scope", "POST /verify"]})

    def do_POST(self):                                  # noqa: N802
        if self.path.split("?")[0].rstrip("/") != "/verify":
            return self._send(404, {"error": f"no route {self.path!r}"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._send(400, {"error": "Content-Length is not a number"})
        if length <= 0:
            return self._send(400, {"error": "empty request body"})
        if length > MAX_BODY:
            return self._send(413, {"error": f"body exceeds {MAX_BODY} bytes",
                                    "max_bytes": MAX_BODY})

        body = self.rfile.read(length)
        anchor = ""
        for source in (self.headers.get("X-LCERT-Anchor"),
                       _query(self.path).get("anchor")):
            if source:
                anchor = source.strip().lower()
                break

        tmp = Path(tempfile.mkdtemp(prefix="lcert-serve-"))
        try:
            ok, err = _materialise(body, self.headers.get("Content-Type", ""), tmp / "b")
            if not ok:
                return self._send(400, {"error": err})
            res = verify_bundle(tmp / "b", anchor)
            payload = {k: v for k, v in res.items() if not k.startswith("_")}
            payload["anchor_supplied"] = bool(anchor)
            # A bundle.json posted on its own cannot carry its payload files, so
            # the manifest fails on every one of them. That is a correct verdict
            # and a confusing one, so say what to do about it.
            if (not self.headers.get("Content-Type", "").startswith("application/zip")
                    and any("was not supplied" in e or "manifest" in e.lower()
                            for e in res.get("errors", []))):
                payload["how_to_resolve"] = (
                    "This bundle has payload files listed in its manifest, and a "
                    "bare bundle.json cannot carry them. Post the whole directory "
                    "as application/zip instead.")
            if res["verdict"] == "UNVERIFIED":
                payload["how_to_resolve"] = (
                    "Send the bundle fingerprint you obtained OUT OF BAND in the "
                    "X-LCERT-Anchor header. Without it nothing can be asserted, "
                    "which is why this is 428 and not 200.")
            return self._send(status_for(res["verdict"]), payload)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def log_message(self, fmt, *args):                  # noqa: A003
        # Log the verdict, not the payload. Bundles can be confidential and this
        # service is meant to be droppable into a fab's internal network.
        pass


def _query(path: str) -> dict:
    from urllib.parse import parse_qs, urlparse
    return {k: v[0] for k, v in parse_qs(urlparse(path).query).items()}


def make_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


def main(argv=None) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(
        prog="lcert-verify serve",
        description="Run the verifier as an HTTP service. Standard library only.")
    ap.add_argument("--host", default="127.0.0.1",
                    help="default is loopback; pass 0.0.0.0 to expose deliberately")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args(argv if argv is not None else sys.argv[1:])
    srv = make_server(a.host, a.port)
    print(f"lcert-verify {__version__} serving on http://{a.host}:{a.port}")
    print("  GET  /health   GET /scope   POST /verify")
    print("  an abstention is 428, not 200 — see the module docstring for why")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
