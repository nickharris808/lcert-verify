#!/usr/bin/env python3
"""Regenerate the README badges that carry a number, by running the code.

A badge saying "26 passing" over a suite of 409 is a claim the code does not
support, and that is what shipped. So the numbers are derived here and a CI job
runs this with --check: a stale badge fails the build rather than misleading a
reader.

Same discipline as the generated CLI reference and the regenerated leaderboard.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

PY_PACKAGES = ["lcert-verify", "lcert-build", "equiv-receipt", "prereg-seal",
               "cert-atlas", "certified-mcp", "certified-kit"]

PY_VERSIONS = "3.9 | 3.10 | 3.11 | 3.12 | 3.13"


def shield(label: str, message: str, colour: str) -> str:
    def enc(s):
        return (s.replace("-", "--").replace("_", "__").replace(" ", "%20")
                .replace("|", "%7C").replace("/", "%2F"))
    return f"https://img.shields.io/badge/{enc(label)}-{enc(message)}-{colour}"


def count_tests(pkg: Path) -> int:
    """Passing tests, by running the suite. Not by reading a number."""
    # -p no:regtest: that plugin prints its own report after the summary line,
    # which makes the count harder to find and is not what is being measured.
    # No -q here: several packages already set it in addopts, and -qq suppresses
    # the summary line this function exists to read.
    r = subprocess.run([sys.executable, "-m", "pytest", "tests",
                        "-p", "no:cacheprovider", "-p", "no:regtest"],
                       cwd=pkg, capture_output=True, text=True)
    m = re.findall(r"(\d+) passed", r.stdout + r.stderr)
    if not m:
        raise RuntimeError(f"could not count tests in {pkg.name}:\n"
                           f"{(r.stdout + r.stderr)[-400:]}")
    if r.returncode != 0:
        raise RuntimeError(f"{pkg.name}: the suite is not green; refusing to "
                           f"write a badge over a failing run")
    return int(m[-1])


def count_conformance(pkg: Path) -> int:
    subprocess.run([sys.executable, "test/gen_fixtures.py"], cwd=pkg,
                   capture_output=True, text=True)
    r = subprocess.run(["node", "test/conformance.mjs"], cwd=pkg,
                       capture_output=True, text=True)
    m = re.search(r"(\d+) passed", r.stdout)
    if not m:
        raise RuntimeError(f"could not count conformance checks:\n{r.stdout[-400:]}")
    return int(m.group(1))


def atlas_shape(pkg: Path):
    sys.path.insert(0, str(pkg / "src"))
    import tempfile

    from cert_atlas.generate import build
    ix = build(Path(tempfile.mkdtemp()) / "a")
    return ix["n_cases"], ix["n_invalid"]


def badges_for(name: str, pkg: Path) -> dict:
    """label -> (message, colour), every number derived by running the code.

    ``pkg`` is the package directory, which differs between the development tree
    (one directory per package) and a published repository (the package IS the
    repository root) -- hence --single.
    """
    out = {
        "license": ("Apache-2.0", "blue"),
        "python": (PY_VERSIONS, "blue"),
        "dependencies": ("none", "brightgreen"),
    }
    if name == "lcert-verify-web":
        out.pop("python")
        out["node"] = ("18+", "blue")
        out["conformance"] = (f"{count_conformance(pkg)} checks vs Python", "brightgreen")
        return out
    if name == "certified-oss":
        return {"license": ("Apache-2.0", "blue"),
                "repositories": ("9", "blue"),
                "docs": ("live", "brightgreen")}
    out["tests"] = (f"{count_tests(pkg)} passing", "brightgreen")
    if name == "cert-atlas":
        n, inv = atlas_shape(pkg)
        out["atlas"] = (f"{n} cases / {inv} forgeries", "blue")
        out["python"] = ("3.9+", "blue")
        out.pop("dependencies")
    if name in ("lcert-build", "certified-kit", "certified-mcp"):
        out.pop("dependencies", None)
        out["python"] = ("3.9+", "blue")
    if name == "certified-mcp":
        out["mcp"] = ("stdio | 8 tools", "8A2BE2")
    return out


def rewrite(readme: Path, name: str, badges: dict) -> str:
    text = readme.read_text()
    ci = (f"[![ci](https://github.com/nickharris808/{name}/actions/workflows/ci.yml/"
          f"badge.svg)](https://github.com/nickharris808/{name}/actions/workflows/ci.yml)")
    line = ci if "actions/workflows/ci.yml" in text else ""
    for label, (msg, colour) in badges.items():
        line += ("\n" if line else "") + f"![{label}]({shield(label, msg, colour)})"

    # Strip any existing badge lines wherever they are, then place the block
    # directly under the H1. A stranger should see what this is and that it is
    # green before reading a word of prose.
    kept = [ln for ln in text.split("\n")
            if not re.match(r"^(\[!\[ci\]|!\[[a-z]+\]\(https://img\.shields\.io)", ln)]
    while len(kept) > 1 and kept[0].strip() == "":
        kept.pop(0)
    out, placed = [], False
    for ln in kept:
        out.append(ln)
        if not placed and ln.startswith("# "):
            out.append("")
            out.append(line)
            placed = True
    if not placed:
        out = [line, ""] + out
    # collapse any run of blank lines the strip left behind
    collapsed = []
    for ln in out:
        if ln.strip() == "" and collapsed and collapsed[-1].strip() == "":
            continue
        collapsed.append(ln)
    return "\n".join(collapsed)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("names", nargs="*",
                    default=PY_PACKAGES + ["lcert-verify-web", "certified-oss"])
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--single", default="")
    a = ap.parse_args(argv)

    stale = []
    for name in (a.names or PY_PACKAGES + ["lcert-verify-web", "certified-oss"]):
        d = Path(a.root) if a.single == name else \
            Path(a.root) / ("verify-web" if name == "lcert-verify-web" else name)
        readme = d / "README.md"
        if not readme.exists():
            print(f"  {name}: no README")
            continue
        try:
            new = rewrite(readme, name, badges_for(name, d))
        except Exception as exc:                       # noqa: BLE001
            print(f"  {name}: could not derive badges — {exc}", file=sys.stderr)
            return 1
        if a.check:
            if readme.read_text() != new:
                stale.append(name)
        else:
            readme.write_text(new)
            print(f"  {name}: badges refreshed")
    if stale:
        print("STALE badges (run python refresh_badges.py): " + ", ".join(stale),
              file=sys.stderr)
        return 1
    if a.check:
        print("every badge is current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
