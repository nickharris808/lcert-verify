#!/usr/bin/env python3
"""Render CLI.md from a package's own argparse definitions.

A hand-written CLI reference is wrong within two releases. This one is generated,
and a test fails if the committed file is stale — the same arrangement as
cert-atlas's leaderboard.

Run with --check in CI.
"""
from __future__ import annotations

import argparse
import importlib
import io
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

#: package -> (command, cli module, extra subcommands to render)
PACKAGES = {
    "lcert-verify": ("lcert-verify", "lcert_verify.cli", ["serve"]),
    "lcert-build": ("lcert-build", "lcert_build.cli", []),
    "equiv-receipt": ("equiv-receipt", "equiv_receipt.cli", []),
    "prereg-seal": ("prereg-seal", "prereg_seal.cli", []),
    "cert-atlas": ("cert-atlas", "cert_atlas.cli", []),
    "certified-kit": ("certified-kit", "certified_kit.cli", []),
}

#: Where a package already has a hand-written CLI.md, the generated option tables
#: go BETWEEN these markers and the prose around them is left alone. Blowing away
#: a page someone wrote in order to paste in `--help` output is a downgrade.
BEGIN = "<!-- BEGIN GENERATED CLI -->"
END = "<!-- END GENERATED CLI -->"

HEADER = """# CLI reference — `{cmd}`

**The command listings below are generated.** Run `python gen_cli_docs.py` after changing any
argument; a test fails if they are stale.

"""

FOOTER = """
## Exit codes

Every command in this toolkit uses the same taxonomy, so a caller can branch on it:

| Code | Meaning |
|---|---|
| `0` | verified / sealed / equivalent — the check was made and it stood |
| `1` | refuted by re-derivation |
| `2` | refuted on integrity: fingerprint, manifest, root, commitment |
| `3` | vacuous — nothing was certified |
| `4` | **abstained** — the evidence for an assertion is absent |
| `5` | usage error — not a verdict at all |

`4` is the one worth wiring up. It is not a failure of the artifact; it means nothing was
established, and treating it as a pass is the failure this toolkit exists to prevent.

---

*Part of [certified-oss](https://github.com/nickharris808/certified-oss).*
"""


def _help(module: str, args) -> str:
    """Capture `--help` for a command, without letting it exit the process."""
    mod = importlib.import_module(module)
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            mod.main(list(args) + ["--help"])
    except SystemExit:
        pass
    text = buf.getvalue().strip()
    if not text:
        # Some CLIs dispatch before argparse sees --help; fall back to a subprocess.
        out = subprocess.run([sys.executable, "-m", module, *args, "--help"],
                             capture_output=True, text=True)
        text = (out.stdout or out.stderr).strip()
    return text


def _subcommands(module: str):
    """Every subcommand argparse knows about, in declaration order."""
    mod = importlib.import_module(module)
    found = []

    real = argparse.ArgumentParser.parse_args

    def capture(self, args=None, namespace=None):
        for action in self._actions:
            if isinstance(action, argparse._SubParsersAction):
                found.extend(action.choices)
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = capture
    try:
        mod.main([])
    except SystemExit:
        pass
    except Exception:                          # noqa: BLE001 - best effort
        pass
    finally:
        argparse.ArgumentParser.parse_args = real
    return found


def render(pkg: str) -> str:
    cmd, module, extra = PACKAGES[pkg]
    parts = [HEADER.format(cmd=cmd), "## Top level\n\n```\n" + _help(module, []) + "\n```\n"]
    subs = _subcommands(module)
    for sub in subs:
        parts.append(f"\n## `{cmd} {sub}`\n\n```\n{_help(module, [sub])}\n```\n")
    for sub in extra:
        if sub not in subs:
            parts.append(f"\n## `{cmd} {sub}`\n\n```\n{_help(module, [sub])}\n```\n")
    parts.append(FOOTER)
    return "".join(parts)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("packages", nargs="*", default=sorted(PACKAGES))
    ap.add_argument("--check", action="store_true", help="fail if any file is stale")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent))
    ap.add_argument("--single", default="", help="this repo's package name")
    a = ap.parse_args(argv)

    stale = []
    for pkg in (a.packages or sorted(PACKAGES)):
        root = Path(a.root)
        target = (root / "CLI.md") if a.single == pkg else (root / pkg / "CLI.md")
        try:
            text = render(pkg)
        except ImportError as exc:
            print(f"  {pkg}: not importable here ({exc})")
            continue
        existing = target.read_text() if target.exists() else ""
        if BEGIN in existing and END in existing:
            # Splice into the hand-written page, keeping the prose around it.
            body = text.split("## Top level", 1)[1]
            body = "## Top level" + body.split(FOOTER.strip()[:20])[0].rstrip()
            head, rest = existing.split(BEGIN, 1)
            _, tail = rest.split(END, 1)
            text = f"{head}{BEGIN}\n\n{body}\n\n{END}{tail}"
        if a.check:
            if not target.exists() or target.read_text() != text:
                stale.append(pkg)
        else:
            target.write_text(text)
            print(f"  wrote {target} ({len(text.splitlines())} lines)")
    if stale:
        print("STALE (run python gen_cli_docs.py): " + ", ".join(stale), file=sys.stderr)
        return 1
    if a.check:
        print("every CLI.md is current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
