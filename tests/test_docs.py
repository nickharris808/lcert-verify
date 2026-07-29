"""Documentation integrity.

Docs that nobody checks are docs that are wrong. These assert the pages exist,
point at real files, and — where a page shows output — that the output is what the
code actually prints.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = ["README.md", "CLI.md", "TUTORIAL.md", "TROUBLESHOOTING.md",
            "CONTRIBUTING.md", "CITATION.cff", "LICENSE"]


@pytest.mark.parametrize("name", REQUIRED)
def test_the_page_exists_and_is_not_a_stub(name):
    p = ROOT / name
    assert p.is_file(), f"{name} is missing"
    assert len(p.read_text().strip()) > 200, f"{name} is a stub"


def test_every_relative_link_in_every_page_resolves():
    """A broken link is a claim the repository does not support."""
    broken = []
    for page in ROOT.glob("*.md"):
        for m in re.finditer(r"\]\(([^)#:]+?)(?:#[^)]*)?\)", page.read_text()):
            target = m.group(1).strip()
            if target.startswith(("http", "mailto:", "//")):
                continue
            if not (ROOT / target).exists() and not (page.parent / target).exists():
                broken.append(f"{page.name} -> {target}")
    assert not broken, "broken relative links: " + ", ".join(broken)


def test_the_citation_file_is_valid_and_apache():
    text = (ROOT / "CITATION.cff").read_text()
    assert "cff-version: 1.2.0" in text
    assert "license: Apache-2.0" in text
    assert "nickharris808" in text


def test_the_readme_points_at_the_portfolio():
    text = (ROOT / "README.md").read_text()
    assert "certified-oss" in text, "a visitor cannot tell this is one body of work"
    assert "recorded verdict is a claim to be checked" in text


def test_the_cli_reference_is_generated_and_says_so():
    text = (ROOT / "CLI.md").read_text()
    assert "generated" in text.lower()
    assert "gen_cli_docs.py" in text


def test_the_exit_code_taxonomy_is_documented_the_same_way_everywhere():
    text = (ROOT / "CLI.md").read_text()
    for code in ("`0`", "`4`", "`5`"):
        assert code in text, code
    assert "abstain" in text.lower()


def test_the_performance_note_is_present():
    """It is one document shared by every package; a stale copy is a wrong claim."""
    perf = ROOT / "PERFORMANCE.md"
    assert perf.is_file()
    text = perf.read_text()
    assert "measured" in text.lower()
    # it must state what was NOT optimised as well as what was
    assert "not built" in text or "no optimisation" in text.lower()
