"""Remediation helpers: requirements pinning and repo-slug parsing."""

from patchpilot.orchestrator import Orchestrator

bump = Orchestrator._bump_pin
slug = Orchestrator._repo_slug


def test_bump_preserves_name_casing():
    # pip-audit lowercases the package name; the file keeps its original casing.
    out = bump("PyYAML==5.3.1\nfastapi\n", "pyyaml", "6.0.3")
    assert "PyYAML==6.0.3" in out
    assert "fastapi" in out  # untouched


def test_bump_handles_any_comparator():
    assert bump("requests>=2.19.0\n", "requests", "2.32.0") == "requests==2.32.0\n"
    assert bump("jinja2 ~= 2.10\n", "jinja2", "3.1.6").strip() == "jinja2 ==3.1.6"


def test_bump_leaves_unrelated_lines():
    src = "flask==1.0\nrequests==2.19.0\n"
    out = bump(src, "requests", "2.32.0")
    assert "flask==1.0" in out and "requests==2.32.0" in out


def test_bump_no_match_is_noop():
    src = "flask==1.0\n"
    assert bump(src, "requests", "2.32.0") == src


def test_repo_slug_parses_github_urls():
    assert slug("https://github.com/owner/name") == "owner/name"
    assert slug("https://github.com/owner/name/") == "owner/name"
    assert slug("https://github.com/owner/name.git") == "owner/name"
    assert slug("git@github.com:owner/name.git") == "owner/name"
    assert slug("https://gitlab.com/owner/name") == ""  # only GitHub
    assert slug("") == ""
