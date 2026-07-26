"""Scanner: parsing pip-audit output into ranked Vulnerability records."""

import json

from patchpilot.scanner import _dedupe_and_rank, _parse_pip_audit, _requirements_files

AUDIT = {
    "dependencies": [
        {"name": "pyyaml", "version": "5.3.1", "vulns": [
            {"id": "PYSEC-2021-142", "fix_versions": ["5.4"], "aliases": ["CVE-2020-14343"],
             "description": "FullLoader RCE bypass\nsecond line dropped"}]},
        {"name": "fastapi", "version": "0.100.0", "vulns": []},
        {"name": "requests", "version": "2.19.0", "vulns": [
            {"id": "PYSEC-2018-28", "fix_versions": [], "aliases": ["CVE-2018-18074"],
             "description": "credential leak"}]},
    ]
}


def _blob():
    # Mimic the mixed stdout/stderr a sandbox returns around the JSON.
    return "WARNING: pip old wrapper\n" + json.dumps(AUDIT) + "\n\x1b[?25h done"


def test_parses_only_vulnerable_deps():
    vulns = _parse_pip_audit(_blob(), manifest="requirements.txt")
    names = {v["package"] for v in vulns}
    assert names == {"pyyaml", "requests"}  # fastapi has no vulns


def test_summary_is_first_line_only():
    vulns = _parse_pip_audit(_blob())
    py = next(v for v in vulns if v["package"] == "pyyaml")
    assert "second line" not in py["summary"]
    assert py["fix_versions"] == ["5.4"]
    assert "CVE-2020-14343" in py["aliases"]


def test_garbage_and_empty_are_safe():
    assert _parse_pip_audit("not json") == []
    assert _parse_pip_audit("") == []


def test_dedupe_and_rank_fixable_first():
    vulns = _parse_pip_audit(_blob())
    ranked = _dedupe_and_rank(vulns + vulns)  # duplicates collapse
    assert len(ranked) == 2
    assert ranked[0]["package"] == "pyyaml"  # has a fix -> ranks first


def test_requirements_file_detection():
    manifests = ["requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock"]
    assert _requirements_files(manifests) == ["requirements.txt", "requirements-dev.txt"]
