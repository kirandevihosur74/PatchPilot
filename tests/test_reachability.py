"""Reachability analysis: does the repo actually call the vulnerable API?"""

from patchpilot import knowledge as K
from patchpilot import reachability as R

PYYAML = {"package": "pyyaml", "vuln_id": "PYSEC-2021-142",
          "aliases": ["CVE-2020-14343"], "fix_versions": ["5.4"]}
REQUESTS = {"package": "requests", "vuln_id": "PYSEC-2018-28", "aliases": [], "fix_versions": ["2.20.0"]}
JINJA = {"package": "jinja2", "vuln_id": "PYSEC-2019-217", "aliases": [], "fix_versions": ["2.10.1"]}


def v(sources, vuln):
    return R.analyze(sources, vuln, K)


def test_vulnerable_api_called():
    r = v({"a.py": "import yaml\ndef f(t):\n    return yaml.load(t)\n"}, PYYAML)
    assert r["verdict"] == "vulnerable-api-called"
    assert r["reachable"] is True
    assert "load" in r["affected_symbols"]
    assert r["call_sites"][0]["line"] == 3


def test_imported_but_unused():
    r = v({"a.py": "import requests\nx = 1\n"}, REQUESTS)
    assert r["verdict"] == "imported-unused"
    assert r["reachable"] is False


def test_not_imported():
    assert v({"a.py": "import os\n"}, JINJA)["verdict"] == "not-imported"


def test_safe_call_is_not_a_vuln_hit():
    # safe_load is not in the affected set for this CVE -> package-called, not vuln.
    r = v({"a.py": "import yaml as y\ny.safe_load('x')\n"}, PYYAML)
    assert r["verdict"] == "package-called"
    assert r["affected_symbols"] == []


def test_from_import_direct_and_aliased():
    assert v({"a.py": "from yaml import load\nload('x')\n"}, PYYAML)["verdict"] == "vulnerable-api-called"
    r = v({"a.py": "from yaml import load as L\nL('x')\n"}, PYYAML)
    assert r["verdict"] == "vulnerable-api-called"
    assert "load" in r["affected_symbols"]


def test_unparseable_source_is_skipped():
    r = v({"bad.py": "print 'py2'\n", "good.py": "import yaml\nyaml.load('x')\n"}, PYYAML)
    assert r["verdict"] == "vulnerable-api-called"


def test_rank_puts_reachable_first():
    absent = v({"a.py": "import os"}, {"package": "idna", "vuln_id": "X", "fix_versions": ["1"]})
    called = v({"a.py": "import yaml\nyaml.load('x')"}, PYYAML)
    vulns = [
        {"package": "idna", "vuln_id": "X", "fix_versions": ["1"], "reachability": absent},
        {"package": "pyyaml", "vuln_id": "PYSEC-2021-142", "fix_versions": ["5.4"], "reachability": called},
    ]
    vulns.sort(key=R.rank_key)
    assert vulns[0]["package"] == "pyyaml"


def test_import_name_mapping():
    assert K.import_names("PyYAML") == ["yaml"]
    assert K.import_names("beautifulsoup4") == ["bs4"]
    assert "unknown_pkg" in K.import_names("unknown-pkg")  # fallback: dash -> underscore
