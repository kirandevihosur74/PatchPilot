"""npm support: package-lock parsing, OSV record mapping, JS reachability."""

from patchpilot import reachability as R
from patchpilot.scanner import _osv_to_vuln, _parse_package_lock


def test_parse_package_lock_v3():
    data = {"lockfileVersion": 3, "packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.11"},
        "node_modules/@babel/core": {"version": "7.0.0"},
    }}
    pairs = _parse_package_lock(data)
    assert ("lodash", "4.17.11") in pairs
    assert ("@babel/core", "7.0.0") in pairs
    assert ("app", "1.0.0") not in pairs  # root project excluded


def test_parse_package_lock_v1_nested():
    data = {"lockfileVersion": 1, "dependencies": {
        "minimist": {"version": "1.2.0", "dependencies": {"nested": {"version": "0.1.0"}}},
    }}
    pairs = _parse_package_lock(data)
    assert ("minimist", "1.2.0") in pairs and ("nested", "0.1.0") in pairs


def test_osv_to_vuln_prefers_cve_and_extracts_fix():
    osv = {
        "id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"],
        "summary": "Prototype pollution in lodash\nsecond line dropped",
        "severity": [{"type": "CVSS_V3", "score": "7.4"}],
        "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}],
    }
    rec = _osv_to_vuln(osv, "lodash", "4.17.11", "package-lock.json")
    assert rec["vuln_id"] == "CVE-2020-8203"       # CVE alias preferred as display id
    assert "GHSA-p6mc-m468-83gw" in rec["aliases"]  # ghsa kept as alias
    assert rec["fix_versions"] == ["4.17.19"]
    assert rec["severity"] == "7.4" and rec["ecosystem"] == "npm"
    assert "second line" not in rec["summary"]


def _js(sources, pkg):
    return R.analyze_js(sources, {"package": pkg})


def test_js_import_forms_are_reachable():
    for src in ("import _ from 'lodash'\n", "const _ = require('lodash')\n",
                "import 'lodash/fp'\n", "const x = await import('lodash')\n"):
        assert _js({"a.js": src}, "lodash")["verdict"] == "package-imported"


def test_js_scoped_package_and_line():
    assert _js({"a.tsx": "import x from '@babel/core'\n"}, "@babel/core")["verdict"] == "package-imported"
    r = _js({"src/app.ts": "x\nimport _ from 'lodash'\n"}, "lodash")
    assert r["reachable"] is True and r["call_sites"][0]["line"] == 2


def test_js_not_imported_and_no_substring_false_positive():
    assert _js({"a.js": "const y=1\n"}, "lodash")["verdict"] == "not-imported"
    # 'lodashers' must not match a scan for 'lodash'
    assert _js({"a.js": "import x from 'lodashers'\n"}, "lodash")["verdict"] == "not-imported"
