"""Preview: local mode has no sandbox preview; the evidence page renders findings."""

from patchpilot.orchestrator import Orchestrator
from patchpilot.sandbox import LocalSandbox
from patchpilot.state import RunState


def test_local_sandbox_has_no_preview():
    sb = LocalSandbox()
    assert sb.get_preview_url(8420) == (None, None)
    assert sb.serve(8420) is None


def test_evidence_html_renders_findings_and_escapes():
    state = RunState(run_id="t1", target_path="x", repo_url="https://github.com/o/<b>r</b>")
    state.vulns = [{
        "package": "pyyaml", "installed_version": "5.3.1", "vuln_id": "PYSEC-2021-142",
        "fix_versions": ["5.4"], "severity": "",
        "reachability": {"verdict": "vulnerable-api-called", "reachable": True,
                         "call_sites": [{"file": "parser.py", "line": 19, "snippet": ""}]},
    }]
    html = Orchestrator._evidence_html(state)
    assert "PatchPilot findings" in html
    assert "pyyaml" in html and "PYSEC-2021-142" in html
    assert "vulnerable-api-called" in html
    assert "parser.py:19" in html
    # repo_url is HTML-escaped, not injected raw
    assert "<b>r</b>" not in html
    assert "&lt;b&gt;r&lt;/b&gt;" in html
