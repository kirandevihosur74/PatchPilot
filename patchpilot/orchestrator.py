"""The loop. Idempotent nodes over a RunState; everything dangerous runs in a
sandbox. isolate (Daytona) -> generate (Fireworks) -> evaluate (Braintrust)
-> review (CodeRabbit, in vcs.py).
"""

from __future__ import annotations

import re
import shlex
import uuid

from . import knowledge, reachability, scanner
from .config import Config, load_config
from .evals import Tracer
from .llm import LLM
from .sandbox import make_sandbox
from .state import Node, RunState, TestResult

# Files the agent is allowed to repair (the app), never the attack script.
NON_FIXABLE = {"exploit.py"}


class Orchestrator:
    def __init__(self, config: Config | None = None, on_event=None, repo_url: str = "") -> None:
        self.config = config or load_config()
        self.on_event = on_event  # live subscriber (web dashboard); called per event
        self.repo_url = repo_url  # the pasted GitHub URL (product path)
        self.llm = LLM(self.config)
        self.tracer = Tracer(self.config)

    # --- entry point ---
    def run(self) -> RunState:
        cfg = self.config
        source = self.repo_url or cfg.target_path
        state = RunState(
            run_id=uuid.uuid4().hex[:8],
            target_path=source,
            repo_url=self.repo_url,
            max_iterations=cfg.max_fix_iterations,
        )
        if self.on_event:
            state.on_event = self.on_event
        print(cfg.summary())
        print(f"\n=== PatchPilot run {state.run_id} on {source} ===\n")

        sb = make_sandbox(cfg, label="scan")
        try:
            with self.tracer.span("patchpilot_run", type="task") as root:
                root.log(input={"target": source})

                self._ingest(state, sb, source)
                self._scan(state, sb)
                if state.vulns:
                    self._analyze(state, sb)
                    self._select_target(state)
                    if (state.target_vuln or {}).get("ecosystem") == "npm":
                        state.log(Node.ANALYZE,
                                  "npm remediation isn't supported yet — detection + reachability only")
                    else:
                        self._remediate(state, sb)
                        if not state.escalated and self.config.has_github and state.changed_paths:
                            self._review(state, sb)
                    self._preview(state, sb)
                else:
                    state.log(Node.SCAN, "no known-vulnerable dependencies found — nothing to remediate")

                state.node = Node.ESCALATE if state.escalated else Node.DONE
                root.log(output=state.to_dict())
        finally:
            # Keep the sandbox alive when a preview is published so its link stays
            # reachable; Daytona auto-stops/deletes it on the configured intervals.
            if not state.preview_url:
                sb.stop()

        self._print_summary(state)
        return state

    # --- 1. INGEST: clone the target repo into a fresh sandbox ---
    def _ingest(self, state: RunState, sb, source: str) -> None:
        state.node = Node.INGEST
        is_url = source.startswith(("http://", "https://", "git@"))
        with self.tracer.span("ingest") as span:
            state.log(Node.INGEST, f"spinning up sandbox ({sb.label})")
            sb.start()
            state.log(Node.INGEST, f"{'cloning repo' if is_url else 'loading local repo'}: {source}")
            sb.load_repo(source)
            state.log(Node.INGEST, "preparing scan environment")
            sb.setup(requirements=None)  # bare env — scanner installs its own tooling
            span.log(input={"source": source}, metadata={"node": "ingest"})

    # --- 2. SCAN: discover manifests + run the real scanner ---
    def _scan(self, state: RunState, sb) -> None:
        state.node = Node.SCAN
        with self.tracer.span("scan") as span:
            state.manifests = scanner.discover_manifests(sb)
            vulns = scanner.scan(sb, manifests=state.manifests,
                                 log=lambda m: state.log(Node.SCAN, m))
            state.vulns = vulns
            # One structured event carrying the full list for the UI to render.
            state.log(Node.SCAN, f"{len(vulns)} vulnerable dependenc(y/ies) found", vulns=vulns)
            span.log(output={"count": len(vulns), "manifests": state.manifests},
                     metadata={"node": "scan"})

    # --- 3. ANALYZE: reachability — is the vulnerable API actually called? ---
    def _analyze(self, state: RunState, sb) -> None:
        state.node = Node.ANALYZE
        with self.tracer.span("analyze") as span:
            ecosystems = {v.get("ecosystem", "PyPI") for v in state.vulns}
            py_sources = self._repo_sources(sb) if "PyPI" in ecosystems else {}
            js_sources = self._repo_sources_js(sb) if "npm" in ecosystems else {}
            total = len(py_sources) + len(js_sources)
            state.log(Node.ANALYZE, f"analyzing reachability across {total} source file(s)")
            for v in state.vulns:
                if v.get("ecosystem") == "npm":
                    v["reachability"] = reachability.analyze_js(js_sources, v)
                else:
                    v["reachability"] = reachability.analyze(py_sources, v, knowledge)
            state.vulns.sort(key=reachability.rank_key)
            reached = sum(1 for v in state.vulns if (v.get("reachability") or {}).get("reachable"))
            # Re-emit the ranked, reachability-annotated list for the UI.
            state.log(Node.ANALYZE, f"{reached}/{len(state.vulns)} reachable in this repo's code",
                      vulns=state.vulns)
            span.log(output={"reachable": reached, "total": len(state.vulns)},
                     metadata={"node": "analyze"})

    def _repo_sources(self, sb, max_files: int = 600, max_bytes: int = 200_000) -> dict[str, str]:
        """Pull the repo's own .py source text out of the sandbox for AST analysis.
        Skips vendored/venv/cache dirs; bounded so a huge repo can't run away."""
        listing = sb.exec(
            "find . -type f -name '*.py' "
            r"\( -path './.sbvenv/*' -o -path '*/site-packages/*' -o -path './.git/*' "
            r"-o -path '*/node_modules/*' -o -path '*/.venv/*' -o -path '*/venv/*' \) -prune "
            r"-o -type f -name '*.py' -print"
        ).output
        sources: dict[str, str] = {}
        for raw in listing.splitlines():
            name = raw.strip().removeprefix("./")
            if not name or len(sources) >= max_files:
                continue
            try:
                text = sb.read_file(name)
            except Exception:
                continue
            if len(text) <= max_bytes:
                sources[name] = text
        return sources

    def _repo_sources_js(self, sb, max_files: int = 800, max_bytes: int = 200_000) -> dict[str, str]:
        """Pull the repo's JS/TS source text for import-level reachability.
        Skips node_modules and build output; bounded like the Python reader."""
        listing = sb.exec(
            r"find . -type f \( -path '*/node_modules/*' -o -path './.git/*' "
            r"-o -path '*/dist/*' -o -path '*/build/*' \) -prune "
            r"-o -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' "
            r"-o -name '*.mjs' -o -name '*.cjs' \) -print"
        ).output
        sources: dict[str, str] = {}
        for raw in listing.splitlines():
            name = raw.strip().removeprefix("./")
            if not name or len(sources) >= max_files:
                continue
            try:
                text = sb.read_file(name)
            except Exception:
                continue
            if len(text) <= max_bytes:
                sources[name] = text
        return sources

    # --- select the vuln to remediate (top of the reachability ranking) ---
    def _select_target(self, state: RunState) -> None:
        tv = state.vulns[0]
        state.target_vuln = tv
        state.package = tv["package"]
        state.installed_version = tv["installed_version"]
        state.cve_id = tv["vuln_id"]
        # Data-driven: the advisory's fix version for THIS package, or empty so
        # _upgrade escalates. (A global configured version can't be right across
        # arbitrary packages/ecosystems, so it isn't used here.)
        state.patched_version = tv["fix_versions"][0] if tv.get("fix_versions") else ""
        reach = tv.get("reachability") or {}
        # The "reachable" beat: proven reachable in this repo's own code.
        state.goals.exploit_proven = bool(reach.get("reachable"))
        verdict = reach.get("verdict", "unknown")
        state.log(Node.ANALYZE,
                  f"target: {tv['package']} {tv['installed_version']} → {tv['vuln_id']} "
                  f"[{verdict}] (fix {state.patched_version or 'none available'})")

    # --- PREVIEW: serve the findings from inside the real Daytona sandbox ---
    PREVIEW_PORT = 8420

    def _preview(self, state: RunState, sb) -> None:
        if not self.config.has_daytona:
            return  # real preview is a Daytona feature; local mode has none
        state.node = Node.PREVIEW
        with self.tracer.span("preview") as span:
            try:
                state.log(Node.PREVIEW, "publishing findings to the sandbox preview")
                sb.exec("mkdir -p .patchpilot_preview")
                sb.write_file(".patchpilot_preview/index.html", self._evidence_html(state))
                sb.serve(self.PREVIEW_PORT, cwd_rel=".patchpilot_preview")
                url, token = sb.get_preview_url(self.PREVIEW_PORT)
                if url:
                    state.preview_url, state.preview_token = url, token or ""
                    state.log(Node.PREVIEW, "sandbox preview is live", preview_url=url)
                else:
                    state.log(Node.PREVIEW, "preview link unavailable")
            except Exception as exc:  # a preview miss must never fail the run
                state.log(Node.PREVIEW, f"preview skipped ({type(exc).__name__})")
            span.log(output={"preview_url": state.preview_url}, metadata={"node": "preview"})

    @staticmethod
    def _evidence_html(state: RunState) -> str:
        from html import escape

        def badge(v):
            r = v.get("reachability") or {}
            return escape(r.get("verdict", "—"))

        rows = []
        for v in state.vulns:
            r = v.get("reachability") or {}
            sites = "".join(
                f"<div class='site'>{escape(s['file'])}:{s['line']}</div>"
                for s in (r.get("call_sites") or [])[:4]
            )
            fix = escape(v["fix_versions"][0]) if v.get("fix_versions") else "—"
            reachable = (r.get("verdict") == "vulnerable-api-called")
            rows.append(
                f"<tr class='{'hot' if reachable else ''}'>"
                f"<td><b>{escape(v['package'])}</b> <span class='ver'>{escape(v['installed_version'])}</span></td>"
                f"<td>{escape(v['vuln_id'])}</td>"
                f"<td><span class='badge'>{badge(v)}</span>{sites}</td>"
                f"<td>{fix}</td></tr>"
            )
        reached = sum(1 for v in state.vulns if (v.get("reachability") or {}).get("reachable"))
        return (
            "<!doctype html><meta charset='utf-8'><title>PatchPilot — findings</title>"
            "<style>body{background:#0d0d12;color:#aeaac0;font:15px/1.5 -apple-system,system-ui,sans-serif;"
            "margin:0;padding:40px}h1{color:#dad7de;font-weight:500}.sub{color:#62626f;margin-bottom:24px}"
            "table{width:100%;border-collapse:collapse;font-size:14px}th{text-align:left;color:#62626f;"
            "text-transform:uppercase;font-size:12px;padding:10px 12px;border-bottom:1px solid #31313a}"
            "td{padding:12px;border-bottom:1px solid #1c1c22;vertical-align:top}.ver{color:#62626f}"
            ".badge{display:inline-block;font-size:12px;border:1px solid #31313a;border-radius:3px;"
            "padding:2px 7px;color:#aeaac0}tr.hot .badge{border-color:#ab8ff1;color:#ab8ff1}"
            ".site{color:#62626f;font-size:12px;margin-top:4px;font-family:ui-monospace,monospace}</style>"
            f"<h1>PatchPilot findings</h1><div class='sub'>{escape(state.repo_url or state.target_path)} · "
            f"{len(state.vulns)} vulnerable dependencies · {reached} reachable in this code</div>"
            "<table><tr><th>Package</th><th>Advisory</th><th>Reachability</th><th>Fix</th></tr>"
            + "".join(rows) + "</table>"
            "<p class='sub' style='margin-top:24px'>Served live from the isolated Daytona sandbox.</p>"
        )

    # --- UPGRADE: move the target package to an installable fixed version ---
    def _upgrade(self, state: RunState, sb) -> None:
        if not state.patched_version:
            self._escalate(state, f"no fix version is available for {state.cve_id}")
            return
        state.node = Node.UPGRADE
        with self.tracer.span("upgrade") as span:
            pkg, target = state.package, state.patched_version
            # Prefer the advisory's exact fix; if it won't build/install on this
            # Python (older pins often don't), fall back to the newest release >= fix.
            r = sb.exec(f"{sb.py()} -m pip install {shlex.quote(f'{pkg}=={target}')}")
            if r.exit_code != 0:
                state.log(Node.UPGRADE,
                          f"{pkg}=={target} won't install here — moving to the newest release ≥ {target}")
                r2 = sb.exec(f"{sb.py()} -m pip install --upgrade {shlex.quote(f'{pkg}>={target}')}")
                if r2.exit_code != 0:
                    self._escalate(state, f"could not install a fixed {pkg} (>= {target}) in this environment")
                    span.log(output={"error": "install failed"}, metadata={"node": "upgrade"})
                    return
            resolved = self._installed_version(sb, pkg) or target
            state.patched_version = resolved

            changed: list[str] = []
            for m in state.manifests:
                if not m.lower().endswith(".txt"):
                    continue  # v1 edits requirements files; other manifests: install-only
                try:
                    content = sb.read_file(m)
                except Exception:
                    continue
                bumped = self._bump_pin(content, pkg, resolved)
                if bumped != content:
                    sb.write_file(m, bumped)
                    changed.append(m)
            # Install the repo's full deps (against the bumped pin) + pytest so the suite can run.
            for m in state.manifests:
                if m.lower().endswith(".txt"):
                    sb.exec(f"{sb.py()} -m pip install -r {shlex.quote(m)}")
            sb.exec(f"{sb.py()} -m pip install --quiet pytest")
            for c in changed:
                if c not in state.changed_paths:
                    state.changed_paths.append(c)
            state.log(Node.UPGRADE, f"upgraded {pkg} → {resolved}"
                      + (f" (pinned in {', '.join(changed)})" if changed else " (pin not in a requirements file)"))
            span.log(output={"changed": changed, "version": resolved}, metadata={"node": "upgrade"})

    @staticmethod
    def _installed_version(sb, pkg: str) -> str:
        out = sb.exec(f"{sb.py()} -m pip show {shlex.quote(pkg)}").output
        m = re.search(r"(?im)^Version:\s*(.+)$", out)
        return m.group(1).strip() if m else ""

    @staticmethod
    def _bump_pin(content: str, pkg: str, version: str) -> str:
        """Pin `pkg` to `version` in a requirements file, preserving the original
        name casing. Matches any comparator (==, >=, ~=, …); leaves other lines alone."""
        pat = re.compile(rf"(?im)^(\s*)({re.escape(pkg)})(\s*)(==|>=|~=|<=|!=|<|>)([^\n#]*)")
        return pat.sub(rf"\1\2\g<3>=={version}", content)

    # --- OBSERVE / FIX / VERIFY (or the honest no-tests path) ---
    def _remediate(self, state: RunState, sb) -> None:
        self._upgrade(state, sb)
        if state.escalated:
            return
        status, tr = self._run_tests(state, sb, Node.OBSERVE)
        if status == "none":
            state.has_tests = False
            state.goals.tests_green = None  # not applicable
            ok = self._import_smoke(state, sb)
            state.log(Node.OBSERVE,
                      "no runnable test suite — verified the repo's modules still import"
                      if ok else "no runnable test suite — some modules fail to import (flagged in the PR)")
        else:
            state.has_tests = True
            state.tests = tr
            if tr.all_green:
                state.goals.tests_green = True
                state.log(Node.OBSERVE, "suite still green after the upgrade — no breakage to repair")
            else:
                state.log(Node.OBSERVE, f"pytest: {tr.passed} passed, {tr.failed} failed, {tr.errors} error(s)")
                self._repair(state, sb, tr)
        if not state.escalated:
            self._guard(state, sb)
        if not state.escalated:
            self._reprove(state, sb)

    def _repair(self, state: RunState, sb, tr: TestResult) -> None:
        while state.iteration < state.max_iterations:
            state.iteration += 1
            self._fix(state, sb, tr)
            status, tr = self._run_tests(state, sb, Node.VERIFY)
            state.tests = tr
            if status != "none" and tr.all_green:
                state.goals.tests_green = True
                state.log(Node.VERIFY, f"suite green after {state.iteration} iteration(s)")
                return
            state.log(Node.VERIFY, f"still failing after iteration {state.iteration}")
        self._escalate(state, f"tests still failing after {state.max_iterations} fix iterations")

    def _fix(self, state: RunState, sb, tr: TestResult) -> None:
        state.node = Node.FIX
        with self.tracer.span("fix") as span:
            files = self._fix_candidates(state, sb, tr)
            changed = self.llm.generate_fix(files, tr.raw) if files else {}
            for name, content in changed.items():
                sb.write_file(name, content)
                state.fixes_applied.append({"file": name, "iteration": str(state.iteration)})
                if name not in state.changed_paths:
                    state.changed_paths.append(name)
            state.log(Node.FIX, f"iteration {state.iteration}: patched {', '.join(changed) or '(no change)'}"
                      + ("" if self.llm.online else " [offline fix]"))
            span.log(input={"failure": tr.raw[:2000]}, output={"changed": list(changed)},
                     metadata={"node": "fix", "iteration": state.iteration, "online": self.llm.online})

    # --- GUARD: did the fix weaken security? (generalized per package) ---
    def _guard(self, state: RunState, sb) -> None:
        state.node = Node.GUARD
        with self.tracer.span("guard") as span:
            patterns = knowledge.guard_patterns(state.package)
            weakened: list[str] = []
            if patterns:
                for p in state.changed_paths:
                    if not p.endswith(".py"):
                        continue
                    try:
                        content = sb.read_file(p)
                    except Exception:
                        continue
                    if any(re.search(pat, content) for pat in patterns):
                        weakened.append(p)
            ok = not weakened
            if not patterns:
                detail = f"no package-specific regression rule for {state.package}; relying on tests + re-scan"
            elif ok:
                detail = f"security preserved — no unsafe {state.package} pattern in the patch"
            else:
                detail = f"fix weakened security in {', '.join(weakened)}"
            state.security_eval = {"ok": ok, "detail": detail, "score": 1.0 if ok else 0.0}
            state.log(Node.GUARD, f"security eval: {detail}")
            span.log(output=state.security_eval,
                     scores={"security_preservation": state.security_eval["score"]},
                     metadata={"node": "guard"})
            if not ok:
                state.goals.cve_resolved = False
                self._escalate(state, f"fix weakened security: {detail}")

    # --- RE-PROVE: re-scan to confirm the advisory is gone ---
    def _reprove(self, state: RunState, sb) -> None:
        state.node = Node.REPROVE
        with self.tracer.span("reprove") as span:
            vulns = scanner.scan(sb, manifests=state.manifests, log=None)
            pkg, vid = state.package.lower(), state.cve_id
            still = any(v["vuln_id"] == vid and v["package"].lower() == pkg for v in vulns)
            cleared = not still
            state.goals.exploit_blocked = cleared
            state.goals.cve_resolved = cleared and (state.security_eval or {}).get("ok", True)
            state.exploit_evidence_after = ("re-scan: advisory no longer reported"
                                            if cleared else "re-scan: advisory still present")
            state.log(Node.REPROVE, f"re-scan: {vid} {'cleared — vulnerability gone' if cleared else 'STILL PRESENT'}")
            span.log(output={"cleared": cleared}, scores={"cve_dead": 1.0 if cleared else 0.0},
                     metadata={"node": "reprove"})
            if not cleared:
                self._escalate(state, f"{vid} still present after upgrade")

    # --- REVIEW: open a PR on the pasted repo (honest escalation w/o push access) ---
    def _review(self, state: RunState, sb) -> None:
        from .vcs import GitHubClient

        repo = self._repo_slug(state.repo_url) or self.config.github_repo
        # The service token can write; only let it target allowed owners so a
        # pasted repo_url can't aim a PR (or merge) at an arbitrary repository.
        owner = repo.split("/")[0].lower() if "/" in repo else ""
        allowed = self.config.allowed_owners()
        if allowed and owner not in allowed:
            self._escalate(state,
                           f"PR target {repo} is outside the allowed owners "
                           f"({', '.join(sorted(allowed))}) — writes are restricted to protect the token")
            return
        files: dict[str, str] = {}
        for p in state.changed_paths:
            try:
                files[p] = sb.read_file(p)
            except Exception:
                pass
        if not files:
            return
        branch = f"patchpilot/{re.sub(r'[^a-z0-9.-]+', '-', state.cve_id.lower())}-{state.run_id}"
        title = (f"PatchPilot: fix {state.cve_id} in {state.package} "
                 f"({state.installed_version} -> {state.patched_version})")
        body = self._pr_body(state)
        state.node = Node.SUBMIT
        with self.tracer.span("submit") as span:
            try:
                gh = GitHubClient(self.config, repo=repo)
                pr = gh.open_pr(branch, title, body, files)
            except Exception as exc:
                self._escalate(state,
                               f"patch is ready but couldn't open a PR on {repo} ({type(exc).__name__}) — "
                               f"likely no push access; a fork-based flow is the next step")
                span.log(output={"error": str(exc)}, metadata={"node": "submit"})
                return
            state.pr_url, state.pr_number = pr.url, pr.number
            try:
                gh.comment(pr.number, "@coderabbitai review")
            except Exception:
                pass
            state.log(Node.SUBMIT, f"opened PR {pr.url}")
            span.log(output={"pr": pr.url}, metadata={"node": "submit"})

        if self.config.auto_merge:
            self._gate_and_merge(state, gh, pr)
        else:
            state.log(Node.GATE, f"PR open — awaiting tests + CodeRabbit review: {pr.url}")

    def _gate_and_merge(self, state: RunState, gh, pr) -> None:
        state.node = Node.GATE
        gate = gh.poll_gate(pr.number, pr.head_sha, timeout_s=300)
        state.tests_check_ok, state.review_ok = gate["tests_ok"], gate["review_ok"]
        state.log(Node.GATE, f"gate: tests_ok={gate['tests_ok']} review_ok={gate['review_ok']}")
        if state.tests_check_ok and state.review_ok:
            state.node = Node.MERGE
            state.merged = gh.merge(pr.number)
            state.log(Node.MERGE, "merged (tests + CodeRabbit both green)" if state.merged else "merge call failed")
        elif gate.get("changes_requested"):
            self._escalate(state, f"CodeRabbit requested changes on {pr.url} — human review needed")
        else:
            state.log(Node.GATE, f"gate not yet green — PR left open for review: {pr.url}")

    def _pr_body(self, state: RunState) -> str:
        r = (state.target_vuln or {}).get("reachability") or {}
        sites = ", ".join(f"`{s['file']}:{s['line']}`" for s in (r.get("call_sites") or [])[:5]) or "n/a"
        if state.has_tests is False:
            tests = "no runnable suite in a clean checkout — imports verified"
        elif state.goals.tests_green:
            tests = f"green after repair ({state.iteration} iteration(s))" if state.iteration else "green (no breakage)"
        else:
            tests = "see run log"
        return (
            f"Automated patch by **PatchPilot**.\n\n"
            f"- **Advisory:** {state.cve_id} in `{state.package}=={state.installed_version}`\n"
            f"- **Reachability:** {r.get('verdict', 'unknown')} — {sites}\n"
            f"- **Upgrade:** `{state.package}` -> `{state.patched_version}`\n"
            f"- **Repair:** {len(state.fixes_applied)} file(s) over {state.iteration} iteration(s)\n"
            f"- **Security:** {state.security_eval['detail'] if state.security_eval else 'n/a'}\n"
            f"- **Tests:** {tests}\n"
            f"- **Re-scan:** advisory {'cleared' if state.goals.exploit_blocked else 'still present'}\n\n"
            f"The agent that wrote this patch does not approve it — merge gates on tests + CodeRabbit."
        )

    # --- helpers ---
    def _run_tests(self, state: RunState, sb, node: Node):
        """Return (status, TestResult). status is 'ran' or 'none' (no suite collected)."""
        state.node = node
        sb.exec(f"{sb.py()} -m pip install --quiet pytest")
        res = sb.exec(f"{sb.py()} -m pytest -q --tb=short")
        if res.exit_code == 5:  # pytest exit code 5 = no tests collected
            return "none", TestResult(raw=res.output)
        tr = self._parse_pytest(res.output)
        tr.raw = res.output
        return "ran", tr

    def _fix_candidates(self, state: RunState, sb, tr: TestResult) -> dict[str, str]:
        """Source files worth sending to the fixer: those named in the failing
        traceback plus the reachability call sites. Bounded; never library code."""
        paths: list[str] = []
        for m in re.finditer(r"([\w./-]+\.py):\d+", tr.raw or ""):
            p = m.group(1).lstrip("./")
            if p and "site-packages" not in p and ".sbvenv" not in p and not p.startswith("/"):
                paths.append(p)
        for s in ((state.target_vuln or {}).get("reachability") or {}).get("call_sites", []):
            paths.append(s["file"])
        files: dict[str, str] = {}
        for p in paths:
            if p in files or p in NON_FIXABLE or len(files) >= 8:
                continue
            try:
                files[p] = sb.read_file(p)
            except Exception:
                pass
        return files

    def _import_smoke(self, state: RunState, sb) -> bool:
        """No-tests fallback: do the repo's top-level modules still import after the
        upgrade? Runs inside the sandbox (executes import-time code safely there)."""
        script = (
            "import sys, importlib, pathlib\n"
            "sys.path.insert(0, '.')\n"
            "mods=set()\n"
            "for p in pathlib.Path('.').iterdir():\n"
            "  if p.suffix=='.py' and p.stem not in ('setup','conftest'): mods.add(p.stem)\n"
            "  elif p.is_dir() and (p/'__init__.py').exists(): mods.add(p.name)\n"
            "bad=[]\n"
            "for m in sorted(mods):\n"
            "  try: importlib.import_module(m)\n"
            "  except Exception as e: bad.append(m+':'+type(e).__name__)\n"
            "print('SMOKE_BAD='+';'.join(bad))\n"
        )
        res = sb.exec(f"{sb.py()} -c {shlex.quote(script)}")
        m = re.search(r"SMOKE_BAD=(.*)", res.output)
        return bool(m) and not m.group(1).strip()

    @staticmethod
    def _repo_slug(url: str) -> str:
        m = re.search(r"github\.com[:/]+([\w.-]+/[\w.-]+?)(?:\.git)?/?$", url or "")
        return m.group(1) if m else ""

    def _escalate(self, state: RunState, reason: str) -> None:
        state.escalated = True
        state.escalation_reason = reason
        state.node = Node.ESCALATE
        state.log(Node.ESCALATE, f"ESCALATE — {reason}")

    @staticmethod
    def _parse_pytest(output: str) -> TestResult:
        def n(word: str) -> int:
            m = re.search(rf"(\d+) {word}", output)
            return int(m.group(1)) if m else 0
        passed, failed, errors = n("passed"), n("failed"), n("error")
        # A collection error shows up without a normal summary line.
        if errors == 0 and failed == 0 and ("error" in output.lower() and "Interrupted" in output):
            errors = 1
        return TestResult(passed=passed, failed=failed, errors=errors)

    def _print_summary(self, state: RunState) -> None:
        print("\n" + "=" * 68)
        print(f"  RUN {state.run_id}  ({'ESCALATED' if state.escalated else 'COMPLETE'})")
        print("  " + state.goals.render())
        if state.escalated:
            print(f"  escalation: {state.escalation_reason}")
        print("=" * 68)
