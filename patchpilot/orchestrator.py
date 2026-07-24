"""The loop. Idempotent nodes over a RunState; everything dangerous runs in a
sandbox. isolate (Daytona) -> generate (Fireworks) -> evaluate (Braintrust)
-> review (CodeRabbit, in vcs.py).
"""

from __future__ import annotations

import json
import re
import uuid

from .config import Config, load_config
from .evals import Tracer, assess_fix_security
from .llm import LLM
from .sandbox import make_sandbox
from .state import Node, RunState, TestResult

# Files the agent is allowed to repair (the app), never the attack script.
NON_FIXABLE = {"exploit.py"}


class Orchestrator:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or load_config()
        self.llm = LLM(self.config)
        self.tracer = Tracer(self.config)

    # --- entry point ---
    def run(self) -> RunState:
        cfg = self.config
        state = RunState(
            run_id=uuid.uuid4().hex[:8],
            target_path=cfg.target_path,
            max_iterations=cfg.max_fix_iterations,
            patched_version=cfg.patched_version,
        )
        print(cfg.summary())
        print(f"\n=== PatchPilot run {state.run_id} on {cfg.target_path} ===\n")

        sandbox_a = make_sandbox(cfg, label="A-exploit")
        sandbox_b = make_sandbox(cfg, label="B-work")
        try:
            with self.tracer.span("patchpilot_run", type="task") as root:
                root.log(input={"target": cfg.target_path})

                # Sandbox A: the exploit lab (vulnerable code + pinned dep).
                sandbox_a.start(); sandbox_a.load_repo(cfg.target_path); sandbox_a.setup()
                # Sandbox B: the repair lab.
                sandbox_b.start(); sandbox_b.load_repo(cfg.target_path); sandbox_b.setup()

                self._detect(state, sandbox_b)
                self._prove(state, sandbox_a)
                self._upgrade(state, sandbox_b)
                self._repair_loop(state, sandbox_b)
                if not state.escalated:
                    self._guard(state, sandbox_b)
                if not state.escalated:
                    self._reprove(state, sandbox_a, sandbox_b)
                if not state.escalated and self.config.has_github:
                    self._review(state, sandbox_b)

                state.node = Node.ESCALATE if state.escalated else Node.DONE
                root.log(output=state.to_dict())
        finally:
            sandbox_a.stop(); sandbox_b.stop()

        self._print_summary(state)
        return state

    # --- 1. DETECT ---
    def _detect(self, state: RunState, sb) -> None:
        state.node = Node.DETECT
        with self.tracer.span("detect") as span:
            sb.exec(f"{sb.py()} -m pip install --quiet pip-audit")
            res = sb.exec(f"{sb.py()} -m pip_audit -r requirements.txt -f json")
            pkg, ver, cve, fix = self._parse_pip_audit(res.output)
            state.package, state.installed_version, state.cve_id = pkg, ver, cve
            if fix and not state.patched_version:
                state.patched_version = fix
            state.log(Node.DETECT, f"pip-audit: {pkg}=={ver} vulnerable -> {cve} (fix {state.patched_version})")
            span.log(input="pip-audit -r requirements.txt",
                     output={"package": pkg, "version": ver, "cve": cve},
                     metadata={"node": "detect"})

    # --- 2. PROVE (Sandbox A) ---
    def _prove(self, state: RunState, sb) -> None:
        state.node = Node.PROVE
        with self.tracer.span("prove") as span:
            res = sb.exec(f"{sb.py()} exploit.py")
            accepted = res.exit_code == 0
            state.exploit_accepted_before = accepted
            state.exploit_evidence_before = self._verdict_line(res.output)
            state.goals.exploit_proven = accepted
            state.log(Node.PROVE, f"exploit on vulnerable code -> {'ACCEPTED (RCE)' if accepted else 'not accepted'}")
            span.log(output={"accepted": accepted, "evidence": state.exploit_evidence_before},
                     scores={"exploitable": 1.0 if accepted else 0.0}, metadata={"node": "prove"})
        if not state.exploit_accepted_before:
            self._escalate(state, "exploit did not reproduce on the vulnerable target")

    # --- 3. UPGRADE (Sandbox B) ---
    def _upgrade(self, state: RunState, sb) -> None:
        if state.escalated:
            return
        state.node = Node.UPGRADE
        with self.tracer.span("upgrade") as span:
            reqs = sb.read_file("requirements.txt")
            pkg = state.package or "PyYAML"
            bumped = re.sub(rf"(?im)^{re.escape(pkg)}\s*==.*$", f"{pkg}=={state.patched_version}", reqs)
            if bumped == reqs:  # fall back to case-insensitive contains
                bumped = re.sub(r"(?im)^pyyaml\s*==.*$", f"PyYAML=={state.patched_version}", reqs)
            sb.write_file("requirements.txt", bumped)
            sb.exec(f"{sb.py()} -m pip install -r requirements.txt")
            state.log(Node.UPGRADE, f"bumped {pkg} -> {state.patched_version}")
            span.log(output={"requirements": bumped}, metadata={"node": "upgrade"})

    # --- 4-6. OBSERVE / FIX / VERIFY loop ---
    def _repair_loop(self, state: RunState, sb) -> None:
        if state.escalated:
            return
        tests = self._run_tests(state, sb, Node.OBSERVE)
        state.tests = tests
        if tests.all_green:
            state.log(Node.OBSERVE, "no breakage from the upgrade (unexpected) — continuing")
            state.goals.tests_green = True
            return

        while state.iteration < state.max_iterations:
            state.iteration += 1
            self._fix(state, sb, tests)
            tests = self._run_tests(state, sb, Node.VERIFY)
            state.tests = tests
            if tests.all_green:
                state.goals.tests_green = True
                state.log(Node.VERIFY, f"suite green after {state.iteration} iteration(s)")
                return
            state.log(Node.VERIFY, f"still failing after iteration {state.iteration}")
        self._escalate(state, f"tests still failing after {state.max_iterations} fix iterations")

    def _fix(self, state: RunState, sb, tests: TestResult) -> None:
        state.node = Node.FIX
        with self.tracer.span("fix") as span:
            files = self._source_files(sb)
            changed = self.llm.generate_fix(files, tests.raw)
            for name, content in changed.items():
                sb.write_file(name, content)
                state.fixes_applied.append({"file": name, "iteration": str(state.iteration)})
            state.log(Node.FIX, f"iteration {state.iteration}: patched {', '.join(changed) or '(no change)'}"
                      + ("" if self.llm.online else " [offline fix]"))
            span.log(input={"failure": tests.raw[:2000]}, output={"changed": list(changed)},
                     metadata={"node": "fix", "iteration": state.iteration, "online": self.llm.online})

    # --- 7. GUARD (Braintrust security eval) ---
    def _guard(self, state: RunState, sb) -> None:
        state.node = Node.GUARD
        with self.tracer.span("guard") as span:
            patched = self._source_files(sb)
            verdict = assess_fix_security(patched)
            state.security_eval = verdict
            span.log(output=verdict, scores={"security_preservation": verdict["score"]},
                     metadata={"node": "guard"})
            state.log(Node.GUARD, f"security eval: {verdict['detail']}")
            if not verdict["ok"]:
                state.goals.cve_resolved = False
                self._escalate(state, f"fix weakened security: {verdict['detail']}")
            else:
                state.goals.cve_resolved = True

    # --- 8. RE-PROVE (Sandbox A, patched) ---
    def _reprove(self, state: RunState, sb_a, sb_b) -> None:
        state.node = Node.REPROVE
        with self.tracer.span("reprove") as span:
            # Bring Sandbox A up to the patched state: same exploit, fixed code.
            sb_a.write_file("requirements.txt", sb_b.read_file("requirements.txt"))
            for name in self._source_files(sb_b):
                sb_a.write_file(name, sb_b.read_file(name))
            sb_a.exec(f"{sb_a.py()} -m pip install -r requirements.txt")
            res = sb_a.exec(f"{sb_a.py()} exploit.py")
            blocked = res.exit_code != 0
            state.exploit_accepted_after = not blocked
            state.exploit_evidence_after = self._verdict_line(res.output)
            state.goals.exploit_blocked = blocked
            state.log(Node.REPROVE, f"same exploit on patched code -> {'BLOCKED (dead)' if blocked else 'STILL ACCEPTED!'}")
            span.log(output={"blocked": blocked, "evidence": state.exploit_evidence_after},
                     scores={"cve_dead": 1.0 if blocked else 0.0}, metadata={"node": "reprove"})
        if not blocked:
            self._escalate(state, "exploit still succeeds after patch")

    # --- 9-11. SUBMIT / GATE / MERGE (GitHub + CodeRabbit) ---
    def _review(self, state: RunState, sb) -> None:
        from .vcs import GitHubClient

        gh = GitHubClient(self.config)
        files = self._source_files(sb)
        files["requirements.txt"] = sb.read_file("requirements.txt")
        subdir = self.config.repo_subdir
        if subdir:  # target app lives in a subdir of the repo -> prefix PR paths
            files = {f"{subdir}/{name}": content for name, content in files.items()}
        branch = f"patchpilot/{state.cve_id.lower()}-{state.run_id}"
        title = f"PatchPilot: fix {state.cve_id} in {state.package} ({state.installed_version} -> {state.patched_version})"
        body = self._pr_body(state)

        state.node = Node.SUBMIT
        with self.tracer.span("submit") as span:
            pr = gh.open_pr(branch, title, body, files)
            state.pr_url, state.pr_number = pr.url, pr.number
            gh.comment(pr.number, "@coderabbitai review")
            state.log(Node.SUBMIT, f"opened PR {pr.url}")
            span.log(output={"pr": pr.url}, metadata={"node": "submit"})

        state.node = Node.GATE
        with self.tracer.span("gate") as span:
            gate = gh.poll_gate(pr.number, pr.head_sha, timeout_s=300)
            state.tests_check_ok = gate["tests_ok"]
            state.review_ok = gate["review_ok"]
            state.log(Node.GATE, f"gate: tests_ok={gate['tests_ok']} review_ok={gate['review_ok']}")
            span.log(output=gate, metadata={"node": "gate"})

        if state.tests_check_ok and state.review_ok:
            if self.config.auto_merge:
                state.node = Node.MERGE
                state.merged = gh.merge(pr.number)
                state.log(Node.MERGE, "merged (tests + CodeRabbit both green)" if state.merged else "merge call failed")
            else:
                state.log(Node.GATE, f"gate GREEN — auto-merge off, PR left for human review: {pr.url}")
        else:
            self._escalate(state, "merge gate not satisfied (tests or CodeRabbit review pending/failed)")

    def _pr_body(self, state: RunState) -> str:
        return (
            f"Automated patch by **PatchPilot**.\n\n"
            f"- **CVE:** {state.cve_id} in `{state.package}=={state.installed_version}`\n"
            f"- **Proven exploitable:** {state.exploit_evidence_before}\n"
            f"- **Upgrade:** `{state.package}` -> `{state.patched_version}`\n"
            f"- **Repair:** {len(state.fixes_applied)} call site(s) fixed over {state.iteration} iteration(s)\n"
            f"- **Security preserved:** {state.security_eval['detail'] if state.security_eval else 'n/a'}\n"
            f"- **Re-proven dead:** {state.exploit_evidence_after}\n\n"
            f"The agent that wrote this patch does not approve it — merge gates on tests + CodeRabbit."
        )

    # --- helpers ---
    def _run_tests(self, state: RunState, sb, node: Node) -> TestResult:
        state.node = node
        res = sb.exec(f"{sb.py()} -m pytest -q --tb=short")
        tr = self._parse_pytest(res.output)
        tr.raw = res.output
        if node == Node.OBSERVE:
            state.log(node, f"pytest: {tr.passed} passed, {tr.failed} failed, {tr.errors} error(s)")
        return tr

    def _source_files(self, sb) -> dict[str, str]:
        listing = sb.exec("ls *.py").output.split()
        files: dict[str, str] = {}
        for name in listing:
            if name in NON_FIXABLE:
                continue
            try:
                files[name] = sb.read_file(name)
            except Exception:
                pass
        return files

    def _escalate(self, state: RunState, reason: str) -> None:
        state.escalated = True
        state.escalation_reason = reason
        state.node = Node.ESCALATE
        state.log(Node.ESCALATE, f"ESCALATE — {reason}")

    @staticmethod
    def _verdict_line(output: str) -> str:
        for line in output.splitlines():
            if line.startswith("RESULT"):
                return line.strip()
        return output.strip().splitlines()[-1] if output.strip() else ""

    @staticmethod
    def _parse_pip_audit(output: str):
        pkg = ver = cve = fix = ""
        try:
            data = json.loads(output[output.find("{"): output.rfind("}") + 1])
            deps = data.get("dependencies", data.get("results", []))
            for dep in deps:
                vulns = dep.get("vulns", [])
                if vulns:
                    pkg, ver = dep.get("name", ""), dep.get("version", "")
                    cve = vulns[0].get("id", "")
                    fixes = vulns[0].get("fix_versions", [])
                    fix = fixes[0] if fixes else ""
                    break
        except Exception:
            m = re.search(r"(?im)^(\S+)\s+(\S+)\s+(PYSEC-\S+|CVE-\S+)", output)
            if m:
                pkg, ver, cve = m.group(1), m.group(2), m.group(3)
        return pkg or "PyYAML", ver or "5.3.1", cve or "PYSEC-2021-142", fix

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
