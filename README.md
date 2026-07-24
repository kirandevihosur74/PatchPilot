# PatchPilot

An autonomous agent that proves a dependency vulnerability is *actually exploitable*
in your code, patches it, repairs whatever the upgrade breaks, and re-runs the
exploit to prove the bug is dead.

## The problem

Vulnerability scanners like Dependabot and Snyk match version strings: "you have
PyYAML 5.3.1, it's in the vulnerable range, here's a ticket." They can't tell whether
the vulnerable code path is actually reachable in *your* application — so teams drown
in alerts, can't triage them, and patch nothing. And the scary part, fixing the code
the upgrade breaks, is left entirely to a human.

PatchPilot closes that loop. It writes a real exploit to prove the CVE is reachable,
upgrades the dependency, repairs the call sites the upgrade breaks, and re-runs the
same exploit to prove the vulnerability is gone — without ever weakening security to
make the tests pass.

## How it works

PatchPilot runs a self-correcting loop across two isolated sandboxes — one is the
exploit lab, the other is the repair lab:

1. **Detect** — `pip-audit` scans the target and identifies the vulnerable package.
2. **Prove** — the exploit runs against the vulnerable code; arbitrary code executes.
3. **Upgrade** — the dependency is bumped to the fixed version.
4. **Observe** — the test suite is run to surface exactly what the upgrade broke.
5. **Fix** — a coding model rewrites the broken call sites (retries up to 3 times).
6. **Verify** — the suite is re-run until it's green.
7. **Guard** — a security check rejects any fix that keeps the vulnerability alive.
8. **Re-prove** — the same exploit is run against the patched code; it's now blocked.

The result is four beats you can watch turn green:
**exploitable → CVE resolved → tests green → exploit blocked.**

The demo target is a small FastAPI service pinned to `PyYAML==5.3.1`
(CVE-2020-14343, a `yaml.load` bypass that reaches remote code execution). Upgrading
to 6.0 both kills the CVE and forces a `TypeError` at every call site, so the fix is
to add `Loader=yaml.SafeLoader`. The guard's job is to make sure the agent never
"repairs" it with the unsafe `yaml.Loader` — which would pass the tests but keep the
RCE alive.

## Architecture

```
                 ┌──────────────────────────────┐
                 │         Orchestrator         │
                 │  (the detect → reprove loop) │
                 └───────────────┬──────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          ▼                      ▼                      ▼
   Sandbox A (exploit)    Sandbox B (repair)      Security guard
   run the exploit        upgrade + patch +       reject unsafe
   before / after         re-run the suite        fixes
```

Everything dangerous — running the exploit, installing the upgrade, running the
patched code — happens inside a sandbox. The control plane never executes untrusted
code. Every service sits behind a single interface, so a run works end-to-end with no
external keys (local/offline mode) and lights up the real tools when keys are present.

## Layout

| Path | What |
|---|---|
| `patchpilot/` | The agent — `orchestrator.py` (the loop), `sandbox.py` + `daytona_sandbox.py` (isolation), `llm.py` (fix generation), `evals.py` (tracing + security eval), `vcs.py` (review). |
| `target-app/` | The intentionally-vulnerable demo target the agent attacks and patches. |
| `security_eval.py` | Standalone Braintrust eval for the security-preservation check. |

## Tools

| Tool | Role |
|---|---|
| **Daytona** | Isolated sandboxes — one runs the live exploit, the other runs the patch-and-repair loop. |
| **Fireworks** | Two-model loop: a fast model triages test failures, a coder model generates the fix. |
| **Braintrust** | Per-step tracing and the security-preservation eval that catches weaken-to-pass fixes. |
| **CodeRabbit** | Independent AI review on the patch PR — the agent that writes the fix never approves it. |

## Tech stack

- **Python** — orchestrator built as idempotent, re-enterable nodes over a single run state.
- **FastAPI** — the demo target service.
- **pip-audit** — real vulnerability detection, not a hardcoded CVE list.
- **pytest** — the test suite that surfaces upgrade breakage.
- **OpenAI-compatible client** — talks to Fireworks models for triage and fixes.

## Useful commands

Run the full loop locally — no keys required:

```bash
python3 -m patchpilot --local
```

Point it at a different target repo, or override the upgrade version:

```bash
python3 -m patchpilot --local --target ./target-app --patched-version 6.0.1
```

Work with the demo target directly:

```bash
cd target-app
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q      # suite passes on the pinned version
.venv/bin/python exploit.py        # prints EXPLOIT ACCEPTED, exit 0
```
