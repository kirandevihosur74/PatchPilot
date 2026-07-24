# PatchPilot

Prove a dependency CVE is **actually exploitable** in your code, patch it, repair
what the upgrade breaks, and re-run the exploit to prove the bug is **dead** —
then open a PR that only merges if tests *and* an independent AI review pass.

> Scanners tell you that you *have* a vulnerable version. None tell you whether
> you're actually exploitable — so teams drown in noise and patch nothing.
> PatchPilot writes the exploit, proves the bug is reachable, patches it, fixes
> what the upgrade breaks, and re-runs the exploit to prove it's dead.

## The loop

```
detect  -> prove -> upgrade -> observe -> fix -> verify -> guard -> reprove -> submit -> gate -> merge
(pip-audit) (RCE)   (bump dep) (tests    (coder (suite   (security (exploit  (PR)     (tests+  (both
                               break)     model) green)   eval)     dead)              review)  green)
```

Everything dangerous runs in a **sandbox**; the control plane never executes the
exploit. The pipeline is one sentence:

**isolate (Daytona) → generate (Fireworks) → evaluate (Braintrust) → review (CodeRabbit).**

## Layout

| Path | What |
|---|---|
| `target-app/` | Intentionally-vulnerable demo target (`PyYAML==5.3.1`, CVE-2020-14343 / RCE). The app PatchPilot attacks and patches. |
| `patchpilot/` | The agent: `orchestrator.py` (loop), `sandbox.py` + `daytona_sandbox.py` (isolate), `llm.py` (generate), `evals.py` (evaluate), `vcs.py` (review). |
| `security_eval.py` | Braintrust eval that catches "weaken-to-pass" fixes (`braintrust eval security_eval.py`). |
| `PLAN.md` | Full build plan. |

## Run it

No keys required — the loop runs fully in local/offline mode:

```bash
python3 -m patchpilot --local
```

You'll see all four goals go green: **Exploitable proven → CVE resolved → Tests
green → Exploit blocked.**

Show the safeguard catching a bad fix (fix passes tests but weakens security):

```bash
PATCHPILOT_FORCE_UNSAFE_FIX=1 python3 -m patchpilot --local
# -> guard ESCALATES: "weakened security ... unsafe loader kept the RCE"
```

## Wire the real services

```bash
cp .env.example .env      # fill FIREWORKS / DAYTONA / BRAINTRUST / GITHUB keys
pip install -r requirements.txt
python3 -m patchpilot      # Daytona sandboxes + Fireworks fixes + Braintrust traces + CodeRabbit gate
```

Each service activates when its key is present; anything missing degrades to the
local/offline path with no code change. Confirm live Fireworks model ids with the
`/models` endpoint (they drift); confirm the CodeRabbit check name / bot login on
one real PR, then they're picked up automatically.

## Status

- ✅ Core loop runs end-to-end (local + offline), both success and escalate paths.
- ✅ Daytona / Fireworks / Braintrust / GitHub+CodeRabbit wired behind one interface.
- ⏳ Live run with real keys; SSE control-plane API; Discord/MCP trigger surface (§12).
