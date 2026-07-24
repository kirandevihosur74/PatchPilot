# PatchPilot — Architecture & Build Plan (Exploit-First)

> **Hand-off note for Claude Code:** This is the approved plan. Do NOT write feature code until
> the human confirms the architecture in §6. First task is the demo repo + exploit PoC (§9,
> "Tonight"). Scoped to a ~5.5-hour hackathon build. Bias toward one flawless end-to-end run over
> breadth. Cut from the bottom of the sponsor list up if time runs short.

---

## 1. The Idea

**PatchPilot** — an autonomous agent that **proves a dependency vulnerability is actually
exploitable in your code**, patches it, repairs the code the upgrade breaks, and re-runs the
exploit to prove the vulnerability is dead.

The loop: **detect → PROVE (write a working exploit) → upgrade → observe breakage → repair call
sites → re-verify → re-run exploit (now blocked) → open a reviewable PR → gate the merge.**

**The creative wedge — say this first, always:**
> "Every scanner tells you that you *have* a vulnerable version. None tell you whether you're
> actually exploitable — so teams drown in noise and patch nothing. PatchPilot writes the exploit,
> proves the bug is reachable in your code, patches it, fixes what the upgrade breaks, and re-runs
> the exploit to prove it's dead."

This is NOT "an agent that fixes bugs." It replaces advisory version-matching with **empirical
proof of exploitability** — that's the originality.

---

## 2. The Problem

Enterprise security backlogs are ~90% noise. Scanners (Dependabot/Snyk/etc.) do version-string
matching: "you have PyYAML 5.3.1, it's in the vulnerable range, here's a ticket." They have no idea
whether the vulnerable code path is actually reachable in *your* app. So engineers face a wall of
alerts they can't triage, patch nothing, and real CVEs sit unaddressed (industry median
time-to-remediate ~= 252 days).

Two unsolved halves nobody automates together:
1. **Proving exploitability** — is this CVE actually reachable here, or is it noise?
2. **Fixing the breakage** the patch causes — the scary part that makes teams avoid patching.

Dependabot/Renovate open a PR and leave the breakage to you. Infield plans the upgrade but hands
the fix to a human. SAST tools flag *your* code, not dependency-upgrade fallout. None prove
reachability by exploitation. **PatchPilot closes the whole loop, proof-first.**

---

## 3. The Demo Vulnerability (VALIDATED — empirically, on Python 3.13)

**Package:** PyYAML · **CVE-2020-14343** (PYSEC-2021-142, FullLoader bypass -> arbitrary code
execution; rated Critical by NVD) · **Vulnerable:** <=5.3.x · **CVE fixed:** 5.4+

> **Pivot note:** the original plan used PyJWT/CVE-2022-29217. It **failed the exploit gate** — a
> functional PyJWT 1.7.1 auth service is not actually exploitable (1.7.1 already blocklists PEM
> public keys as HMAC secrets, and the one DER bypass breaks legit verification). PyYAML validated
> clean end-to-end and is a *stronger* story: the exploit is **RCE**, not just auth bypass.

**Why this one:** pin `PyYAML==5.3.1` and two boundaries stack perfectly. The CVE is fixed at 5.4,
but the clean **forced API breakage** lands at 6.0 — `yaml.load()` requires an explicit `Loader`.
So upgrading to `>=6.0` both kills the CVE *and* forces breakages. The target calls `yaml.load()`
at three sites (`load_settings`, `load_policy`, `parse_request`); the upgrade breaks all three:

1. `load_settings(text)` — `yaml.load(text)` -> `TypeError: load() missing 1 required positional argument: 'Loader'`.
2. `load_policy(text)` — same TypeError.
3. `parse_request(text)` — same TypeError. *(This is the untrusted sink — the security-critical fix.)*

Each fix is one line: add `Loader=yaml.SafeLoader`.

**The exploit (§2's "prove it" step):** a crafted YAML document (a FullLoader-bypass gadget) sent
to `parse_request` **executes code on the server** (the harness proves it by creating a marker
file — observable, non-destructive). In Sandbox A, PatchPilot sends the payload and shows it
**ACCEPTED (code runs)**. After patch + `Loader=yaml.SafeLoader`, the same payload is **REJECTED**
(`ConstructorError`). Cause-and-effect a non-technical judge feels instantly.

**Narrative gold:** the security-critical repair is *choosing* `SafeLoader`, not just silencing the
TypeError. `Loader=yaml.Loader` also makes the tests pass — and **keeps the RCE alive**. The agent
must reason about untrusted input, not do syntax repair.

**Guardrail to build:** the agent must NEVER "fix" a break with `yaml.Loader`/`yaml.FullLoader`
(weaken-to-pass). This becomes a Braintrust eval we show catching a bad fix live.

**Validation evidence (all confirmed):** pip-audit flags PyYAML 5.3.1 (PYSEC-2021-142); the payload
executes on 5.3.1; upgrade to 6.0.1 breaks all three call sites; `SafeLoader` restores function AND
blocks the payload; `Loader` restores function but keeps the RCE. Target lives at `target-app/`.

---

## 4. Sponsor Tools & Use Cases (Daytona HackSprint)

| Sponsor | Role in the system | Why it's load-bearing | Prize odds |
|---|---|---|---|
| **Daytona** | Isolated sandboxes. **Sandbox A** runs the live RCE exploit (before & after). **Sandbox B** runs the patch-and-repair loop. Fresh sandbox per retry. | The sandbox is *why running live remote code execution on stage is safe.* The argument, not decoration. | **Highest** |
| **Braintrust** | Per-step tracing (detect->prove->fix->verify) + run scores (exploitable y/n, iterations-to-green, CVE dead y/n) + the **security-preservation eval** catching "weaken-to-pass" fixes. | Eval engineer on the panel. A *real eval*, not just traces. Few teams will have this. | **High** |
| **CodeRabbit** | Independent AI reviews the security-patch PR. Merge only on tests OK + review OK. Stretch: agent reads review comments, responds in a 2nd commit. **See §12 for the Discord Bot / MCP challenge track.** | 3 CodeRabbit judges. "The agent that writes the patch never approves it." | **Real shot** |
| **Fireworks** | Two-model loop: small fast model for triage/error-parsing, coder model for exploit-writing + fix generation. Speed makes 3 self-correction iterations viable in <1 min. | Necessary, well-used, not central. Name-check speed; don't chase. | Long shot |
| **WorkOS** | SSO on the dashboard. One safeguards-slide bullet ("enterprise auth on the control plane"). | 20-min add in a lull. | Optics |
| **CopilotKit** | *(If a teammate does frontend.)* Live agent-status panel + "approve escalation" button = visible human-in-the-loop. | Doubles as safeguard + prize entry. Solo -> skip, use a log view. | If teamed |
| **ElevenLabs** | *(Optional flourish.)* 20-sec spoken "security briefing" on completion. | Tasteful, not a prize play. Spare time only. | N/A |

**The one-sentence pipeline (architecture slide):**
> Prove & isolate (Daytona) -> generate fast (Fireworks) -> evaluate (Braintrust) -> independently review (CodeRabbit) -> authenticate humans (WorkOS).

---

## 5. Technology Stack

**Backend / agent**
- **Python 3.11** - reuse durable/idempotent patterns for crash-safe recovery.
- **Orchestration:** LangGraph (explicit state machine, maps 1:1 to the loop) OR a plain async
  state machine if LangGraph adds friction. Keep it inspectable - the graph *is* the demo. Use
  whichever you're fluent in; hackathon day is the wrong time to fight a framework.
- **API layer:** FastAPI - one endpoint to start a run, one to stream status (SSE/WebSocket).
- **Sandbox:** Daytona SDK - programmatic create / exec / teardown.
- **LLM:** Fireworks (OpenAI-compatible client) - two models (fast triage + coder).
- **VCS:** GitHub REST API (PyGithub or httpx) - branch, commit, open PR, poll check status.
- **Vuln detection:** `pip-audit` (real scanner, flags PYSEC-2021-142 on PyYAML 5.3.1 - detect step isn't faked).
- **Test runner:** `pytest` in the sandbox; parse JUnit XML / stdout for pass/fail + tracebacks.
- **Exploit harness:** a small Python script the agent generates/runs in Sandbox A that sends a
  malicious YAML document to the untrusted sink and asserts accept-before / reject-after (code
  executes -> code blocked). Already built at `target-app/exploit.py`.
- **Evals/telemetry:** Braintrust SDK - wrap each node, log inputs/outputs/scores.

**Frontend**
- **Minimum viable (solo):** single-page dashboard streaming loop steps + a goal tracker
  (Exploitable: proven OK / CVE resolved OK / N/N tests green OK / Exploit now blocked OK).
- **If teamed:** Next.js + CopilotKit panel with live agent state + "approve escalation" button,
  wrapped in WorkOS SSO.
- Keep it dead simple - a legible goal tracker beats a pretty dashboard that doesn't update.

**Database**
- **None required for MVP.** Run state lives in the LangGraph state object + Braintrust logs.
- If persistence is wanted for a "resolution rate across N repos" metric: **SQLite** (one file,
  zero ops). One `runs` table: run_id, repo, cve, exploitable, resolved, iterations, tests_passed,
  duration, escalated.
- Do NOT stand up Postgres/anything hosted. Time sink, zero demo value.

---

## 6. Architecture (CONFIRM BEFORE CODING)

```
                         +---------------------------------------------+
                         |  FastAPI control plane  (+ WorkOS SSO)      |
                         |  POST /run   ->  starts a run               |
                         |  GET  /stream -> SSE of loop state          |
                         +---------------+-----------------------------+
                                         |
                    +--------------------v---------------------+
                    |  Orchestrator (LangGraph state machine)  |
                    |                                          |
                    |  1. DETECT   pip-audit -> CVE identified |
                    |  2. PROVE    Sandbox A: generate + run   |  <- creative core
                    |              malicious YAML payload ->    |
                    |              code EXECUTES (exploitable)  |
                    |  3. UPGRADE  bump PyYAML 5.3.1 -> >=6.0   |
                    |  4. OBSERVE  Sandbox B: pytest -> collect|
                    |              failing tests + tracebacks  |
                    |  5. FIX      Fireworks coder model:      |
                    |              patch call sites from traces|
                    |  6. VERIFY   Sandbox B: re-run pytest    |
                    |      |- fail -> back to 5 (max 3 iters)  |
                    |      |- pass -> continue                 |
                    |      |- exhausted -> ESCALATE (draft PR +|
                    |              "here's what I tried")       |
                    |  7. GUARD    Braintrust eval: security   |
                    |              NOT weakened? fail->ESCALATE |
                    |  8. RE-PROVE Sandbox A: re-run same       |  <- the payoff
                    |              payload -> code BLOCKED      |
                    |  9. SUBMIT   GitHub: branch, commit, PR   |
                    |  10. GATE    poll tests OK + CodeRabbit OK|
                    |  11. MERGE   only if both green           |
                    +------------------+-----------------------+
                                       |
          +----------------------------+----------------------------+
          v                            v                            v
   Daytona sandboxes           Braintrust traces           GitHub + CodeRabbit
   (A: exploit, B: loop)       (every node scored)          (PR + review gate)
```

**Key design rules**
- **Prove before patch, re-prove after** - steps 2 and 8 use the *same* exploit; the before/after is the demo.
- **Observe before fix** - never generate a patch without a real failing test proving the break.
- **Retry cap = 3**, then escalate. The escalation path IS a safeguard; show it.
- **Idempotent nodes** - each step safe to re-enter (enables the crash-resume party trick).
- **Everything dangerous runs in Daytona.** The control plane never executes untrusted code or exploits.

---

## 7. Demo Script (3 minutes)

1. **0:00** - "Scanners tell you that you *have* a vulnerable version. None tell you if you're actually exploitable - so teams patch nothing." (15s)
2. **0:15** - **Sandbox A:** agent sends a malicious YAML doc, runs it -> **code EXECUTES**. "That's live remote code execution - proven, and safe only because it's sandboxed." (Daytona + the wedge)
3. **0:45** - Loop streams: detect -> upgrade -> **tests break** -> fix 1 -> re-run -> next break -> fix -> green. (self-correcting loop = wow)
4. **1:45** - Braintrust panel: security-preservation eval clears (or catches) the fix. "Scored on never weakening security to pass tests - `SafeLoader`, never `Loader`."
5. **2:10** - **Sandbox A again:** same payload -> **BLOCKED.** "Proven exploitable. Now proven dead." (the payoff)
6. **2:30** - **Pre-triggered** PR where CodeRabbit's review already landed (insurance vs. latency). Gate merges on tests OK + review OK.
7. **2:50** - Goal tracker green. "The agent that writes the patch never approves it. At my last startup this pattern hit 78% autonomous resolution in prod." Done.

---

## 8. Scope Guardrails

**MVP (must-have):** PyYAML case, one demo repo, the exploit prove/re-prove beats, the 3 breakages
repaired + verified, one clean rehearsed end-to-end run, Daytona + Braintrust + CodeRabbit wired,
goal tracker.

**Stretch (only if ahead):** crash-and-resume demo; 3-5 repo benchmark for a resolution-rate
number; CopilotKit panel; WorkOS SSO; ElevenLabs briefing; agent responds to CodeRabbit comments.

**Cut ruthlessly:** transitive dependency cascades, multi-language, arbitrary monorepos, real
Sentry/webhook ingestion, Postgres. All "what's next" slide material. Never claim "provably no
behavior change" - say "verified by the existing suite, extended to cover the changed surface."

---

## 9. Task Sequence

**TONIGHT (validation - the go/no-go gate)** — steps 1-4 DONE, 5-6 pending a model key.
1. ✅ **DONE.** Built demo repo `target-app/`: FastAPI Config Ingest Service - `parser.py` with
   `load_settings`/`load_policy`/`parse_request` (all 3 use `yaml.load` with no Loader), `app.py`,
   11 pytest tests, `exploit.py`, README banner. Pinned `PyYAML==5.3.1`.
2. ✅ **DONE.** `exploit.py` sends the malicious YAML -> **code executes** on 5.3.1 (RCE, exit 0).
3. ✅ **DONE.** `pip-audit -r requirements.txt` flags PyYAML 5.3.1 (PYSEC-2021-142, fix 5.4).
4. ✅ **DONE.** Bumped to `PyYAML==6.0.1`, ran pytest -> all 3 `yaml.load` sites raise TypeError
   (collection error at import via `load_settings`). Reverted to pinned 5.3.1.
5. ⏳ **TODO (needs Fireworks/Anthropic key).** Feed each traceback to the model, 3-5 runs ->
   confirm near-100% correct fixes (`Loader=yaml.SafeLoader`) AND the exploit is **blocked** after.
6. ⏳ **TODO.** **Critical check:** confirm the model uses `SafeLoader` and never "fixes" with
   `yaml.Loader`/`yaml.FullLoader` (keeps the RCE). If it ever does, capture it - that's the eval.
   -> Steps 1-4 locked. If the model whiffs 5-6 badly -> fall back to backups below.

**EVENT DAY (~5.5 hrs)**
- **10:00-10:45** Plumbing: Daytona spin-up + clone + pytest; GitHub PR open; CodeRabbit installed & firing on a dummy PR.
- **10:45-12:30** Core loop on PyYAML (detect->prove->upgrade->observe->fix->verify->re-prove, retry cap).
- **12:30-1:00** Lunch; confirm CodeRabbit review-status polling reads pass/fail programmatically.
- **1:00-2:15** Braintrust tracing + the security-preservation eval + the merge gate.
- **2:15-3:00** Rehearse the exact demo 3x; record a backup screen capture (~2:45).
- **3:00-3:30** Slides (Problem -> Loop diagram -> **Safeguards** -> Live demo -> What's next) + submit.

**Backup CVE candidates (if PyYAML somehow needs replacing):**
- urllib3 1.26.x -> 2.x (`method_whitelist` -> `allowed_methods` removal in Retry) — API break only, no exploit.
- Pillow 9.x -> 10.x (CVEs + `Image.ANTIALIAS` removal) — API break only, no exploit.
- *(PyYAML is the validated pick: RCE exploit + a forced API breakage at 6.0 is the cleanest,
  most legible story. **PyJWT was rejected** — see §3 pivot note; do not re-attempt.)*

---

## 10. Judging-Criteria Fit (self-check)

- **Impact (25%):** unpatched CVEs (~252 days) + alert-fatigue is real, quantified, industry-scale.
- **Technical Execution (25%):** real self-correcting loop, sandboxed exploit + repair, retry cap, merge gate. *Lives or dies on the rehearsed live run.*
- **Creativity (25%):** "prove exploitability by writing the exploit, then prove it dead" - not a genre. Lead with the wedge line in §1, never with "fixes bugs."
- **Presentation (25%):** exploit accepted -> self-correcting loop -> exploit rejected -> green merge. Cause-and-effect any judge feels. Memorized wedge line.
- **Sponsor Usage (bonus):** five sponsors as one coherent proof/trust pipeline, not bolted-on logos.

---

## 11. Pre-Mortem (how the demo dies, and the insurance)

- **CodeRabbit review latency** > pitch window -> pre-trigger the PR; show the landed review.
- **Venue wifi fails mid-demo** -> the ~2:45 backup recording. Non-negotiable.
- **Model whiffs the fix live** -> rehearse on the exact PyYAML bugs (the `yaml.load` Loader fix is heavily represented in training data). Be honest that harder upgrades escalate - that honesty is a safeguard talking point.
- **Exploit step looks staged** -> use a *real* scanner (pip-audit) for detect and the *same* exploit script before/after. Don't hardcode the accept/reject result.
- **Scope creep** -> "watch a repo" is a poll loop, nothing more. Guard the MVP.
- **Sponsor over-wiring** -> a clean Daytona+Braintrust+CodeRabbit run beats all 7 half-working. Cut bottom-up.

---

## 12. Discord Bot + MCP Integration (CodeRabbit Challenge Track)

> **VERIFY FIRST:** confirm with the CodeRabbit team that this challenge is part of this
> hackathon (the $1,000 matches "Best Use of CodeRabbit," but the doc doesn't name the event).
> Also confirm the correct GitHub org - the brief names it inconsistently ("the-builders burrow"
> / "working-ant" / "the-builders-burrow") - and that the Discord invite link is valid.

**This is NOT a separate project.** It is a new trigger surface on the same loop. The agent,
sandboxes, and evals in §6 are unchanged. Only the front door is new.

### 12.1 Challenge setup requirements
- Project repo must be **public**, inside their GitHub org. **Create it there from the start** -
  migrating mid-hackathon costs time you don't have.
- Dedicated team channel in the hackathon Discord server.
- GitHub OAuth completed *through the Discord chat* with the bot (not the usual dashboard install).
- Bar for the prize: "build something creative **using the bot**." Having CodeRabbit review your
  PRs is table stakes and almost certainly does NOT qualify on its own.

### 12.2 The play: PatchPilot as an MCP server
The brief explicitly mentions connecting MCP servers - this is the unfair-advantage angle
(production MCP integration experience). Expose the existing loop as MCP tools the CodeRabbit
Discord Bot can call:

| MCP tool | Input | Returns |
|---|---|---|
| `scan_repo` | repo_url | pip-audit results; CVEs found |
| `prove_exploit` | repo_url, cve_id | Sandbox A verdict: ACCEPTED (exploitable) + evidence |
| `patch_and_repair` | repo_url, cve_id | run_id; kicks off the §6 loop |
| `get_run_status` | run_id | current node, iteration count, goal tracker state |
| `approve_escalation` | run_id, decision | unblocks a run parked at ESCALATE |

### 12.3 Discord UX flow (the demo, driven from chat)
```
user:  @CodeRabbit scan my repo
bot:   Found PYSEC-2021-142 (PyYAML 5.3.1, RCE) - exploitable? unknown
user:  prove it
bot:   [Sandbox A] Malicious YAML executed code on the server. RCE confirmed. Evidence attached.
user:  patch it
bot:   [running] upgrade -> 3 tests broke -> fix 1/3 ... 3/3 -> suite green
       [Sandbox A] Same payload now BLOCKED (ConstructorError).
       PR #4 opened. Awaiting CodeRabbit review + tests.
bot:   Review passed, tests green -> merged.
```
Escalation path posts into the channel: *"3 attempts, still failing on X. Here's what I tried."*
A human approves or rejects via the bot = **visible human-in-the-loop**, which doubles as a
safeguards-slide bullet and a CopilotKit-equivalent story without a frontend.

### 12.4 Note on the public vulnerable repo
The demo target pins `PyYAML==5.3.1` and ships an exploit script. Its README already carries the
banner: **"Intentionally vulnerable demo target - do not deploy."** Bonus demo moment: CodeRabbit
itself will flag the vulnerable pin on review, which *supports* the pitch rather than undermining it.

### 12.5 Scope guardrails
- **Thin layer only.** MCP tools wrap existing orchestrator entry points. If you find yourself
  rewriting loop logic to fit the bot, stop - you've inverted the priority.
- **Ask the CodeRabbit team early** (first hour) what the bot can actually do: available commands,
  whether MCP servers are genuinely supported, auth model, rate limits. Design after that answer,
  not before.
- **Fallback if MCP isn't supported:** trigger runs via a slash command or webhook, and post
  results into the channel via a Discord webhook. Still qualifies as "using the bot," far less risk.
- **Hard rule:** if the core loop (§6) is not green by 1:00 PM, cut this entirely. A flawless
  end-to-end run beats a second prize track half-wired.
