# PatchPilot — 2–3 min demo script

A tight, recordable run for Loom / QuickTime. Real live run for the loop, a
pre-reviewed PR for the CodeRabbit beat so you never wait on review latency.

---

## Before you record (2-minute setup)

1. **Start the server** (leave it running):
   ```bash
   cd ~/Developer/daytona_hackathon
   .cpvenv/bin/python -m uvicorn patchpilot.api:app --port 8077
   ```
2. **Reset to a clean slate:**
   ```bash
   ./reset-demo.sh          # target vulnerable, old PRs closed
   ```
3. **Pre-open one PR so CodeRabbit has already reviewed it** (this is your review beat — CodeRabbit takes 1–2 min, too long to wait on camera):
   - Open http://127.0.0.1:8077 → **Run live** → let it open a PR → wait ~2 min until CodeRabbit posts its review on that PR.
   - Keep that PR tab open (GitHub → the PR → "Files changed" / the CodeRabbit review).
4. **Then reset again** so the on-camera live run starts clean:
   ```bash
   ./reset-demo.sh
   ```
   (Leave the pre-reviewed PR open in its tab — you'll cut to it.)
5. **Tabs to have open:** (a) http://127.0.0.1:8077, (b) the pre-reviewed GitHub PR, (c) optional: Braintrust project `patch_pilot` (to show traces).
6. Full-screen the browser. Hide the terminal.

> If wifi/API is shaky on the day, use **Replay demo** instead of Run live — same
> UI, streams instantly, no dependency on live services.

---

## The script (~2:45)

**0:00 – 0:20 · The hook** *(landing page)*
> "Every scanner tells you that you *have* a vulnerable dependency. None tell you
> whether you're *actually exploitable* — so teams drown in alerts and patch
> nothing. PatchPilot writes the exploit, proves the bug is real, patches it, and
> re-runs the exploit to prove it's dead."

Scroll once through **Isolate → Generate → Evaluate → Review** — "one loop, four
systems: Daytona, Fireworks, Braintrust, CodeRabbit."

**0:20 – 0:35 · Launch** *(click Launch App → the console)*
> "One click on a real vulnerable package — PyYAML 5.3.1, a remote-code-execution
> CVE." **Click Run live.**

**0:35 – 1:30 · Watch it run** *(narrate as the console streams)*
- prove → **"That's a live remote code execution — a forged YAML doc runs code on the server. Safe only because it's in a Daytona sandbox."**
- upgrade + observe → "We bump the dependency; the upgrade breaks the code."
- fix + verify → **"Fireworks writes the fix — `yaml.safe_load` — and the suite goes green."**
- guard → **"Braintrust scores it: the fix preserved security. It never weakens the loader to pass tests."**
- reprove → **"Same exploit, patched code: BLOCKED. Proven exploitable — now proven dead."**

The four goal beats fill green as you talk.

**1:30 – 2:15 · The independent gate** *(cut to the pre-reviewed PR tab)*
> "PatchPilot opened a real pull request — and it doesn't approve its own work.
> CodeRabbit reviewed it independently."

Show CodeRabbit's review. Point at a real finding:
> "It even ran a dependency scan and flagged that the patch doesn't pin the rest
> of the stack — so the merge is gated on tests *and* an independent review. The
> agent that writes the patch never approves it."

**2:15 – 2:45 · Close** *(back to the console, all green)*
> "Detect, prove, patch, re-prove, review — end to end, in about a minute.
> Unpatched CVEs sit a median of 252 days because teams can't tell real from
> noise. PatchPilot proves it, fixes it, and proves it's gone."

---

## Reset between takes

```bash
./reset-demo.sh
```
Restores the vulnerable target from the `vulnerable-baseline` tag and clears any
PRs the run opened, so every take starts identical. (Or click **Reset** in the app.)

---

## Backup

- **Replay demo** button = the whole loop, streamed instantly, no live services.
- If you'd rather not cut to GitHub, the console's **"View the PR + CodeRabbit
  review"** button appears when the run finishes and deep-links to the PR.
