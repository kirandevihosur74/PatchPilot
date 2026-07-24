# PatchPilot — voiceover script (~2:35)

Word-for-word narration timed to on-screen actions. Read it live, or paste the
spoken lines into ElevenLabs / Descript for an AI voice, then screen-record the
actions silently and lay the audio over it. `[brackets]` = what to do on screen.

---

**[0:00 — landing page]**
This is PatchPilot. Every security scanner tells you that you *have* a vulnerable
dependency — but not whether you're actually exploitable. So teams get thousands of
alerts, can't tell real from noise, and patch nothing. PatchPilot is different: it
writes the exploit to prove the bug is real, patches it, fixes what the upgrade
breaks, and re-runs the exploit to prove it's dead.

**[0:20 — slowly scroll through the four "How it works" cards]**
It's one loop across four systems: Daytona for isolation, Fireworks for the fix,
Braintrust for evaluation, and CodeRabbit for independent review.

**[0:32 — click Launch App, then Run live]**
Let's run it on a real vulnerable package — PyYAML 5.3.1, a remote-code-execution
CVE. One click.

**[0:40 — console streaming; the "prove" row appears]**
First it proves the vulnerability is real. Inside an isolated Daytona sandbox, it
sends a malicious YAML document — and it executes code on the server. That's a live
remote code execution, safe only because it's sandboxed.

**[0:55 — upgrade / observe / fix rows]**
Now it patches. It upgrades the dependency, which breaks the code — and Fireworks
writes the fix: switch to a safe loader. The test suite goes green.

**[1:12 — guard row]**
Braintrust scores the fix and confirms it preserved security — it never weakens the
loader just to pass the tests.

**[1:22 — reprove row; the four goal beats are all green]**
Then the payoff: the same exploit, against the patched code — blocked. Proven
exploitable, now proven dead. All four goals green.

**[1:35 — submit row appears; cut to the GitHub PR tab]**
And it doesn't ship on its own say-so. PatchPilot opens a real pull request, and
CodeRabbit reviews it independently.

> Use the ending that matches your take — CodeRabbit's verdict varies run to run.

**[1:50 — ENDING A · CodeRabbit approved + green "Merged" badge]**
CodeRabbit approved it, the tests passed, and PatchPilot merged it — autonomously.
The agent that writes the patch never gets to be the only one who approves it.

**[1:50 — ENDING B · CodeRabbit requested changes / gate held]** *(this is the PR #5 take)*
CodeRabbit reviewed it and pushed back — it ran a dependency scan and flagged that
the patch doesn't pin the rest of the stack. So the merge is gated: tests *and* an
independent review both have to pass. The agent that writes the patch never gets to
ship it alone.

**[2:10 — back to the all-green console]**
Detect, prove, patch, re-prove, review — end to end, in about a minute.
Unpatched CVEs sit a median of 252 days because teams can't separate real from noise.
PatchPilot proves it's exploitable, fixes it, proves it's gone — and won't ship it
until an independent reviewer signs off.

**[2:35 — end]**

---

### Timing tip
A real live run takes ~75s to open the PR, then 1–2 min for CodeRabbit. To fit 2–3
min: do one full live run **before** recording so the PR is already reviewed/merged,
then during the take use **Run live** for the streaming beats and **cut** to that
finished PR for the CodeRabbit section. Or use **Replay demo** for a guaranteed,
instant, clean run. Reset between takes with `./reset-demo.sh`.
