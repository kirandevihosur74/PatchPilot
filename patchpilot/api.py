"""Control plane for the web dashboard.

  POST /run     -> start a run (mode: "live" runs the real orchestrator; "demo"
                   replays a canned sequence — the wifi-failure backup).
  GET  /stream/{token} -> Server-Sent Events, one per loop node, live.
  GET  /meta    -> repo/config the frontend needs.
  GET  /        -> the single-page app.

Run:  uvicorn patchpilot.api:app --port 8000
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from .config import REPO_ROOT, load_config
from .orchestrator import Orchestrator

app = FastAPI(title="PatchPilot")
WEB = Path(__file__).parent / "web"

_runs: dict[str, "queue.Queue"] = {}
_SENTINEL = object()


# --- canned demo sequence (mirrors a real run; the presentation backup) ---
def _g(ep=None, cr=None, tg=None, eb=None):
    return {"exploit_proven": ep, "cve_resolved": cr, "tests_green": tg, "exploit_blocked": eb}


DEMO_EVENTS = [
    {"node": "detect", "message": "pip-audit: pyyaml==5.3.1 vulnerable → PYSEC-2021-142 (fix 6.0.1)", "goals": _g(), "_d": 1.4},
    {"node": "prove", "message": "Sandbox A: forged YAML executed code → ACCEPTED (RCE)", "goals": _g(ep=True), "_d": 1.6},
    {"node": "upgrade", "message": "bumped pyyaml 5.3.1 → 6.0.1", "goals": _g(ep=True), "_d": 1.1},
    {"node": "observe", "message": "Sandbox B: pytest → tests break (yaml.load needs Loader)", "goals": _g(ep=True), "_d": 1.4},
    {"node": "fix", "message": "Fireworks coder: patched parser.py → yaml.safe_load", "goals": _g(ep=True), "_d": 1.6},
    {"node": "verify", "message": "Sandbox B: pytest → suite green after 1 iteration", "goals": _g(ep=True, tg=True), "_d": 1.3},
    {"node": "guard", "message": "Braintrust eval: safe loader used, security preserved", "goals": _g(ep=True, cr=True, tg=True), "_d": 1.4},
    {"node": "reprove", "message": "Sandbox A: same forged YAML → BLOCKED (dead)", "goals": _g(ep=True, cr=True, tg=True, eb=True), "_d": 1.6},
    {"node": "submit", "message": "opened PR — @coderabbitai review requested", "goals": _g(ep=True, cr=True, tg=True, eb=True), "_d": 1.4},
    {"node": "gate", "message": "CI green · CodeRabbit reviewing the patch", "goals": _g(ep=True, cr=True, tg=True, eb=True), "_d": 1.2},
    {"node": "done", "message": "Proven exploitable → patched → proven dead. Review it on GitHub.",
     "goals": _g(ep=True, cr=True, tg=True, eb=True), "done": True, "_d": 0},
]


def _run_live(token: str) -> None:
    q = _runs[token]
    cfg = load_config()
    orch = Orchestrator(cfg, on_event=lambda evt: q.put(evt))
    try:
        state = orch.run()
        q.put({
            "node": "done",
            "message": ("CodeRabbit requested changes — awaiting human review"
                        if state.escalated else "Proven exploitable → patched → proven dead."),
            "goals": state.goal_snapshot(), "done": True,
            "escalated": state.escalated, "pr_url": state.pr_url,
            "cve": state.cve_id, "package": state.package,
        })
    except Exception as exc:  # surface, don't hang the stream
        q.put({"node": "error", "message": f"{type(exc).__name__}: {exc}", "done": True, "error": True})
    finally:
        q.put(_SENTINEL)


def _run_demo(token: str) -> None:
    q = _runs[token]
    for evt in DEMO_EVENTS:
        q.put({k: v for k, v in evt.items() if k != "_d"})
        time.sleep(evt.get("_d", 1.2))
    q.put(_SENTINEL)


@app.post("/run")
async def start_run(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    mode = (body or {}).get("mode", "demo")
    token = uuid.uuid4().hex[:12]
    _runs[token] = queue.Queue()
    target = _run_live if mode == "live" else _run_demo
    threading.Thread(target=target, args=(token,), daemon=True).start()
    return {"token": token, "mode": mode}


@app.get("/stream/{token}")
def stream(token: str):
    q = _runs.get(token)
    if q is None:
        return JSONResponse({"error": "unknown token"}, status_code=404)

    def gen():
        while True:
            try:
                evt = q.get(timeout=90)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            if evt is _SENTINEL:
                yield "event: end\ndata: {}\n\n"
                break
            yield f"data: {json.dumps(evt)}\n\n"
        _runs.pop(token, None)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/reset")
def reset():
    """Run reset-demo.sh — restore the vulnerable target + clean up old PRs."""
    script = REPO_ROOT / "reset-demo.sh"
    if not script.exists():
        return JSONResponse({"ok": False, "output": "reset-demo.sh not found"}, status_code=404)
    try:
        p = subprocess.run(["bash", str(script)], cwd=str(REPO_ROOT),
                           capture_output=True, text=True, timeout=120)
        return {"ok": p.returncode == 0, "output": (p.stdout + p.stderr).strip()}
    except subprocess.TimeoutExpired:
        return JSONResponse({"ok": False, "output": "reset timed out"}, status_code=504)


@app.get("/meta")
def meta():
    cfg = load_config()
    return {"repo": cfg.github_repo, "repo_url": f"https://github.com/{cfg.github_repo}" if cfg.github_repo else ""}


@app.get("/", response_class=HTMLResponse)
def index():
    return (WEB / "index.html").read_text()
