"""Control plane for the web dashboard.

  POST /run     -> start a run on a pasted GitHub repo (body: {"repo_url": ...}).
  GET  /stream/{token} -> Server-Sent Events, streamed live as the run progresses.
  GET  /meta    -> capability flags the frontend needs (which services are wired).
  GET  /        -> the single-page app.

The control plane NEVER executes the target repo's code — cloning, installing and
scanning all happen inside a Sandbox (Daytona in production, local as a fallback).

Run:  uvicorn patchpilot.api:app --port 8000
"""

from __future__ import annotations

import json
import queue
import re
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from .config import load_config
from .orchestrator import Orchestrator

app = FastAPI(title="PatchPilot")
WEB = Path(__file__).parent / "web"

_runs: dict[str, "queue.Queue"] = {}
_SENTINEL = object()

_REPO_RE = re.compile(r"^https?://github\.com/[\w.-]+/[\w.-]+/?$|^git@github\.com:[\w.-]+/[\w.-]+(\.git)?$")


def _valid_repo_url(url: str) -> bool:
    return bool(url) and bool(_REPO_RE.match(url.strip()))


def _run_live(token: str, repo_url: str) -> None:
    q = _runs[token]
    cfg = load_config()
    orch = Orchestrator(cfg, on_event=lambda evt: q.put(evt), repo_url=repo_url)
    try:
        state = orch.run()
        n = len(state.vulns)
        if state.escalated:
            msg = f"stopped: {state.escalation_reason}"
        elif n == 0:
            msg = "No known-vulnerable dependencies found."
        else:
            tv = state.target_vuln or {}
            msg = (f"Found {n} vulnerable dependenc{'y' if n == 1 else 'ies'}. "
                   f"Top target: {tv.get('package','?')} {tv.get('vuln_id','')}")
        q.put({
            "node": "done", "message": msg, "goals": state.goal_snapshot(),
            "done": True, "escalated": state.escalated,
            "vulns": state.vulns, "target": state.target_vuln,
            "preview_url": state.preview_url, "pr_url": state.pr_url,
        })
    except Exception as exc:  # surface, don't hang the stream
        q.put({"node": "error", "message": f"{type(exc).__name__}: {exc}", "done": True, "error": True})
    finally:
        q.put(_SENTINEL)


@app.post("/run")
async def start_run(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):  # JSON allows lists/scalars — those have no .get
        body = {}
    repo_url = str(body.get("repo_url", "")).strip()
    if not _valid_repo_url(repo_url):
        return JSONResponse(
            {"error": "Provide a GitHub repo URL, e.g. https://github.com/owner/name"},
            status_code=400,
        )
    token = uuid.uuid4().hex[:12]
    _runs[token] = queue.Queue()
    threading.Thread(target=_run_live, args=(token, repo_url), daemon=True).start()
    return {"token": token}


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


@app.get("/meta")
def meta():
    cfg = load_config()
    return {
        "has_daytona": cfg.has_daytona,
        "has_fireworks": cfg.has_fireworks,
        "has_braintrust": cfg.has_braintrust,
        "has_github": cfg.has_github,
    }


@app.get("/", response_class=HTMLResponse)
def index():
    return (WEB / "index.html").read_text()
