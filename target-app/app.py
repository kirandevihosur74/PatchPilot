"""Config Ingest Service — the PatchPilot demo target.

Accepts YAML config documents over HTTP and parses them. Deliberately vulnerable
(see parser.py, pinned PyYAML==5.3.1). Do not deploy.
"""

from fastapi import FastAPI, Request, HTTPException

import parser

app = FastAPI(title="Config Ingest Service")

# Trusted settings the service loads at startup.
DEFAULT_SETTINGS = """
service:
  name: ingest
  max_items: 100
"""

SETTINGS = parser.load_settings(DEFAULT_SETTINGS)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": SETTINGS["service"]["name"]}


@app.post("/config")
async def ingest_config(request: Request) -> dict:
    """Parse a client-supplied YAML config body and echo the result."""
    body = (await request.body()).decode("utf-8")
    try:
        parsed = parser.parse_request(body)
    except Exception as exc:  # noqa: BLE001 - demo surface
        raise HTTPException(status_code=400, detail=f"parse error: {exc}")
    return {"parsed": parsed}
