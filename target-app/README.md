# Config Ingest Service

> ⚠️ **INTENTIONALLY VULNERABLE DEMO TARGET — DO NOT DEPLOY.**
> This service pins `PyYAML==5.3.1` and ships an exploit script on purpose. It is
> the target application that [PatchPilot](../) scans, exploits, patches, and
> re-verifies. It exists to be attacked in an isolated sandbox.

A tiny FastAPI service that ingests YAML config documents.

## The vulnerability

`PyYAML==5.3.1` is affected by **CVE-2020-14343** (PYSEC-2021-142): a crafted YAML
document defeats the default FullLoader and reaches arbitrary code execution. The
service calls `yaml.load()` with no `Loader` at three sites in `parser.py`; the
untrusted one is `parse_request`, reachable via `POST /config`.

## What PatchPilot does to it

1. **Detect** — `pip-audit` flags PyYAML 5.3.1 (PYSEC-2021-142).
2. **Prove** — `exploit.py` sends a malicious document → code executes (ACCEPTED).
3. **Upgrade** — bump PyYAML to `>=6.0`.
4. **Observe** — every `yaml.load()` call site now raises `TypeError` (Loader required).
5. **Fix** — add `Loader=yaml.SafeLoader` at each site.
6. **Guard** — reject the weaken-to-pass fix (`Loader=yaml.Loader`, which keeps the RCE).
7. **Re-prove** — `exploit.py` runs again → payload blocked (REJECTED).

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q          # suite passes on 5.3.1
.venv/bin/python exploit.py            # prints EXPLOIT ACCEPTED, exit 0
.venv/bin/uvicorn app:app --reload     # serve on :8000
```
