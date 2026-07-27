"""Real dependency scanning for an arbitrary Python repo (runs inside a sandbox).

Discovers the repo's dependency manifests, resolves/installs what it needs, and
runs `pip-audit` to surface EVERY known-vulnerable dependency — not a hardcoded
CVE. Everything here executes through a Sandbox, never in the control plane.

Python-first, deep: requirements*.txt / pyproject.toml / poetry.lock / Pipfile.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any, Callable, Optional

# Manifests we know how to reason about, in rough priority order.
REQUIREMENTS_RE = re.compile(r"(?i)^(requirements[\w.-]*\.txt|requirements/.+\.txt)$")
PYPROJECT = "pyproject.toml"
POETRY_LOCK = "poetry.lock"
PIPFILE = "Pipfile"
PIPFILE_LOCK = "Pipfile.lock"
SETUP_PY = "setup.py"
SETUP_CFG = "setup.cfg"

# npm (detection + reachability only; no remediation yet).
PACKAGE_LOCK = "package-lock.json"
PACKAGE_JSON = "package.json"
OSV_API = "https://api.osv.dev"

Log = Optional[Callable[[str], None]]


def _emit(log: Log, msg: str) -> None:
    if log:
        log(msg)


def discover_manifests(sb) -> list[str]:
    """Return the dependency manifests present at the repo root (depth<=2).

    Uses `find` in the sandbox so it works on any cloned repo layout."""
    # Limit depth so we don't crawl vendored deps; skip common noise dirs.
    cmd = (
        "find . -maxdepth 2 "
        r"\( -path ./.git -o -path './*/.git' -o -name node_modules -o -name .venv "
        r"-o -name venv -o -name site-packages \) -prune -o -type f "
        r"\( -iname 'requirements*.txt' -o -name pyproject.toml -o -name poetry.lock "
        r"-o -name Pipfile -o -name Pipfile.lock -o -name setup.py -o -name setup.cfg "
        r"-o -name package-lock.json -o -name package.json \) -print"
    )
    out = sb.exec(cmd).output
    found = []
    for line in out.splitlines():
        name = line.strip().removeprefix("./")
        if name:
            found.append(name)
    return sorted(set(found))


def _requirements_files(manifests: list[str]) -> list[str]:
    return [m for m in manifests if REQUIREMENTS_RE.match(m) or m.lower().startswith("requirements")]


def scan(sb, manifests: Optional[list[str]] = None, log: Log = None) -> list[dict[str, Any]]:
    """Discover + audit the repo. Returns a de-duplicated, ranked list of
    Vulnerability dicts. Never raises on a scan miss — returns [] instead."""
    if manifests is None:
        manifests = discover_manifests(sb)
    _emit(log, f"found {len(manifests)} manifest(s): {', '.join(manifests) or 'none'}")

    vulns: list[dict[str, Any]] = []
    req_files = _requirements_files(manifests)
    has_python = bool(req_files) or any(
        m in (PYPROJECT, POETRY_LOCK, PIPFILE, PIPFILE_LOCK, SETUP_PY, SETUP_CFG) for m in manifests)
    npm_locks = [m for m in manifests if m.endswith(PACKAGE_LOCK)]

    if has_python:
        sb.exec(f"{sb.py()} -m pip install --quiet --upgrade pip-audit")
        if req_files:
            # Audit pinned requirements directly — no full install needed, most reliable.
            for req in req_files:
                _emit(log, f"scanning {req}")
                res = sb.exec(f"{sb.py()} -m pip_audit -r {shlex.quote(req)} -f json --progress-spinner off")
                vulns.extend(_parse_pip_audit(res.output, manifest=req))
        else:
            # No plain requirements: install the project, then audit the environment.
            _emit(log, "installing project to audit the resolved environment")
            _install_project(sb, manifests, log)
            res = sb.exec(f"{sb.py()} -m pip_audit -f json --progress-spinner off")
            vulns.extend(_parse_pip_audit(res.output, manifest="(installed environment)"))

    for lock in npm_locks:
        _emit(log, f"scanning {lock} (npm)")
        vulns.extend(_scan_npm(sb, lock, log))

    if not has_python and not npm_locks:
        _emit(log, "no recognized Python or npm manifest — nothing to scan")
        return []

    ranked = _dedupe_and_rank(vulns)
    _emit(log, f"scan complete: {len(ranked)} vulnerable dependenc(y/ies)")
    return ranked


def _install_project(sb, manifests: list[str], log: Log) -> None:
    """Best-effort install so pip-audit can read the resolved environment."""
    try:
        if POETRY_LOCK in manifests or PYPROJECT in manifests:
            # Prefer a plain PEP 517 install; poetry export path is a future refinement.
            sb.exec(f"{sb.py()} -m pip install --quiet .")
        elif PIPFILE_LOCK in manifests or PIPFILE in manifests:
            sb.exec(f"{sb.py()} -m pip install --quiet pipenv && {sb.py()} -m pipenv install --skip-lock")
        elif SETUP_PY in manifests or SETUP_CFG in manifests:
            sb.exec(f"{sb.py()} -m pip install --quiet .")
    except Exception as exc:  # scanning must survive an install miss
        _emit(log, f"install best-effort failed ({type(exc).__name__}); auditing whatever installed")


def _parse_pip_audit(output: str, manifest: str = "") -> list[dict[str, Any]]:
    """Parse `pip-audit -f json` into Vulnerability dicts. Tolerates the mixed
    stdout/stderr blob a sandbox returns by slicing to the JSON object."""
    vulns: list[dict[str, Any]] = []
    try:
        blob = output[output.find("{"): output.rfind("}") + 1]
        data = json.loads(blob)
    except Exception:
        return vulns

    deps = data.get("dependencies", data.get("results", []))
    for dep in deps:
        name = dep.get("name", "")
        version = dep.get("version", "")
        for v in dep.get("vulns", []) or []:
            vulns.append({
                "package": name,
                "installed_version": version,
                "vuln_id": v.get("id", ""),
                "aliases": v.get("aliases", []) or [],
                "fix_versions": v.get("fix_versions", []) or [],
                "severity": _severity_of(v),
                "summary": (v.get("description", "") or "").strip().split("\n")[0][:280],
                "manifest": manifest,
                "ecosystem": "PyPI",
            })
    return vulns


# --- npm (detect + reachability only) ---

def _scan_npm(sb, lockfile: str, log: Log = None) -> list[dict[str, Any]]:
    """Read an npm lockfile, resolve its packages, and query OSV for vulns."""
    try:
        data = json.loads(sb.read_file(lockfile))
    except Exception:
        _emit(log, f"could not read/parse {lockfile}")
        return []
    pairs = _parse_package_lock(data)
    if not pairs:
        return []
    _emit(log, f"querying OSV for {len(pairs)} npm package(s)")
    try:
        return _osv_query_npm(pairs, lockfile)
    except Exception as exc:  # network/API miss must not fail the whole scan
        _emit(log, f"npm/OSV query failed ({type(exc).__name__})")
        return []


def _parse_package_lock(data: dict) -> list[tuple[str, str]]:
    """Extract (name, version) from a package-lock.json (v1 or v2/v3)."""
    pairs: set[tuple[str, str]] = set()
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2/v3
        for path, info in packages.items():
            if not path or not isinstance(info, dict):
                continue  # "" is the root project
            name = path.split("node_modules/")[-1]
            ver = info.get("version")
            if name and ver:
                pairs.add((name, ver))
    deps = data.get("dependencies")
    if isinstance(deps, dict):  # lockfile v1 (nested)
        def walk(node: dict) -> None:
            for name, info in node.items():
                if not isinstance(info, dict):
                    continue
                ver = info.get("version")
                if ver:
                    pairs.add((name, ver))
                if isinstance(info.get("dependencies"), dict):
                    walk(info["dependencies"])
        walk(deps)
    return sorted(pairs)


def _osv_query_npm(pairs: list[tuple[str, str]], manifest: str) -> list[dict[str, Any]]:
    """Batch-query OSV for which npm packages are vulnerable, then fetch details."""
    import httpx

    with httpx.Client(timeout=30) as client:
        results: list[dict] = []
        for i in range(0, len(pairs), 500):  # OSV batch cap
            chunk = pairs[i:i + 500]
            queries = [{"version": v, "package": {"name": n, "ecosystem": "npm"}} for n, v in chunk]
            r = client.post(f"{OSV_API}/v1/querybatch", json={"queries": queries})
            r.raise_for_status()
            results.extend(r.json().get("results", []))

        # Which (name, version) pairs have vulns, and the vuln ids to detail-fetch.
        wanted: dict[str, tuple[str, str]] = {}
        for (name, ver), res in zip(pairs, results):
            for vd in (res.get("vulns") or []):
                wanted.setdefault(vd["id"], (name, ver))

        out: list[dict[str, Any]] = []
        for vid, (name, ver) in wanted.items():
            try:
                detail = client.get(f"{OSV_API}/v1/vulns/{vid}").json()
            except Exception:
                continue
            out.append(_osv_to_vuln(detail, name, ver, manifest))
    return out


def _osv_to_vuln(d: dict, name: str, version: str, manifest: str) -> dict[str, Any]:
    fixes: list[str] = []
    for aff in d.get("affected", []) or []:
        p = aff.get("package", {})
        if p.get("ecosystem") == "npm" and p.get("name") == name:
            for rng in aff.get("ranges", []) or []:
                for ev in rng.get("events", []) or []:
                    if ev.get("fixed"):
                        fixes.append(ev["fixed"])
    severity = ""
    for s in d.get("severity", []) or []:
        severity = s.get("score", "") or severity
    summary = (d.get("summary") or d.get("details") or "").strip().split("\n")[0][:280]
    # Prefer a CVE alias as the display id when present.
    vid = d.get("id", "")
    cve = next((a for a in (d.get("aliases") or []) if a.startswith("CVE-")), "")
    return {
        "package": name,
        "installed_version": version,
        "vuln_id": cve or vid,
        "aliases": [a for a in (d.get("aliases") or []) if a != (cve or vid)] + ([vid] if cve else []),
        "fix_versions": sorted(set(fixes)),
        "severity": severity,
        "summary": summary,
        "manifest": manifest,
        "ecosystem": "npm",
    }


def _severity_of(vuln: dict[str, Any]) -> str:
    """pip-audit doesn't always carry severity; surface it when present."""
    sev = vuln.get("severity") or vuln.get("cvss") or ""
    if isinstance(sev, dict):
        return sev.get("score", sev.get("level", "")) or ""
    return str(sev)


def _dedupe_and_rank(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse duplicates (same package+id across manifests) and order so the
    most actionable (has a fix) surface first. Reachability re-ranks later."""
    seen: dict[tuple, dict[str, Any]] = {}
    for v in vulns:
        key = (v["package"].lower(), v["vuln_id"])
        if key not in seen:
            seen[key] = v
    def sort_key(v: dict[str, Any]):
        return (0 if v["fix_versions"] else 1, v["package"].lower(), v["vuln_id"])
    return sorted(seen.values(), key=sort_key)
