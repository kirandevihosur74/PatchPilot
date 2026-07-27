"""Reachability analysis — the real proof of exploitability.

A scanner tells you a vulnerable *version* is present. This tells you whether the
vulnerable code is actually reachable in the repo: is the affected package
imported, and is its dangerous API actually called? That's the difference between
"you have it" and "you're exposed."

Runs on source *text* only. `ast.parse` builds a syntax tree without executing a
single line, so analyzing an untrusted repo's code here is safe — no sandbox
needed for the parse itself.

Limitation (honest): this measures DIRECT reachability in the repo's own code. A
vulnerable transitive dependency the repo never imports shows as `not-imported`,
which is correct for "is YOUR code calling it" but does not model exploitation
through an intermediate library.
"""

from __future__ import annotations

import ast
import re
from typing import Any, Optional

# verdict -> (rank score, confidence). Higher score = more likely exploitable.
_VERDICTS = {
    "vulnerable-api-called": (3, "high"),
    "package-called": (2, "medium"),
    "package-imported": (2, "medium"),   # JS/TS: import-level (coarser than Python's call-level)
    "imported-unused": (1, "low"),
    "not-imported": (0, "none"),
}
_REACHABLE = {"vulnerable-api-called", "package-called", "package-imported"}


def analyze(sources: dict[str, str], vuln: dict[str, Any], knowledge) -> dict[str, Any]:
    """Return a reachability verdict for one vuln against the repo's sources.

    `sources` is {relative_path: file_text}. `knowledge` is the knowledge module.
    """
    roots = set(knowledge.import_names(vuln.get("package", "")))
    affected = knowledge.affected_symbols(vuln)  # set[str] | None

    imported = False
    package_sites: list[dict[str, Any]] = []
    vuln_sites: list[dict[str, Any]] = []

    for path, src in sources.items():
        try:
            tree = ast.parse(src)
        except (SyntaxError, ValueError):
            continue  # skip files we can't parse (py2, templates, etc.)

        module_aliases, from_imports, this_imported = _collect_imports(tree, roots)
        imported = imported or this_imported
        if not this_imported:
            continue

        lines = src.splitlines()
        for call in _iter_calls(tree):
            hit = _match_call(call, module_aliases, from_imports)
            if hit is None:
                continue
            symbol = hit
            site = {"file": path, "line": call.lineno, "snippet": _snippet(lines, call.lineno)}
            package_sites.append(site)
            if affected and symbol in affected:
                vuln_sites.append({**site, "symbol": symbol})

    verdict = _grade(imported, package_sites, vuln_sites)
    symbols = sorted({s["symbol"] for s in vuln_sites})
    return _result(verdict, (vuln_sites or package_sites), symbols)


def analyze_js(sources: dict[str, str], vuln: dict[str, Any]) -> dict[str, Any]:
    """Import-level reachability for an npm package in JS/TS sources.

    Detects `import ... from 'pkg'`, `import 'pkg'`, `require('pkg')`, and
    `import('pkg')` (including subpath imports like 'pkg/sub'). This is coarser
    than the Python call-level analysis — it answers "is the vulnerable package
    imported in this code" rather than "is the vulnerable function called."
    """
    pkg = vuln.get("package", "")
    if not pkg:
        return _result("not-imported", [])
    spec = re.escape(pkg)
    pat = re.compile(rf"""(?:require\(|import\(|from|import)\s*['"]{spec}(?:/[^'"]*)?['"]""")
    sites: list[dict[str, Any]] = []
    for path, src in sources.items():
        for i, line in enumerate(src.splitlines(), 1):
            if pat.search(line):
                sites.append({"file": path, "line": i, "snippet": line.strip()[:160]})
    return _result("package-imported" if sites else "not-imported", sites)


def _result(verdict: str, sites: list, affected_symbols: Optional[list] = None) -> dict[str, Any]:
    score, confidence = _VERDICTS[verdict]
    return {
        "verdict": verdict,
        "confidence": confidence,
        "score": score,
        "reachable": verdict in _REACHABLE,
        "affected_symbols": affected_symbols or [],
        "call_sites": sites[:12],
    }


def rank_key(vuln: dict[str, Any]):
    """Sort key so reachable + fixable vulns surface first."""
    r = vuln.get("reachability") or {}
    score = r.get("score", 0)
    has_fix = 1 if vuln.get("fix_versions") else 0
    return (-score, -has_fix, (vuln.get("package") or "").lower(), vuln.get("vuln_id") or "")


# --- internals ---

def _collect_imports(tree: ast.AST, roots: set[str]):
    """Map local names to the target package.

    Returns (module_aliases, from_imports, imported):
      module_aliases: local name -> True  (for `import pkg` / `import pkg as p`)
      from_imports:   local name -> original attr  (for `from pkg import x as y`)
    """
    module_aliases: dict[str, bool] = {}
    from_imports: dict[str, str] = {}
    imported = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root in roots or a.name in roots:
                    imported = True
                    module_aliases[a.asname or root] = True
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.split(".")[0] in roots or mod in roots:
                imported = True
                for a in node.names:
                    from_imports[a.asname or a.name] = a.name
    return module_aliases, from_imports, imported


def _iter_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def _match_call(call: ast.Call, module_aliases: dict[str, bool],
                from_imports: dict[str, str]) -> Optional[str]:
    """If this call targets the package, return the called symbol name, else None."""
    func = call.func
    # pkg.func(...) or alias.func(...)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id in module_aliases:
            return func.attr
    # from pkg import func; func(...)  (possibly aliased)
    if isinstance(func, ast.Name) and func.id in from_imports:
        return from_imports[func.id]
    return None


def _grade(imported: bool, package_sites: list, vuln_sites: list) -> str:
    if vuln_sites:
        return "vulnerable-api-called"
    if package_sites:
        return "package-called"
    if imported:
        return "imported-unused"
    return "not-imported"


def _snippet(lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""
