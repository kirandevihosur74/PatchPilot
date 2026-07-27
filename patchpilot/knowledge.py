"""Curated, extensible knowledge for reachability + the security guard.

Everything here degrades honestly: when we don't have an entry for a package we
fall back to a weaker (clearly-labelled) signal rather than guessing. None of
this is required for the scanner to work — it sharpens the reachability verdict.
"""

from __future__ import annotations

import re
from typing import Any, Optional

# PyPI distribution name -> the name(s) you actually `import`. Most match after
# normalization; these are the well-known exceptions.
PACKAGE_IMPORT_NAMES: dict[str, list[str]] = {
    "pyyaml": ["yaml"],
    "beautifulsoup4": ["bs4"],
    "pillow": ["PIL"],
    "pyjwt": ["jwt"],
    "scikit-learn": ["sklearn"],
    "python-dateutil": ["dateutil"],
    "opencv-python": ["cv2"],
    "msgpack-python": ["msgpack"],
    "protobuf": ["google.protobuf"],
    "setuptools": ["setuptools", "pkg_resources"],
    "attrs": ["attr", "attrs"],
    "pycryptodome": ["Crypto"],
}

# Affected callable(s) per package (the dangerous entry points). Keyed by the
# normalized PyPI name; a vuln_id key takes precedence when we know the exact fn.
VULN_API_BY_PACKAGE: dict[str, set[str]] = {
    "pyyaml": {"load", "load_all", "unsafe_load", "unsafe_load_all", "full_load", "full_load_all"},
    "jinja2": {"from_string", "Template"},                      # SSTI-adjacent surface
    "requests": {"get", "post", "put", "delete", "patch", "request", "head"},
    "urllib3": {"PoolManager", "HTTPConnectionPool", "request"},
    "lxml": {"parse", "fromstring", "XML"},
    "pycryptodome": {"new"},
}

VULN_API_BY_ID: dict[str, set[str]] = {
    # High-precision overrides where a CVE names a specific function.
    "PYSEC-2021-142": {"load", "load_all", "full_load", "full_load_all"},  # PyYAML FullLoader RCE
}

# Security-guard rules: patterns that mean a "fix" kept the vulnerability alive.
# Default (no rule) -> rely on the version-range check + the repo's own tests.
GUARD_RULES: dict[str, list[str]] = {
    "pyyaml": [
        r"yaml\.unsafe_load\s*\(",
        r"Loader\s*=\s*yaml\.Loader\b",
        r"Loader\s*=\s*yaml\.FullLoader\b",
        r"Loader\s*=\s*yaml\.UnsafeLoader\b",
    ],
}


def _norm(package: str) -> str:
    return re.sub(r"[-_.]+", "-", (package or "").strip().lower())


def import_names(package: str) -> list[str]:
    """Candidate import roots for a PyPI distribution name."""
    key = _norm(package)
    if key in PACKAGE_IMPORT_NAMES:
        return PACKAGE_IMPORT_NAMES[key]
    # Fallback: import name is usually the dist name with '-' -> '_'.
    guess = key.replace("-", "_")
    variants = {guess, key.replace("-", "")}
    return sorted(variants)


def affected_symbols(vuln: dict[str, Any]) -> Optional[set[str]]:
    """The vulnerable callables for this finding, or None when unknown.

    None is meaningful: it tells the analyzer to fall back to 'package is called'
    rather than claim a precise vulnerable-API hit it can't support."""
    vid = vuln.get("vuln_id", "")
    if vid in VULN_API_BY_ID:
        return VULN_API_BY_ID[vid]
    for alias in vuln.get("aliases", []) or []:
        if alias in VULN_API_BY_ID:
            return VULN_API_BY_ID[alias]
    key = _norm(vuln.get("package", ""))
    return VULN_API_BY_PACKAGE.get(key)


def guard_patterns(package: str) -> list[str]:
    return GUARD_RULES.get(_norm(package), [])
