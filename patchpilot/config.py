"""Central configuration — everything is driven by environment variables so the
same code runs with real sponsor services or in local fallback mode.

Load order: real process env wins; a `.env` file at the repo root fills gaps.
No hard dependency on python-dotenv (tiny parser below) to keep setup trivial.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = REPO_ROOT / "target-app"


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, `#` comments, optional quotes.
    Does not overwrite variables already present in the environment."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(REPO_ROOT / ".env")


@dataclass
class Config:
    # --- Fireworks (generate) ---
    fireworks_api_key: str = field(default_factory=lambda: os.getenv("FIREWORKS_API_KEY", ""))
    fireworks_base_url: str = field(
        default_factory=lambda: os.getenv("FIREWORKS_BASE_URL", "https://api.fireworks.ai/inference/v1")
    )
    # Overridable model ids (defaults are filled from SDK research; see llm.py).
    triage_model: str = field(default_factory=lambda: os.getenv("FIREWORKS_TRIAGE_MODEL", ""))
    coder_model: str = field(default_factory=lambda: os.getenv("FIREWORKS_CODER_MODEL", ""))

    # --- Daytona (isolate) ---
    daytona_api_key: str = field(default_factory=lambda: os.getenv("DAYTONA_API_KEY", ""))
    daytona_api_url: str = field(default_factory=lambda: os.getenv("DAYTONA_API_URL", ""))
    daytona_target: str = field(default_factory=lambda: os.getenv("DAYTONA_TARGET", ""))

    # --- Braintrust (evaluate) ---
    braintrust_api_key: str = field(default_factory=lambda: os.getenv("BRAINTRUST_API_KEY", ""))
    braintrust_project: str = field(default_factory=lambda: os.getenv("BRAINTRUST_PROJECT", "PatchPilot"))

    # --- GitHub / CodeRabbit (review) ---
    github_token: str = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    github_repo: str = field(default_factory=lambda: os.getenv("GITHUB_REPO", ""))  # "owner/name"
    # Subdir in the repo where the target app lives (PR paths get this prefix).
    repo_subdir: str = field(default_factory=lambda: os.getenv("PATCHPILOT_REPO_SUBDIR", "").strip("/"))

    # --- run knobs ---
    target_path: str = field(default_factory=lambda: os.getenv("PATCHPILOT_TARGET", str(DEFAULT_TARGET)))
    patched_version: str = field(default_factory=lambda: os.getenv("PATCHPILOT_PATCHED_VERSION", "6.0.1"))
    max_fix_iterations: int = field(default_factory=lambda: int(os.getenv("PATCHPILOT_MAX_ITERS", "3")))
    # Auto-merge the PR when the gate is green. Off -> open PR, report verdict, stop.
    auto_merge: bool = field(
        default_factory=lambda: os.getenv("PATCHPILOT_AUTO_MERGE", "true").lower() in ("1", "true", "yes")
    )
    force_local_sandbox: bool = field(
        default_factory=lambda: os.getenv("PATCHPILOT_LOCAL_SANDBOX", "").lower() in ("1", "true", "yes")
    )
    # Demo toggle: make the offline fixer weaken security (yaml.Loader) so the
    # GUARD/eval is seen catching a "weaken-to-pass" fix live.
    force_unsafe_fix: bool = field(
        default_factory=lambda: os.getenv("PATCHPILOT_FORCE_UNSAFE_FIX", "").lower() in ("1", "true", "yes")
    )

    # --- capability flags (what's actually wired) ---
    @property
    def has_fireworks(self) -> bool:
        return bool(self.fireworks_api_key)

    @property
    def has_daytona(self) -> bool:
        return bool(self.daytona_api_key) and not self.force_local_sandbox

    @property
    def has_braintrust(self) -> bool:
        return bool(self.braintrust_api_key)

    @property
    def has_github(self) -> bool:
        return bool(self.github_token and self.github_repo)

    def summary(self) -> str:
        rows = [
            ("Fireworks (generate)", self.has_fireworks),
            ("Daytona (isolate)", self.has_daytona),
            ("Braintrust (evaluate)", self.has_braintrust),
            ("GitHub/CodeRabbit (review)", self.has_github),
        ]
        lines = [f"  {'[on] ' if ok else '[off]'} {name}" for name, ok in rows]
        return "PatchPilot config:\n" + "\n".join(lines)


def load_config() -> Config:
    return Config()
