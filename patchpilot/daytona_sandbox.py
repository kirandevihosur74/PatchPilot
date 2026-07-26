"""Daytona-backed Sandbox — the real isolation the pitch depends on.

Implements the same interface as LocalSandbox (see sandbox.py) using the
`daytona` SDK (>= v0.21, `from daytona import ...`). The sandbox itself IS the
isolation boundary, so there's no nested venv: we pip-install into the sandbox's
Python directly.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from .sandbox import ExecResult

REPO_DIR = "repo"  # relative to the sandbox home


class DaytonaSandbox:
    def __init__(self, config, label: str = "sandbox") -> None:
        self.label = label
        self._config = config
        self._daytona = None
        self._sandbox = None

    # --- lifecycle ---
    def start(self) -> None:
        from daytona import Daytona, DaytonaConfig, CreateSandboxFromSnapshotParams

        cfg_kwargs = {"api_key": self._config.daytona_api_key}
        if self._config.daytona_api_url:
            cfg_kwargs["api_url"] = self._config.daytona_api_url
        if self._config.daytona_target:
            cfg_kwargs["target"] = self._config.daytona_target
        self._daytona = Daytona(DaytonaConfig(**cfg_kwargs))
        self._sandbox = self._daytona.create(
            CreateSandboxFromSnapshotParams(language="python"), timeout=180
        )

    def stop(self) -> None:
        if self._sandbox is not None:
            try:
                self._sandbox.delete()
            except Exception:
                pass
        self._sandbox = self._daytona = None

    def __enter__(self) -> "DaytonaSandbox":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # --- code in ---
    def load_repo(self, source: str) -> None:
        assert self._sandbox is not None, "sandbox not started"
        if source.startswith(("http://", "https://", "git@")):
            self._sandbox.git.clone(url=source, path=REPO_DIR)
        else:
            self._upload_dir(Path(source), REPO_DIR)

    def _upload_dir(self, local_root: Path, dest_root: str) -> None:
        skip = {".venv", ".sbvenv", "__pycache__", ".git", ".pytest_cache"}
        for path in local_root.rglob("*"):
            if path.is_dir() or any(part in skip for part in path.parts):
                continue
            if path.suffix == ".pyc":
                continue
            rel = path.relative_to(local_root).as_posix()
            self._sandbox.fs.upload_file(str(path), f"{dest_root}/{rel}")

    def setup(self, requirements: Optional[str] = "requirements.txt") -> ExecResult:
        if not requirements:
            return ExecResult(0, "", "")
        return self.exec(f"python -m pip install -r {requirements}")

    def py(self) -> str:
        return "python"

    # --- exec ---
    def exec(self, cmd: str, cwd: Optional[str] = None) -> ExecResult:
        assert self._sandbox is not None, "sandbox not started"
        workdir = REPO_DIR if not cwd else f"{REPO_DIR}/{cwd}"
        resp = self._sandbox.process.exec(cmd, cwd=workdir, timeout=600)
        # ExecuteResponse exposes .exit_code and .result (combined output).
        exit_code = getattr(resp, "exit_code", 0) or 0
        output = getattr(resp, "result", "") or ""
        return ExecResult(exit_code, output, "")

    # --- files ---
    def read_file(self, rel_path: str) -> str:
        return self.exec(f"cat {rel_path}").stdout

    def write_file(self, rel_path: str, content: str) -> None:
        assert self._sandbox is not None, "sandbox not started"
        self._sandbox.fs.upload_file(content.encode("utf-8"), f"{REPO_DIR}/{rel_path}")
