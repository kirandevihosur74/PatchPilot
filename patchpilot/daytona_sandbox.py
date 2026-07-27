"""Daytona-backed Sandbox — the real isolation the pitch depends on.

Implements the same interface as LocalSandbox (see sandbox.py) using the
`daytona` SDK (>= v0.21, `from daytona import ...`). The sandbox itself IS the
isolation boundary, so there's no nested venv: we pip-install into the sandbox's
Python directly.
"""

from __future__ import annotations

import os
import shlex
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
        # Private by default (preview uses a signed, expiring URL); opt in to a
        # token-free public link via config. Auto-stop/delete reaps a sandbox we
        # leave running to serve its preview.
        self._sandbox = self._daytona.create(
            CreateSandboxFromSnapshotParams(
                language="python", public=self._config.daytona_public_preview,
                auto_stop_interval=15, auto_delete_interval=60,
            ),
            timeout=180,
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
        assert self._sandbox is not None, "sandbox not started"
        if not requirements:
            return ExecResult(0, "", "")
        # Match LocalSandbox: only install if the file is actually present.
        check = self.exec(f"test -f {shlex.quote(requirements)} && echo __OK__")
        if "__OK__" not in check.output:
            return ExecResult(0, "", "")
        return self.exec(f"python -m pip install -r {shlex.quote(requirements)}")

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

    # --- preview (the real Daytona sandbox web preview) ---
    def serve(self, port: int, cwd_rel: str = ".") -> None:
        """Start a long-lived HTTP server inside the sandbox on `port`, serving
        `cwd_rel`. Uses a session so the process outlives this exec call."""
        assert self._sandbox is not None, "sandbox not started"
        from daytona import SessionExecuteRequest

        workdir = REPO_DIR if cwd_rel in (".", "", None) else f"{REPO_DIR}/{cwd_rel}"
        sid = f"preview-{port}"
        try:
            self._sandbox.process.create_session(sid)
        except Exception:
            pass  # session may already exist
        self._sandbox.process.execute_session_command(
            sid,
            SessionExecuteRequest(command=f"cd {workdir} && python -m http.server {port}", run_async=True),
        )

    def get_preview_url(self, port: int):
        """Return (url, token) for a port served inside the sandbox, or (None, None).

        Private sandboxes (the default) get a signed, expiring URL that opens in
        the browser without a header; a public sandbox gets the plain link."""
        assert self._sandbox is not None, "sandbox not started"
        try:
            if self._config.daytona_public_preview:
                info = self._sandbox.get_preview_link(port)
                return getattr(info, "url", None), getattr(info, "token", None)
            info = self._sandbox.create_signed_preview_url(port, expires_in_seconds=3600)
            return getattr(info, "url", None), ""
        except Exception:
            return None, None
