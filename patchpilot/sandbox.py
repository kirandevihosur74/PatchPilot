"""Isolation layer. Everything dangerous (running the exploit, running the patch
loop) happens inside a Sandbox — never in the control plane.

Two implementations behind one interface:
  * DaytonaSandbox — real isolated cloud sandbox (see daytona_sandbox.py).
  * LocalSandbox   — subprocess in a throwaway temp dir + venv, for local dev and
    as a fallback when no Daytona key is set. Same interface, so the loop code is
    identical either way.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def output(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()


class Sandbox(Protocol):
    label: str

    def start(self) -> None: ...
    def load_repo(self, source: str) -> None: ...
    def setup(self, requirements: str = "requirements.txt") -> ExecResult: ...
    def py(self) -> str: ...
    def exec(self, cmd: str, cwd: Optional[str] = None) -> ExecResult: ...
    def read_file(self, rel_path: str) -> str: ...
    def write_file(self, rel_path: str, content: str) -> None: ...
    def stop(self) -> None: ...

    def __enter__(self) -> "Sandbox": ...
    def __exit__(self, *exc: object) -> None: ...


class LocalSandbox:
    """Runs commands in an isolated temp copy of the repo with its own venv."""

    def __init__(self, label: str = "local") -> None:
        self.label = label
        self._root: Optional[Path] = None
        self._repo: Optional[Path] = None
        self._py: Optional[Path] = None  # python inside the sandbox venv

    # --- lifecycle ---
    def start(self) -> None:
        self._root = Path(tempfile.mkdtemp(prefix=f"patchpilot-{self.label}-"))

    def stop(self) -> None:
        if self._root and self._root.exists():
            shutil.rmtree(self._root, ignore_errors=True)
        self._root = self._repo = self._py = None

    def __enter__(self) -> "LocalSandbox":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # --- code in ---
    def load_repo(self, source: str) -> None:
        """`source` is a local path (copied) or a git URL (cloned)."""
        assert self._root is not None, "sandbox not started"
        self._repo = self._root / "repo"
        if source.startswith(("http://", "https://", "git@")):
            self._run(["git", "clone", "--depth", "1", source, str(self._repo)], self._root)
        else:
            shutil.copytree(
                source, self._repo,
                ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", ".git", "*.pyc"),
            )

    def setup(self, requirements: str = "requirements.txt") -> ExecResult:
        """Create a venv inside the sandbox and install requirements."""
        assert self._repo is not None, "repo not loaded"
        venv_dir = self._repo / ".sbvenv"
        self._run([sys.executable, "-m", "venv", str(venv_dir)], self._repo)
        self._py = venv_dir / "bin" / "python"
        self._run([str(self._py), "-m", "pip", "install", "--quiet", "--upgrade", "pip"], self._repo)
        return self.exec(f"'{self._py}' -m pip install -r {requirements}")

    # --- exec ---
    def exec(self, cmd: str, cwd: Optional[str] = None) -> ExecResult:
        assert self._repo is not None, "repo not loaded"
        workdir = self._repo / cwd if cwd else self._repo
        proc = subprocess.run(
            cmd, cwd=str(workdir), shell=True, capture_output=True, text=True, timeout=300,
        )
        return ExecResult(proc.returncode, proc.stdout, proc.stderr)

    def py(self) -> str:
        """Path to the sandbox venv python (falls back to the host python)."""
        return str(self._py) if self._py else sys.executable

    # --- files ---
    def _abs(self, rel_path: str) -> Path:
        assert self._repo is not None, "repo not loaded"
        return self._repo / rel_path

    def read_file(self, rel_path: str) -> str:
        return self._abs(rel_path).read_text()

    def write_file(self, rel_path: str, content: str) -> None:
        p = self._abs(rel_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    # --- internal ---
    @staticmethod
    def _run(argv: list[str], cwd: Path) -> None:
        subprocess.run(argv, cwd=str(cwd), check=True, capture_output=True, text=True)


def make_sandbox(config, label: str) -> Sandbox:
    """Pick the sandbox implementation based on what's configured."""
    if config.has_daytona:
        from .daytona_sandbox import DaytonaSandbox  # imported lazily so the SDK stays optional
        return DaytonaSandbox(config, label=label)
    return LocalSandbox(label=label)
