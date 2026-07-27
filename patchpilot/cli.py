"""CLI entrypoint: `python -m patchpilot [--repo URL | --target PATH]` runs one
scan → reachability → remediate loop and prints the streamed nodes + goal tracker."""

from __future__ import annotations

import argparse
import sys

from .config import load_config
from .orchestrator import Orchestrator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="patchpilot",
        description="Scan a repo for vulnerable dependencies, prove reachability, and remediate.",
    )
    parser.add_argument("--repo", help="GitHub repo URL to scan (the product path)")
    parser.add_argument("--target", help="local path to a repo to scan (default: target-app/)")
    parser.add_argument("--local", action="store_true", help="force the local sandbox even if a Daytona key is set")
    args = parser.parse_args(argv)

    cfg = load_config()
    if args.target:
        cfg.target_path = args.target
    if args.local:
        cfg.force_local_sandbox = True

    state = Orchestrator(cfg, repo_url=args.repo or "").run()
    return 1 if state.escalated else 0


if __name__ == "__main__":
    sys.exit(main())
