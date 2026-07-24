"""CLI entrypoint: `python -m patchpilot` runs one full loop and prints the
streamed nodes + goal tracker. The demo driver."""

from __future__ import annotations

import argparse
import sys

from .config import load_config
from .orchestrator import Orchestrator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="patchpilot", description="Prove, patch, and re-prove a dependency CVE.")
    parser.add_argument("--target", help="path to the target repo (default: target-app/)")
    parser.add_argument("--local", action="store_true", help="force the local sandbox even if a Daytona key is set")
    parser.add_argument("--patched-version", help="version to upgrade the vulnerable package to")
    args = parser.parse_args(argv)

    cfg = load_config()
    if args.target:
        cfg.target_path = args.target
    if args.patched_version:
        cfg.patched_version = args.patched_version
    if args.local:
        cfg.force_local_sandbox = True

    state = Orchestrator(cfg).run()
    return 1 if state.escalated else 0


if __name__ == "__main__":
    sys.exit(main())
