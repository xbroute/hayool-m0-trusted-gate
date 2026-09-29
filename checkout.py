"""Fetch a public candidate by exact PR ref without credentials or code execution."""

from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
from pathlib import Path

_spec = importlib.util.spec_from_file_location("trusted_gate_module", Path(__file__).resolve().with_name("gate.py"))
assert _spec is not None and _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def checkout(number: int, head: str, destination: Path) -> None:
    gate.need(0 < number < 1000000, "invalid PR number")
    gate.exact_sha(head, "requested candidate SHA")
    gate.need(not destination.exists(), "candidate destination already exists")
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/tmp",
                   "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"}
    commands = [
        ["git", "init", "-q", str(destination)],
        ["git", "-C", str(destination), "remote", "add", "origin",
         "https://github.com/xbroute/hayool-os.git"],
        ["git", "-C", str(destination), "-c", "credential.helper=", "fetch",
         "--no-tags", "origin", "refs/heads/main", f"refs/pull/{number}/head"],
        ["git", "-C", str(destination), "checkout", "--detach", "-q", head],
    ]
    for command in commands:
        subprocess.run(command, env=environment, check=True, timeout=120,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    gate.need(gate.git(destination, "rev-parse", "HEAD") == head,
              "fetched PR ref does not contain the expected exact SHA")
    gate.need(gate.git(destination, "status", "--porcelain") == "",
              "candidate checkout is dirty")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    checkout(args.pr, args.head, args.destination)
    print("candidate_exact_sha_verified")


if __name__ == "__main__":
    main()
