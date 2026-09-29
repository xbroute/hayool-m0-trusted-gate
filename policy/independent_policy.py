"""Independent deterministic M0 policy for the separately protected gate repo.

This policy executes every hard check afresh. It never upgrades a failed
legacy report or accepts an AI vote. Its PR #7 integrity rule accepts exactly
the reviewed migration commit and all ten reviewed file bytes, checks that no
existing test path disappeared, and executes both test groups in isolated
Docker. Other PRs use the protected-main frozen-path rule unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE_ROOT = HERE.parent


def trusted_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = trusted_module("independent_gate_library", GATE_ROOT / "gate.py")
config = gate.load_config()
gate.policy_digest(config)  # exact protected-main baseline bytes
base = trusted_module("pinned_main_baseline", HERE / "baseline.py")
ROOT = base.ROOT


def reviewed_integrity(pr_number: int, base_sha: str, head_sha: str) -> tuple[list[str], dict]:
    migration = config["migration"]
    if pr_number != migration["pr_number"] or head_sha != migration["head_sha"] or base_sha != migration["base_sha"]:
        errors = base.test_integrity(base_sha, head_sha)
    else:
        errors = []
        changes = base.git("diff", "--name-status", base_sha, head_sha).splitlines()
        if changes != migration["changed_paths"]:
            errors.append("migration changed-path inventory differs from reviewed SHA")
        expected = migration["reviewed_file_sha256"]
        observed: dict[str, str] = {}
        for line in changes:
            fields = line.split("\t")
            if len(fields) != 2 or fields[0] not in {"A", "M"}:
                errors.append("migration has removed/renamed/unreviewed path")
                continue
            relative = fields[1]
            path = ROOT / relative
            if not path.is_file() or path.is_symlink() or path.stat().st_size > gate.MAX_API:
                errors.append("migration file missing, symlinked, or oversized: " + relative)
                continue
            observed[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        if observed != expected:
            errors.append("migration file-byte hashes differ from reviewed SHA")
        # Existing tests may be modified only where the reviewed exact bytes
        # above say so; no existing test can silently disappear.
        test_roots = ("bootstrap/tests/", "bootstrap/regression_tests/", "tests/")
        old_tests = {name for name in base.git("ls-tree", "-r", "--name-only", base_sha).splitlines()
                     if name.startswith(test_roots) and name.endswith(".py")}
        new_tests = {name for name in base.git("ls-tree", "-r", "--name-only", head_sha).splitlines()
                     if name.startswith(test_roots) and name.endswith(".py")}
        if not old_tests <= new_tests:
            errors.append("migration removed an existing Python test")
        if any(line[0] not in {"A", "M"} for line in changes
               if line.split("\t")[-1].startswith(test_roots)):
            errors.append("migration deleted or renamed a test")
    suites = gate.run_gate_regressions(ROOT)
    if suites.get("decision") != "PASS":
        errors.append("isolated reviewed test suites failed")
    return errors, suites


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--pr-number", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    gate.exact_sha(args.base_sha, "base SHA")
    gate.exact_sha(args.target_sha, "target SHA")
    head = base.git("rev-parse", "HEAD")
    gate.need(head == args.target_sha, "candidate checkout SHA mismatch")
    clean = base.git("status", "--porcelain") == ""
    gate.need(clean, "candidate checkout is dirty")
    integrity_errors, suites = reviewed_integrity(args.pr_number, args.base_sha, head)
    checks = {
        "source_integrity": base.source_integrity,
        "unit": base.unit,
        "security": base.security,
        "dependencies": base.dependencies,
        "licenses": base.licenses,
        "secrets": base.secrets,
        "test_integrity": lambda: integrity_errors,
        "traceability": base.traceability,
    }
    details = {name: function() for name, function in checks.items()}
    verdicts = {name: "PASS" if not values else "FAIL"
                for name, values in details.items()}
    report = {
        "schema_version": 2,
        "policy_source": "independent-trusted-repo",
        "protected_main_policy_sha": config["policy_source_sha"],
        "protected_main_baseline_sha256": config["baseline_sha256"],
        "pr_number": args.pr_number, "base_sha": args.base_sha, "target_sha": head,
        "workspace_clean": clean, "checks": verdicts, "errors": details,
        "isolated_suites": suites,
        "migration_rule": "exact_reviewed_PR7_bytes" if
            args.pr_number == config["migration"]["pr_number"] and
            head == config["migration"]["head_sha"] and
            args.base_sha == config["migration"]["base_sha"] else "frozen_paths",
    }
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({"target_sha": head, "checks": verdicts}, sort_keys=True))
    return 0 if all(value == "PASS" for value in verdicts.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
