"""Read-only M0 evaluator for a separately protected trusted repository.

Only the pinned policy/baseline.py is executed on the host. Candidate tests
execute inside that policy's no-network, read-only, bounded Docker container.
No App key or write token belongs in this process. An unconfigured copy cannot
publish a GitHub check and is not live M0 evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import selectors
import signal
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SHA = re.compile(r"[0-9a-f]{40}\Z")
HARD_CHECKS = frozenset({"source_integrity", "unit", "security", "dependencies",
                         "licenses", "secrets", "test_integrity", "traceability"})
MAX_API = 2_000_000
MAX_REPORT = 1_000_000
TEST_IMAGE = "docker.io/library/python@sha256:44ff437bba879d4941b710a369a8f19266aea34b29002807f0c487fabc9eec9b"


class GateError(Exception):
    pass


def need(ok: bool, message: str) -> None:
    if not ok:
        raise GateError(message)


def exact_sha(value: object, label: str) -> str:
    need(isinstance(value, str) and SHA.fullmatch(value) is not None,
         f"invalid {label}")
    return value


def load_config(path: Path = ROOT / "config.json") -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    need(value.get("schema_version") == 1, "configuration schema mismatch")
    need(value.get("target_repo") == "xbroute/hayool-os" and
         type(value.get("target_repo_id")) is int, "unexpected target repository")
    exact_sha(value.get("policy_source_sha"), "policy source SHA")
    need(re.fullmatch(r"[0-9a-f]{64}", str(value.get("baseline_sha256"))) is not None,
         "invalid baseline digest")
    need(re.fullmatch(r"[0-9a-f]{64}", str(value.get("independent_policy_sha256"))) is not None,
         "invalid independent policy digest")
    migration = value.get("migration")
    need(isinstance(migration, dict) and migration.get("pr_number") == 7,
         "migration configuration missing")
    exact_sha(migration.get("base_sha"), "migration base SHA")
    exact_sha(migration.get("head_sha"), "migration head SHA")
    return value


def policy_digest(config: dict) -> str:
    digest = hashlib.sha256((ROOT / "policy/baseline.py").read_bytes()).hexdigest()
    need(digest == config["baseline_sha256"], "pinned baseline policy bytes changed")
    independent = hashlib.sha256((ROOT / "policy/independent_policy.py").read_bytes()).hexdigest()
    need(independent == config["independent_policy_sha256"],
         "independent policy bytes changed")
    return digest


class GitHub:
    """Bounded read-only GitHub API; no write method exists in this module."""

    def __init__(self, token: str = "") -> None:
        self.token = token

    def get(self, path: str) -> dict:
        need(path.startswith("repos/") and
             not any(part in {"", ".", ".."} for part in path.split("/")),
             "invalid API path")
        headers = {"Accept": "application/vnd.github+json",
                   "User-Agent": "hayool-independent-gate/1",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request("https://api.github.com/" + path,
                                         headers=headers)
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(MAX_API + 1)
        need(len(raw) <= MAX_API, "GitHub API response too large")
        value = json.loads(raw)
        need(isinstance(value, dict), "GitHub API returned non-object")
        return value


def verify_live_target(api: GitHub, config: dict, number: int,
                       expected_head: str) -> dict:
    """Bind target repo, PR, current base/head, commit ancestry and merge tree."""
    repo = config["target_repo"]
    repo_id = config["target_repo_id"]
    exact_sha(expected_head, "expected PR head")
    meta = api.get(f"repos/{repo}")
    need(meta.get("id") == repo_id and meta.get("full_name") == repo,
         "target repository identity mismatch")
    pr = api.get(f"repos/{repo}/pulls/{number}")
    head, base = pr.get("head"), pr.get("base")
    need(pr.get("number") == number and pr.get("state") == "open" and
         isinstance(head, dict) and isinstance(base, dict), "PR is not live/open")
    need(head.get("sha") == expected_head and head.get("repo", {}).get("id") == repo_id
         and base.get("repo", {}).get("id") == repo_id and base.get("ref") == "main",
         "PR head/base/repository mismatch")
    main = api.get(f"repos/{repo}/git/ref/heads/main")
    base_sha = exact_sha(main.get("object", {}).get("sha"), "live main SHA")
    need(base.get("sha") == base_sha, "PR base is not current main")
    commit = api.get(f"repos/{repo}/git/commits/{expected_head}")
    need(commit.get("sha") == expected_head, "PR commit identity mismatch")
    tree_sha = exact_sha(commit.get("tree", {}).get("sha"), "head tree SHA")
    comparison = api.get(f"repos/{repo}/compare/{base_sha}...{expected_head}")
    need(comparison.get("merge_base_commit", {}).get("sha") == base_sha and
         comparison.get("status") in {"ahead", "identical"},
         "candidate is not based on current main")
    merge_sha = exact_sha(pr.get("merge_commit_sha"), "test merge SHA")
    need(pr.get("mergeable") is True, "PR test merge unavailable or conflicting")
    merge = api.get(f"repos/{repo}/git/commits/{merge_sha}")
    parents = merge.get("parents")
    need(merge.get("sha") == merge_sha and isinstance(parents, list) and
         [row.get("sha") for row in parents if isinstance(row, dict)] ==
         [base_sha, expected_head] and merge.get("tree", {}).get("sha") == tree_sha,
         "test merge parents/tree do not equal verified base and head")
    return {"repository": repo, "repository_id": repo_id, "pr_number": number,
            "base_sha": base_sha, "head_sha": expected_head, "head_tree_sha": tree_sha,
            "merge_sha": merge_sha, "merge_parents": [base_sha, expected_head],
            "merge_tree_sha": tree_sha}


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, check=True, timeout=30,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True)
    need(len(result.stdout) <= MAX_REPORT, "git output too large")
    return result.stdout.strip()


def verify_checkout(root: Path, target: dict, config: dict) -> tuple[list[str], dict[str, str]]:
    need(git(root, "rev-parse", "HEAD") == target["head_sha"],
         "checkout head differs from live PR")
    need(git(root, "status", "--porcelain") == "", "candidate checkout is dirty")
    # GitHub's compare API and the local diff must agree on an ancestor base.
    need(git(root, "merge-base", target["base_sha"], target["head_sha"]) ==
         target["base_sha"], "local base/head ancestry mismatch")
    changes = git(root, "diff", "--name-status", target["base_sha"],
                  target["head_sha"]).splitlines()
    hashes: dict[str, str] = {}
    for line in changes:
        fields = line.split("\t")
        need(len(fields) == 2 and fields[0] in {"A", "M"},
             "changed path has unsupported status")
        path = root / fields[1]
        need(path.is_file() and not path.is_symlink() and
             path.stat().st_size <= MAX_API, "changed path invalid or oversized")
        hashes[fields[1]] = hashlib.sha256(path.read_bytes()).hexdigest()
    migration = config["migration"]
    if target["pr_number"] == migration["pr_number"]:
        need(target["base_sha"] == migration["base_sha"] and
             target["head_sha"] == migration["head_sha"] and
             changes == migration["changed_paths"] and
             hashes == migration["reviewed_file_sha256"],
             "reviewed PR #7 migration paths or bytes changed")
    return changes, hashes


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    # Do not cap host virtual address space: the trusted policy launches the
    # Docker CLI, whose Go runtime reserves address space before the candidate
    # container starts. Candidate memory is capped by docker run --memory.
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))


def run_baseline(root: Path, target: dict, output: Path) -> tuple[int, dict]:
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/tmp",
                   "HAYOOL_CANDIDATE_ROOT": str(root.resolve()),
                   "HAYOOL_POLICY_SOURCE": "independent-trusted-repo"}
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "policy/independent_policy.py"),
         "--base-sha", target["base_sha"], "--target-sha", target["head_sha"],
         "--pr-number", str(target["pr_number"]),
         "--output", str(output)], cwd=ROOT, env=environment,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=420,
        check=False, preexec_fn=_limits,
    )
    raw = output.read_bytes()
    need(len(raw) <= MAX_REPORT, "baseline output too large")
    report = json.loads(raw)
    need(isinstance(report, dict), "baseline output invalid")
    return result.returncode, report


def run_gate_regressions(root: Path) -> dict:
    """Run exact unit and gate suites as candidate code only in Docker."""
    code = (
        "import sys,unittest; "
        "u=unittest.defaultTestLoader.discover('/candidate/bootstrap/tests',pattern='test_*.py'); "
        "a=unittest.defaultTestLoader.discover('/candidate/bootstrap/regression_tests',pattern='test_target_gate.py'); "
        "b=unittest.defaultTestLoader.discover('/candidate/bootstrap/regression_tests',pattern='test_trusted_gate.py'); "
        "n=u.countTestCases(); m=a.countTestCases()+b.countTestCases(); "
        "s=unittest.TestSuite((u,a,b)); "
        "print('UNIT_COUNT='+str(n)+' REGRESSION_COUNT='+str(m),flush=True); "
        "r=unittest.TextTestRunner(verbosity=1).run(s); "
        "sys.exit(0 if n==36 and m==24 and r.wasSuccessful() else 1)"
    )
    with tempfile.TemporaryDirectory(prefix="hayool-gate-tests-") as temp:
        cid = Path(temp) / "container-id"
        command = ["docker", "run", "--rm", "--pull=missing",
                   "--platform=linux/amd64", "--cidfile", str(cid),
                   "--network=none", "--read-only", "--cap-drop=ALL",
                   "--security-opt=no-new-privileges", "--pids-limit=64",
                   "--memory=512m", "--memory-swap=512m", "--cpus=1",
                   "--user=65534:65534", "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m",
                   "--mount", f"type=bind,src={root.resolve()},dst=/candidate,readonly",
                   "--workdir=/candidate", "--env=HOME=/tmp", TEST_IMAGE,
                   "python3", "-I", "-B", "-c", code]
        environment = {"PATH": "/usr/bin:/bin", "HOME": temp,
                       "DOCKER_CONFIG": temp}
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, env=environment,
                                   start_new_session=True)
        output = bytearray()
        reason = ""
        try:
            assert process.stdout is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                deadline = __import__("time").monotonic() + 90
                while True:
                    remaining = deadline - __import__("time").monotonic()
                    if remaining <= 0:
                        reason = "regression timeout"
                        break
                    if not selector.select(min(remaining, 0.5)):
                        continue
                    chunk = os.read(process.stdout.fileno(),
                                    min(65536, MAX_REPORT + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_REPORT:
                        reason = "regression output limit"
                        break
            if reason and process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            exit_code = process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            reason = "regression runner error"
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            exit_code = process.returncode
        finally:
            if process.stdout:
                process.stdout.close()
            if reason and cid.is_file():
                container = cid.read_text(encoding="ascii").strip()
                if re.fullmatch(r"[0-9a-f]{64}", container):
                    subprocess.run(["docker", "rm", "-f", container],
                                   env=environment, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=10, check=False)
        text = output.decode("utf-8", errors="replace")
        return {"decision": "PASS" if not reason and exit_code == 0 and
                "UNIT_COUNT=36 REGRESSION_COUNT=24" in text else "FAIL",
                "expected_unit_tests": 36, "expected_regression_tests": 24,
                "exit_code": exit_code,
                "failure_code": reason or ("test_failure" if exit_code else ""),
                "output_sha256": hashlib.sha256(output).hexdigest(),
                "image": TEST_IMAGE, "network": "none", "read_only": True,
                "timeout_seconds": 90, "memory_bytes": 536870912, "pids": 64}


def verify_report(report: dict, returncode: int, target: dict,
                  changes: list[str], config: dict) -> dict:
    need(report.get("schema_version") == 2 and
         report.get("policy_source") == "independent-trusted-repo" and
         report.get("protected_main_policy_sha") == config["policy_source_sha"] and
         report.get("protected_main_baseline_sha256") == config["baseline_sha256"] and
         report.get("pr_number") == target["pr_number"] and
         report.get("base_sha") == target["base_sha"] and
         report.get("target_sha") == target["head_sha"] and
         report.get("workspace_clean") is True,
         "independent policy/head evidence mismatch")
    checks, errors = report.get("checks"), report.get("errors")
    need(isinstance(checks, dict) and isinstance(errors, dict) and
         set(checks) == HARD_CHECKS and set(errors) == HARD_CHECKS,
         "hard-check set missing or expanded")
    migration = config["migration"]
    is_migration = (target["pr_number"] == migration["pr_number"] and
                    target["base_sha"] == migration["base_sha"] and
                    target["head_sha"] == migration["head_sha"] and
                    changes == migration["changed_paths"])
    need(report.get("migration_rule") ==
         ("exact_reviewed_PR7_bytes" if is_migration else "frozen_paths"),
         "independent integrity rule mismatch")
    for name in HARD_CHECKS:
        need(checks[name] == "PASS" and errors[name] == [],
             f"independent hard check failed: {name}")
    suites = report.get("isolated_suites")
    need(isinstance(suites, dict) and suites.get("decision") == "PASS" and
         suites.get("expected_unit_tests") == 36 and
         suites.get("expected_regression_tests") == 24 and
         suites.get("exit_code") == 0 and suites.get("image") == TEST_IMAGE and
         suites.get("network") == "none" and suites.get("read_only") is True and
         suites.get("timeout_seconds") == 90 and
         suites.get("memory_bytes") == 536870912 and suites.get("pids") == 64,
         "isolated reviewed suites missing or failed")
    need(returncode == 0, "independent policy process failed")
    return {"decision": "PASS", "checks": checks, "errors": errors,
            "migration_policy_rule": report["migration_rule"]}


def verify_trusted_run(api: GitHub, config: dict, repository: str,
                       policy_sha: str, run_id: int, attempt: int) -> dict:
    """Reject alternate-ref workflow_dispatch and mismatched workflow code."""
    need(config.get("trusted_repo") == repository and
         config.get("trusted_repo_id") is not None and repository !=
         config["target_repo"], "trusted repository not configured")
    exact_sha(policy_sha, "trusted policy SHA")
    meta = api.get(f"repos/{repository}")
    need(meta.get("id") == config["trusted_repo_id"] and
         meta.get("full_name") == repository,
         "trusted repository identity mismatch")
    main = api.get(f"repos/{repository}/git/ref/heads/main")
    need(main.get("object", {}).get("sha") == policy_sha,
         "trusted workflow did not run current protected main")
    run = api.get(f"repos/{repository}/actions/runs/{run_id}")
    workflow = api.get(f"repos/{repository}/actions/workflows/{Path(config['workflow_path']).name}")
    need(run.get("id") == run_id and run.get("run_attempt") == attempt and
         run.get("event") == "workflow_dispatch" and
         run.get("repository", {}).get("id") == config["trusted_repo_id"] and
         run.get("head_repository", {}).get("id") == config["trusted_repo_id"] and
         run.get("head_branch") == "main" and run.get("head_sha") == policy_sha and
         str(run.get("path", "")).split("@", 1)[0] == config["workflow_path"] and
         run.get("workflow_id") == workflow.get("id") and
         workflow.get("path") == config["workflow_path"] and
         workflow.get("state") == "active",
         "trusted workflow source/ref mismatch")
    return {"trusted_repository": repository,
            "trusted_repository_id": config["trusted_repo_id"],
            "trusted_policy_sha": policy_sha, "trusted_run_id": run_id,
            "trusted_run_attempt": attempt, "trusted_workflow_id": workflow["id"]}


def evaluate(api: GitHub, config: dict, number: int, expected_head: str,
             candidate: Path, repository: str, policy_sha: str,
             run_id: int, attempt: int, output: Path) -> dict:
    policy_hash = policy_digest(config)
    source = verify_trusted_run(api, config, repository, policy_sha, run_id, attempt)
    target = verify_live_target(api, config, number, expected_head)
    changes, file_hashes = verify_checkout(candidate, target, config)
    with tempfile.TemporaryDirectory(prefix="hayool-baseline-") as temporary:
        returncode, baseline = run_baseline(candidate, target,
                                           Path(temporary) / "baseline.json")
    try:
        decision = verify_report(baseline, returncode, target, changes, config)
    except GateError as error:
        # A real hard-check failure still gets a full, exact-SHA failure
        # artifact. The separate publisher may post failure after rechecking
        # the live PR and artifact provenance.
        decision = {"decision": "FAIL", "reason": str(error),
                    "migration_policy_rule": "unmet", "checks": baseline.get("checks"),
                    "errors": baseline.get("errors")}
    result = {"schema_version": 1, **source, **target,
              "policy_source_sha": config["policy_source_sha"],
              "baseline_sha256": policy_hash, "baseline": baseline,
              "independent_policy_sha256": config["independent_policy_sha256"],
              "baseline_returncode": returncode,
              "isolated_suites": baseline.get("isolated_suites"),
              "limits": {"job_minutes": 10, "baseline_wall_seconds": 420,
                         "baseline_cpu_seconds": 180, "baseline_memory_bytes": None,
                         "baseline_address_space": "runner-inherited",
                         "candidate_unit_wall_seconds": 90,
                         "candidate_unit_memory_bytes": 536870912,
                         "candidate_unit_pids": 64, "candidate_network": "none",
                         "candidate_filesystem": "read-only"},
              "changed_paths": changes,
              "changed_file_sha256": file_hashes, **decision}
    # Re-read live PR/ref after the long candidate run. A moved SHA cannot pass.
    need(verify_live_target(api, config, number, expected_head) == target,
         "PR/base/test merge changed during evaluation")
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n",
                      encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        config = load_config()
        result = evaluate(GitHub(), config, args.pr, args.expected_head,
                          args.candidate, os.environ.get("GITHUB_REPOSITORY", ""),
                          os.environ.get("GITHUB_SHA", ""),
                          int(os.environ.get("GITHUB_RUN_ID", "0")),
                          int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")), args.output)
        print(json.dumps({"decision": result["decision"], "head_sha":
                          result["head_sha"], "merge_sha": result["merge_sha"]}))
        return 0 if result["decision"] == "PASS" else 1
    except (GateError, OSError, ValueError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        failure = {"schema_version": 1, "decision": "FAIL", "reason": str(error),
                   "requested_pr": args.pr, "requested_head": args.expected_head,
                   "trusted_run_id": os.environ.get("GITHUB_RUN_ID")}
        args.output.write_text(json.dumps(failure, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
        print(json.dumps({"decision": "FAIL", "reason": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
