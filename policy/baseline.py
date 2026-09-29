"""Deterministic M0 checks; runs without third-party Python packages or secrets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(os.environ.get("HAYOOL_CANDIDATE_ROOT") or Path(__file__).resolve().parents[1]).resolve()
ORIGINAL_ZIP = ROOT / "archive/V7.2/Hayool-OS-V7.2-Final-Source-of-Truth.zip"
ORIGINAL_ZIP_SHA256 = "35054ad417242eda797d81816d81ae10a2bcc44b4a10fcc8784005c7d1d5d700"
PREFIX = "hayool-os-v7.2-final/"
SECRET_PATTERNS = {
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
    "aws_access_key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
}
ALLOWED_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "PostgreSQL", "MPL-2.0", "CC-BY-4.0", "MIXED", "INTERNAL"}
TEST_IMAGE = "docker.io/library/python@sha256:44ff437bba879d4941b710a369a8f19266aea34b29002807f0c487fabc9eec9b"
TEST_TIMEOUT_SECONDS = 90
TEST_OUTPUT_LIMIT_BYTES = 1_048_576


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def source_integrity() -> list[str]:
    errors: list[str] = []
    if hashlib.sha256(ORIGINAL_ZIP.read_bytes()).hexdigest() != ORIGINAL_ZIP_SHA256:
        return ["original V7.2 ZIP hash mismatch"]
    with zipfile.ZipFile(ORIGINAL_ZIP) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or any(not n.startswith(PREFIX) or ".." in Path(n).parts for n in names):
            return ["unsafe or duplicate source ZIP path"]
        manifest = json.loads(archive.read(PREFIX + "PACKAGE_MANIFEST.json"))
        expected = {row["path"] for row in manifest["files"]}
        observed = {n[len(PREFIX):] for n in names if n != PREFIX + "PACKAGE_MANIFEST.json"}
        if expected != observed:
            errors.append("package manifest membership mismatch")
        for row in manifest["files"]:
            data = archive.read(PREFIX + row["path"])
            if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
                errors.append("source package hash mismatch: " + row["path"])
        design_digest = hashlib.sha256()
        for row in sorted(manifest["files"], key=lambda item: item["path"]):
            path = row["path"]
            if path.startswith(("archive/", "docs/evidence/")):
                continue
            design_digest.update(path.encode("utf-8") + b"\0" + hashlib.sha256(archive.read(PREFIX + path)).digest())
        if design_digest.hexdigest() != manifest["design_review_digest"]:
            errors.append("V7.2 design review digest mismatch")
        source = json.loads(archive.read(PREFIX + "SOURCE_MANIFEST.json"))
        if len(source["files"]) != manifest["source_files"] or manifest["source_files"] != 61:
            errors.append("source count mismatch")
        for row in source["files"]:
            relative = "archive/sources/" + row["path"]
            data = (ROOT / relative).read_bytes()
            if len(data) != row["local_bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
                errors.append("imported source hash mismatch: " + relative)
        predecessor = (ROOT / "archive/V7.1/Hayool-OS-V7.1-Source-of-Truth.zip").read_bytes()
        if hashlib.sha256(predecessor).hexdigest() != manifest["predecessor_v71_sha256"]:
            errors.append("V7.1 predecessor hash mismatch")
    return errors


def security() -> list[str]:
    errors: list[str] = []
    kill = json.loads((ROOT / "bootstrap/kill_switch.json").read_text(encoding="utf-8"))
    if kill != {"engaged": False, "autonomous_writes_enabled": False, "merge_enabled": False, "deploy_enabled": False, "external_calls_enabled": False}:
        errors.append("M0 shadow kill switch policy changed")
    workflow_dir = ROOT / ".github/workflows"
    workflows = sorted(p for p in workflow_dir.iterdir() if p.suffix in {".yml", ".yaml"})
    expected = {"engineering-baseline.yml", "engineering-trusted-gate.yml"}
    if {p.name for p in workflows} != expected:
        errors.append("unexpected or missing M0 workflow")
    for workflow in workflows:
        body = workflow.read_text(encoding="utf-8")
        if "secrets." in body or "write-all" in body:
            errors.append(f"unsafe workflow token in {workflow.name}")
        for action in re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", body, re.MULTILINE):
            if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}", action):
                errors.append(f"unpinned action in {workflow.name}")
        if "contents: read" not in body:
            errors.append(f"workflow {workflow.name} lacks explicit read-only contents permission")
        if workflow.name == "engineering-trusted-gate.yml":
            if not all(token in body for token in (
                "pull_request_target:", "branches: [main]", "permissions: {}",
                "candidate-check:", "trusted-gate:", "needs: candidate-check",
                "statuses: write", "actions: read", "ref: ${{ github.sha }}",
                "path: candidate", "persist-credentials: false",
                "HAYOOL_CANDIDATE_ROOT:", "policy/bootstrap/baseline.py",
                "bootstrap/trusted_gate.py", "--pr-target-event", "--post-status",
                "--require-trusted-artifact", "--verify-outcome", "--upload-outcome",
            )):
                errors.append("trusted workflow loses default-branch gate contract")
            # The first job has only read access and runs candidate tests in
            # baseline.unit()'s container. The second job can post a status,
            # but checks out only protected main and reads the first artifact.
            candidate_job = body.split("  candidate-check:", 1)[-1].split("  trusted-gate:", 1)[0]
            trusted_job = body.split("  trusted-gate:", 1)[-1]
            if "statuses: write" in candidate_job or "ref: ${{ github.event.pull_request.head.sha }}" in trusted_job:
                errors.append("status-writing job can access untrusted PR code")
            if "contents: read" not in candidate_job or "statuses: write" not in trusted_job:
                errors.append("trusted job permission boundary missing")
            if any(token in body for token in (
                "workflow_run:", "--privileged", "npm ", "pip install",
            )):
                errors.append("trusted workflow has an unsafe trigger or command")
        else:
            if "workflow_run:" in body or "statuses: write" in body or re.search(
                r"(?im)\b[A-Za-z_-]+:\s*write\b|permissions:\s*write-all\b", body
            ):
                errors.append("candidate workflow requests privileged permission")
            if "pull_request:" not in body or "persist-credentials: false" not in body:
                errors.append("candidate workflow loses unprivileged PR contract")
    return errors


def dependencies() -> list[str]:
    # M0 has no installed application runtime. A package manifest requires a new review.
    discovered = [p for name in ("package.json", "pnpm-lock.yaml", "package-lock.json", "yarn.lock", "requirements.txt", "poetry.lock", "Dockerfile") if (p := ROOT / name).exists()]
    return ["unreviewed installed dependency manifest: " + p.name for p in discovered]


def licenses() -> list[str]:
    path = ROOT / "bootstrap/dependency_baseline.json"
    if not path.is_file():
        return ["dependency baseline missing"]
    rows = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if not isinstance(rows, list) or not rows:
        return ["dependency baseline empty"]
    for row in rows:
        name = row.get("name", "<unknown>")
        if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:[A-Za-z0-9.+_-]*)", str(row.get("version", ""))):
            errors.append(f"{name}: version is not exact")
        if row.get("license") not in ALLOWED_LICENSES:
            errors.append(f"{name}: license not in reviewed M0 allowlist")
        if row.get("license") in {"MIXED", "INTERNAL"} and not row.get("license_review"):
            errors.append(f"{name}: license follow-up missing")
        if row.get("status") != "planned" or row.get("installed") is not False:
            errors.append(f"{name}: inventory claims an unverified installation")
        if not str(row.get("source", "")).startswith("https://"):
            errors.append(f"{name}: source URL missing")
    return errors


def secrets() -> list[str]:
    errors: list[str] = []
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    for raw in tracked:
        if not raw:
            continue
        relative = os.fsdecode(raw)
        path = ROOT / relative
        if path.is_symlink():
            errors.append(f"tracked symlink requires review: {relative}")
            continue
        if not path.is_file():
            errors.append(f"tracked file missing: {relative}")
            continue
        data = path.read_bytes()
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(data):
                errors.append(f"possible {label} in {relative}")
    return errors


def test_integrity(base_sha: str, target_sha: str) -> list[str]:
    errors: list[str] = []
    # The README-only seed is a one-time human-reviewed exception. In M0, a
    # protected base accepts only prose documents and harmless sample text.
    # This freezes the whole test/import surface: a new test, package init,
    # or import-shadow module must not poison the existing suite in its own PR.
    base_has_gate = subprocess.run(
        ["git", "cat-file", "-e", f"{base_sha}:bootstrap/trusted_gate.py"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0
    for line in git("diff", "--name-status", base_sha, target_sha).splitlines():
        columns = line.split("\t")
        status = columns[0]
        paths = columns[1:]
        for path in paths:
            is_test = path.startswith(("bootstrap/tests/", "bootstrap/regression_tests/", "tests/"))
            if base_has_gate:
                if is_test:
                    errors.append("candidate changed test after M0 seed: " + path)
                elif not (path in {"PROJECT_STATE.md", "NEXT_ACTIONS.md", "README.md", "README_FA.md"}
                          or (path.startswith("docs/") and path.endswith(".md"))
                          or (path.startswith("samples/") and path.endswith(".txt"))):
                    errors.append("candidate changed protected M0 path: " + path)
            elif is_test and not status.startswith("A"):
                errors.append("existing test changed or removed: " + path)
    return errors


def traceability() -> list[str]:
    # A PR body can be edited without changing the commit SHA. Required status
    # is SHA-bound, so its traceability input must be immutable at that SHA.
    body = git("show", "-s", "--format=%B", "HEAD")
    required = {
        "REQ": r"REQ-[A-Z]+-[0-9]+",
        "ADR": r"ADR-[0-9]+",
        "Risk": r"R[0-4]",
        "Tests": r"\S+",
        "Evidence": r"\S+",
        "Migration": r"\S+",
    }
    return ["head commit missing " + label for label, pattern in required.items() if not re.search(r"(?im)^" + label + r":\s*" + pattern, body)]


def unit() -> list[str]:
    """Run candidate tests outside this evaluator, with no host write or secret access.

    The Docker client is trusted code; the untrusted Python interpreter runs only
    inside a resource-limited container. A missing Docker daemon fails closed.
    """
    with tempfile.TemporaryDirectory(prefix="hayool-unit-") as temporary:
        cid_file = Path(temporary) / "container-id"
        command = [
            "docker", "run", "--rm", "--pull=missing", "--platform=linux/amd64",
            "--cidfile", str(cid_file), "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--pids-limit=64", "--memory=512m", "--memory-swap=512m",
            "--cpus=1", "--user=65534:65534",
            "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m",
            "--mount", f"type=bind,src={ROOT},dst=/candidate,readonly",
            "--workdir=/candidate", "--env=HOME=/tmp",
            TEST_IMAGE, "python3", "-I", "-B", "-c",
            "import sys,unittest; "
            "s=unittest.defaultTestLoader.discover('/candidate/bootstrap/tests',pattern='test_*.py'); "
            "n=s.countTestCases(); r=unittest.TextTestRunner(verbosity=1).run(s); "
            "sys.exit(0 if n>0 and r.wasSuccessful() else 1)",
        ]
        # Do not give the Docker client a GitHub token, cloud credentials, or a
        # user Docker configuration. No environment is forwarded into the image.
        client_env = {"PATH": "/usr/bin:/bin", "HOME": temporary, "DOCKER_CONFIG": temporary}
        try:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=client_env, start_new_session=True,
            )
        except OSError as exc:
            return [f"isolated unit runner unavailable: {exc.__class__.__name__}"]
        output = bytearray()
        reason = ""
        try:
            assert process.stdout is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + TEST_TIMEOUT_SECONDS
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        reason = "isolated unit suite exceeded time limit"
                        break
                    if not selector.select(min(remaining, 0.5)):
                        continue
                    chunk = os.read(process.stdout.fileno(), min(65536, TEST_OUTPUT_LIMIT_BYTES + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > TEST_OUTPUT_LIMIT_BYTES:
                        reason = "isolated unit suite exceeded output limit"
                        break
            if reason and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            exit_code = process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            reason = f"isolated unit runner failed: {exc.__class__.__name__}"
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            exit_code = process.returncode
        finally:
            if process.stdout is not None:
                process.stdout.close()
            # Killing the Docker client does not guarantee container cleanup.
            if reason and cid_file.is_file():
                cid = cid_file.read_text(encoding="ascii").strip()
                if re.fullmatch(r"[0-9a-f]{64}", cid):
                    subprocess.run(
                        ["docker", "rm", "-f", cid], env=client_env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=10, check=False,
                    )
        if reason:
            return [reason]
        if exit_code != 0:
            detail = output.decode("utf-8", errors="replace")[-2000:]
            return [f"isolated unit suite failed (exit {exit_code}): {detail}"]
        return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true", help="development only; evidence is not admissible")
    args = parser.parse_args()
    target_sha = git("rev-parse", "HEAD")
    if target_sha != args.target_sha:
        parser.error("checkout does not match the requested exact PR head SHA")
    clean = not bool(git("status", "--porcelain"))
    if not clean and not args.allow_dirty:
        parser.error("worktree is dirty; exact-SHA evidence requires a clean checkout")
    functions = {
        "source_integrity": source_integrity,
        "unit": unit,
        "security": security,
        "dependencies": dependencies,
        "licenses": licenses,
        "secrets": secrets,
        "test_integrity": lambda: test_integrity(args.base_sha, target_sha),
        "traceability": traceability,
    }
    details = {name: function() for name, function in functions.items()}
    checks = {name: "PASS" if not errors else "FAIL" for name, errors in details.items()}
    report = {"schema_version": 1, "policy_source": os.environ.get("HAYOOL_POLICY_SOURCE", "local-unverified"), "traceability_source": "head_commit_message", "base_sha": args.base_sha, "target_sha": target_sha, "workspace_clean": clean, "checks": checks, "errors": details}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"target_sha": target_sha, "workspace_clean": clean, "checks": checks}, sort_keys=True))
    return 0 if clean and all(value == "PASS" for value in checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
