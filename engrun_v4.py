"""Read-only ENG-RUN v4 verifier for the independently protected M0 gate.

The manifest is untrusted data. This program never imports, runs, or checks out
candidate PR code and never reads the GitHub App key. PASS is computed from
GitHub server state, the independent artifact, and local Codex session records.
Local session records are unsigned consistency evidence, not signatures.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
_publisher_spec = importlib.util.spec_from_file_location(
    "engrun_trusted_publisher", ROOT / "publisher.py")
assert _publisher_spec is not None and _publisher_spec.loader is not None
publisher = importlib.util.module_from_spec(_publisher_spec)
_publisher_spec.loader.exec_module(publisher)
gate = publisher.gate
SESSION_ROOT = Path("/mnt/c/Users/erfan/.codex/sessions")
POLICY_FILE = ROOT / "engrun_v4_policy.json"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SESSION_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
EXEC_ID = re.compile(r"exec-[0-9a-f-]{36}\Z")
MAX_JSON = 2_000_000
MAX_SESSION = 128 * 1024 * 1024
MAX_SESSION_LINE = 2_000_000
MAX_REPORT = 1_000_000
ENVIRONMENT = "hayool-trusted-publisher"
AI_PASS_FIXTURE_PATH = "samples/injected-ai-pass.json"
WORKFLOW_SPOOF_PATH = ".github/workflows/spoof-trusted-status.yml"
AI_PASS_FIXTURE = (b'{"not_real_reviews":true,"synthetic_votes":["PASS","PASS"],'
                   b'"test_fixture":true}\n')


class VerificationError(Exception):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise VerificationError(reason)


def _object_pairs(pairs: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def _json_bytes(raw: bytes) -> object:
    require(len(raw) <= MAX_JSON, "JSON exceeds size limit")
    return json.loads(raw, object_pairs_hook=_object_pairs)


def _time(value: object) -> datetime:
    require(isinstance(value, str), "timestamp missing")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _positive(value: object) -> bool:
    return type(value) is int and value > 0


class ReadOnlyGitHub:
    """Bounded GET-only transport; the read token is never printed or stored."""

    def __init__(self, token: str = "") -> None:
        self.token = token

    def _request(self, path: str, *, redirect: bool = True, limit: int = MAX_JSON):
        route = path.split("?", 1)[0]
        require(route.startswith("repos/") and all(
            segment not in {"", ".", ".."} for segment in route.split("/")),
            "invalid GitHub path")
        require(not any(char in path for char in "\r\n\\#"), "invalid GitHub path")
        headers = {"Accept": "application/vnd.github+json",
                   "User-Agent": "hayool-engrun-v4/1",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request("https://api.github.com/" + path,
                                         headers=headers, method="GET")
        opener = urllib.request.build_opener() if redirect else urllib.request.build_opener(
            type("NoRedirect", (urllib.request.HTTPRedirectHandler,),
                 {"redirect_request": lambda self, req, fp, code, msg, hdrs, url: None})())
        with opener.open(request, timeout=20) as response:
            raw = response.read(limit + 1)
        require(len(raw) <= limit, "GitHub response exceeds size limit")
        return raw

    def get(self, path: str) -> dict:
        value = _json_bytes(self._request(path))
        require(isinstance(value, dict), "GitHub response is not an object")
        return value

    def listing(self, path: str) -> list:
        value = _json_bytes(self._request(path))
        require(isinstance(value, list), "GitHub response is not an array")
        return value

    def artifact(self, path: str) -> bytes:
        try:
            return self._request(path, redirect=False, limit=publisher.MAX_ZIP)
        except urllib.error.HTTPError as error:
            require(error.code in {301, 302, 303, 307, 308},
                    "artifact download failed")
            location = error.headers.get("Location", "")
            parsed = urllib.parse.urlsplit(location)
            require(parsed.scheme == "https" and bool(parsed.hostname) and
                    parsed.username is None and parsed.password is None,
                    "unsafe artifact redirect")
            request = urllib.request.Request(location, headers={
                "User-Agent": "hayool-engrun-v4/1"}, method="GET")
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read(publisher.MAX_ZIP + 1)
            require(len(raw) <= publisher.MAX_ZIP, "artifact exceeds size limit")
            return raw


def validate_manifest(run: dict, config: dict) -> None:
    required = {"schema_version", "mode", "ci_mode", "repository", "pr_number",
                "base_sha", "head_sha", "trusted_repository", "trusted_policy_sha",
                "trusted_run_id", "trusted_run_attempt", "artifact_id",
                "artifact_digest", "report_sha256", "writer", "reviewers",
                "limits", "kill_switch", "negative_evidence"}
    require(isinstance(run, dict) and set(run) == required,
            "ENG-RUN v4 manifest fields mismatch")
    require(run["schema_version"] == 4 and run["mode"] == "shadow" and
            run["ci_mode"] == "independent_app", "unsupported ENG-RUN mode")
    require(run["repository"] == config["target_repo"] and
            run["trusted_repository"] == config["trusted_repo"] and
            _positive(run["pr_number"]) and _positive(run["trusted_run_id"]) and
            _positive(run["trusted_run_attempt"]) and _positive(run["artifact_id"]),
            "repository or run identity mismatch")
    require(run["pr_number"] != config["migration"]["pr_number"],
            "migration PR cannot be the Shadow ENG-RUN candidate")
    for key in ("base_sha", "head_sha", "trusted_policy_sha"):
        gate.exact_sha(run[key], key)
    require(isinstance(run["artifact_digest"], str) and
            re.fullmatch(r"sha256:[0-9a-f]{64}", run["artifact_digest"]) is not None and
            isinstance(run["report_sha256"], str) and
            SHA256.fullmatch(run["report_sha256"]) is not None,
            "artifact digest identity invalid")
    validate_negative_evidence(run, config)


def verify_local_policy(policy_sha: str) -> None:
    """Do not run candidate code or an uncommitted policy checkout."""
    def git(*args: str) -> str:
        return subprocess.check_output(["git", "-C", str(ROOT), *args],
                                       text=True, timeout=20,
                                       stderr=subprocess.DEVNULL).strip()
    require(git("rev-parse", "HEAD") == policy_sha and
            git("branch", "--show-current") == "main" and
            git("status", "--porcelain") == "", "v4 policy is not clean protected main")


def verify_environment(api: ReadOnlyGitHub, config: dict) -> int:
    repo = config["trusted_repo"]
    prefix = f"repos/{repo}/environments/{ENVIRONMENT}"
    environment = api.get(prefix)
    branch = environment.get("deployment_branch_policy")
    require(environment.get("name") == ENVIRONMENT and isinstance(branch, dict) and
            branch.get("custom_branch_policies") is True and
            branch.get("protected_branches") is False,
            "publisher environment branch restriction missing")
    policies = api.get(prefix + "/deployment-branch-policies?per_page=100")
    rows = policies.get("branch_policies")
    require(isinstance(rows, list) and policies.get("total_count") == len(rows) and
            len(rows) == 1 and rows[0].get("name") == "main",
            "publisher environment is not main-only")
    variable = api.get(prefix + "/variables/HAYOOL_GATE_APP_ID")
    raw = variable.get("value")
    require(variable.get("name") == "HAYOOL_GATE_APP_ID" and
            isinstance(raw, str) and re.fullmatch(r"[1-9][0-9]*", raw) is not None,
            "protected environment App ID unavailable")
    app_id = int(raw)
    require(config.get("github_app_id") in {None, app_id},
            "protected config and environment App IDs disagree")
    return app_id


def verify_publisher_secret_metadata(api: ReadOnlyGitHub, config: dict,
                                     publisher_started_at: object) -> None:
    """Read only the App key's name and timestamps, never its secret value."""
    route = (f"repos/{config['trusted_repo']}/environments/{ENVIRONMENT}"
             "/secrets/HAYOOL_GATE_APP_PRIVATE_KEY")
    secret = api.get(route)
    require(secret.get("name") == "HAYOOL_GATE_APP_PRIVATE_KEY" and
            _time(secret.get("created_at")) <= _time(secret.get("updated_at")) <=
            _time(publisher_started_at),
            "protected publisher App key metadata missing or changed after run")


def verify_protection(api: ReadOnlyGitHub, config: dict, app_id: int) -> None:
    for repo, name, source in ((config["target_repo"], config["check_name"], app_id),
                               (config["trusted_repo"], "independent-gate-selftest", 15368)):
        protection = api.get(f"repos/{repo}/branches/main/protection")
        status = protection.get("required_status_checks") or {}
        checks = status.get("checks")
        reviews = protection.get("required_pull_request_reviews") or {}
        require(status.get("strict") is True and isinstance(checks, list) and
                checks == [{"context": name, "app_id": source}] and
                status.get("contexts") == [name] and
                reviews.get("required_approving_review_count", 0) >= 1 and
                reviews.get("dismiss_stale_reviews") is True and
                reviews.get("require_last_push_approval") is True and
                (protection.get("enforce_admins") or {}).get("enabled") is True and
                (protection.get("allow_force_pushes") or {}).get("enabled") is False and
                (protection.get("allow_deletions") or {}).get("enabled") is False,
                "required check/review/branch protection mismatch: " + repo)


def verify_actions_policy(api: ReadOnlyGitHub, config: dict) -> None:
    for repo, number, expected in ((config["trusted_repo"], 5994,
                                    {"pull_request_target", "workflow_dispatch"}),
                                   (config["target_repo"], 5892,
                                    {"pull_request_target"})):
        policy = api.get(f"repos/{repo}/actions/policies/{number}")
        rules = policy.get("rules")
        require(policy.get("enforcement") == "active" and
                (policy.get("conditions") or {}).get("workflow_path") ==
                {"include": ["~ALL"], "exclude": []} and
                isinstance(rules, list) and len(rules) == 1 and
                rules[0].get("type") == "restrict_action_events" and
                set((rules[0].get("parameters") or {}).get("allowed_events", [])) == expected,
                "Actions event policy mismatch: " + repo)


def verify_app_check(api: ReadOnlyGitHub, config: dict, sha: str,
                     app_id: int, run_id: int, attempt: int, report_hash: str,
                     expected_conclusion: str = "success") -> int:
    require(expected_conclusion in {"success", "failure"}, "invalid App conclusion")
    name = config["check_name"]
    route = (f"repos/{config['target_repo']}/commits/{sha}/check-runs?"
             f"check_name={urllib.parse.quote(name)}&filter=latest&per_page=100")
    listing = api.get(route)
    rows = listing.get("check_runs")
    require(isinstance(rows, list) and listing.get("total_count") == len(rows),
            "App check listing incomplete")
    matches = [row for row in rows if isinstance(row, dict) and
               row.get("name") == name and (row.get("app") or {}).get("id") == app_id]
    require(len(matches) == 1, "independent App check missing or ambiguous")
    check = matches[0]
    require(_positive(check.get("id")) and check.get("head_sha") == sha and
            check.get("status") == "completed" and check.get("conclusion") == expected_conclusion and
            check.get("external_id") == f"{run_id}:{attempt}:{report_hash}" and
            check.get("details_url") ==
            f"https://github.com/{config['trusted_repo']}/actions/runs/{run_id}",
            "independent App check source, SHA, or report mismatch")
    return check["id"]


def verify_publisher_artifact(api: ReadOnlyGitHub, config: dict, run: dict,
                              target: dict, gate_artifact: dict, app_id: int,
                              check_ids: dict[str, int],
                              expected_decision: str = "PASS") -> dict:
    """Bind actual App check IDs to the separate protected publisher output."""
    repo = config["trusted_repo"]
    require(expected_decision in {"PASS", "FAIL"}, "invalid publisher decision")
    conclusion = "success" if expected_decision == "PASS" else "failure"
    run_id, attempt = run["trusted_run_id"], run["trusted_run_attempt"]
    listing = api.get(f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100")
    rows = listing.get("artifacts")
    require(isinstance(rows, list) and listing.get("total_count") == len(rows),
            "publisher artifact listing incomplete")
    name = f"independent-publisher-{run_id}-{attempt}"
    matches = [row for row in rows if isinstance(row, dict) and row.get("name") == name]
    require(len(matches) == 1, "publisher artifact absent or duplicated")
    selected = matches[0]
    origin = selected.get("workflow_run") or {}
    digest = selected.get("digest")
    require(_positive(selected.get("id")) and selected.get("expired") is False and
            type(selected.get("size_in_bytes")) is int and
            0 < selected["size_in_bytes"] <= publisher.MAX_ZIP and
            origin.get("id") == run_id and origin.get("repository_id") ==
            config["trusted_repo_id"] and origin.get("head_repository_id") ==
            config["trusted_repo_id"] and origin.get("head_branch") == "main" and
            origin.get("head_sha") == run["trusted_policy_sha"] and
            isinstance(digest, str) and publisher.SHA256.fullmatch(digest) is not None,
            "publisher artifact source or digest invalid")
    zipped = api.artifact(f"repos/{repo}/actions/artifacts/{selected['id']}/zip")
    require(hashlib.sha256(zipped).hexdigest() == digest[7:],
            "publisher ZIP digest mismatch")
    with zipfile.ZipFile(io.BytesIO(zipped)) as bundle:
        require(bundle.namelist() == ["publisher-result.json"],
                "publisher artifact member invalid")
        member = bundle.getinfo("publisher-result.json")
        require(member.file_size <= MAX_REPORT, "publisher result oversized")
        raw = bundle.read(member)
    result = _json_bytes(raw)
    require(isinstance(result, dict) and result.get("schema_version") == 1 and
            result.get("decision") == expected_decision and result.get("target") == target and
            result.get("source") == {
                "trusted_repo": repo, "trusted_policy_sha": run["trusted_policy_sha"],
                "trusted_run_id": run_id, "trusted_run_attempt": attempt,
                "github_app_id": app_id} and
            result.get("artifact") == gate_artifact and
            result.get("checks") == [
                {"sha": target["merge_sha"], "check_run_id": check_ids["merge"],
                 "app_id": app_id, "conclusion": conclusion},
                {"sha": target["head_sha"], "check_run_id": check_ids["head"],
                 "app_id": app_id, "conclusion": conclusion}],
            "publisher result conflicts with verified App check or gate artifact")
    return {"artifact_id": selected["id"], "artifact_digest": digest,
            "report_sha256": hashlib.sha256(raw).hexdigest()}


def verify_migration_review(api: ReadOnlyGitHub, config: dict,
                            evaluated_pr: int, evaluated_base_sha: str) -> None:
    """Bind the actual PR #7 human approval, not a draft Shadow PR review."""
    migration = config["migration"]
    number, head_sha = migration["pr_number"], migration["head_sha"]
    repo = config["target_repo"]
    pr = api.get(f"repos/{repo}/pulls/{number}")
    author = (pr.get("user") or {}).get("login")
    require(pr.get("number") == number and
            (pr.get("head") or {}).get("sha") == head_sha and
            (pr.get("head") or {}).get("repo", {}).get("id") ==
            config["target_repo_id"] and
            isinstance(author, str) and bool(author),
            "migration PR #7 exact head or author changed")
    require(evaluated_pr != number, "migration PR is not a Shadow candidate")
    merger = (pr.get("merged_by") or {}).get("login")
    require(pr.get("state") == "closed" and pr.get("merged_at") is not None and
            (pr.get("merged_by") or {}).get("type") == "User" and
            isinstance(merger, str) and bool(merger) and merger != author,
            "migration PR #7 is not independently merged")
    shadow = api.get(f"repos/{repo}/pulls/{evaluated_pr}")
    require(shadow.get("number") == evaluated_pr and
            _time(shadow.get("created_at")) > _time(pr["merged_at"]),
            "Shadow PR was not created after the migration merge")
    merge_sha = gate.exact_sha(pr.get("merge_commit_sha"), "migration merge SHA")
    require(merge_sha not in {head_sha, migration["base_sha"]},
            "migration has no two-parent merge commit")
    merged = api.get(f"repos/{repo}/git/commits/{merge_sha}")
    head = api.get(f"repos/{repo}/git/commits/{head_sha}")
    parents = merged.get("parents")
    require(merged.get("sha") == merge_sha and head.get("sha") == head_sha and
            isinstance(parents, list) and
            [row.get("sha") for row in parents if isinstance(row, dict)] ==
            [migration["base_sha"], head_sha] and
            merged.get("tree", {}).get("sha") ==
            head.get("tree", {}).get("sha"),
            "migration merge parents/tree differ from approved exact head")
    comparison = api.get(f"repos/{repo}/compare/{merge_sha}...{evaluated_base_sha}")
    require(comparison.get("merge_base_commit", {}).get("sha") == merge_sha and
            comparison.get("status") in {"ahead", "identical"},
            "Shadow base does not descend from approved migration merge")
    rows = api.listing(f"repos/{repo}/pulls/{number}/reviews?per_page=100")
    require(len(rows) < 100 and all(isinstance(row, dict) for row in rows),
            "native review listing incomplete")
    latest: dict[str, dict] = {}
    for row in rows:
        login = (row.get("user") or {}).get("login")
        if isinstance(login, str):
            latest[login] = row
    require(any(login != author and row.get("state") == "APPROVED" and
                (row.get("user") or {}).get("type") == "User" and
                row.get("commit_id") == head_sha for login, row in latest.items()),
            "PR #7 exact-head nonauthor GitHub approval absent")


def validate_negative_evidence(run: dict, config: dict) -> None:
    negative = run["negative_evidence"]
    require(isinstance(negative, dict) and set(negative) ==
            {"hard_failure", "workflow_spoof", "wrong_source"},
            "required negative evidence missing")
    common = {"pr_number", "head_sha", "trusted_run_id", "trusted_run_attempt",
              "artifact_id", "artifact_digest", "report_sha256"}
    for name in ("hard_failure", "workflow_spoof"):
        ref = negative[name]
        extra = ({"blocked_run_id", "blocked_run_attempt", "workflow_path"}
                 if name == "workflow_spoof" else set())
        require(isinstance(ref, dict) and set(ref) == common | extra and
                all(_positive(ref[key]) for key in
                    ("pr_number", "trusted_run_id", "trusted_run_attempt", "artifact_id")) and
                ref["pr_number"] not in {run["pr_number"], config["migration"]["pr_number"]},
                "negative evidence identity invalid")
        gate.exact_sha(ref["head_sha"], "negative head SHA")
        require(isinstance(ref["artifact_digest"], str) and
                publisher.SHA256.fullmatch(ref["artifact_digest"]) is not None and
                isinstance(ref["report_sha256"], str) and
                SHA256.fullmatch(ref["report_sha256"]) is not None,
                "negative artifact digest invalid")
    hard, spoof, wrong = (negative[name] for name in
                           ("hard_failure", "workflow_spoof", "wrong_source"))
    require(hard["pr_number"] != spoof["pr_number"] and
            hard["trusted_run_id"] != spoof["trusted_run_id"] and
            _positive(spoof["blocked_run_id"]) and
            _positive(spoof["blocked_run_attempt"]) and
            spoof["workflow_path"] == WORKFLOW_SPOOF_PATH and
            isinstance(wrong, dict) and set(wrong) ==
            {"status_id", "creator_login"} and _positive(wrong["status_id"]) and
            isinstance(wrong["creator_login"], str) and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", wrong["creator_login"]) is not None,
            "negative attack references invalid")


def _blocked_pr(api: ReadOnlyGitHub, config: dict, target: dict) -> dict:
    pr = api.get(f"repos/{config['target_repo']}/pulls/{target['pr_number']}")
    require(pr.get("number") == target["pr_number"] and pr.get("state") == "open" and
            (pr.get("head") or {}).get("sha") == target["head_sha"] and
            (pr.get("base") or {}).get("sha") == target["base_sha"] and
            pr.get("mergeable_state") == "blocked", "negative PR is not blocked")
    return pr


def verify_failed_attestation(api: ReadOnlyGitHub, config: dict, run: dict,
                               ref: dict, app_id: int, *, kill_injection: bool) -> tuple[dict, dict]:
    evidence = {**ref, "trusted_policy_sha": run["trusted_policy_sha"]}
    target, report, artifact = publisher.verify_publishable(
        api, api, config, ref["pr_number"], ref["head_sha"],
        run["trusted_repository"], run["trusted_policy_sha"],
        ref["trusted_run_id"], ref["trusted_run_attempt"])
    require(target["base_sha"] == run["base_sha"] and report.get("decision") == "FAIL" and
            artifact == {key: ref[key] for key in
                         ("artifact_id", "artifact_digest", "report_sha256")},
            "negative evidence is not exact-base FAIL artifact")
    baseline = report["baseline"]
    checks, errors = baseline.get("checks"), baseline.get("errors")
    require(baseline.get("schema_version") == 2 and
            baseline.get("policy_source") == "independent-trusted-repo" and
            baseline.get("protected_main_policy_sha") == config["policy_source_sha"] and
            baseline.get("protected_main_baseline_sha256") == config["baseline_sha256"] and
            baseline.get("pr_number") == ref["pr_number"] and
            baseline.get("base_sha") == run["base_sha"] and
            baseline.get("target_sha") == ref["head_sha"] and
            baseline.get("workspace_clean") is True and
            baseline.get("migration_rule") == "frozen_paths" and
            type(report.get("baseline_returncode")) is int and
            report["baseline_returncode"] != 0 and
            isinstance(checks, dict) and isinstance(errors, dict) and
            set(checks) == set(errors) == gate.HARD_CHECKS and
            report.get("checks") == checks and report.get("errors") == errors and
            all(checks[key] in {"PASS", "FAIL"} and isinstance(errors[key], list) and
                all(isinstance(value, str) and value for value in errors[key]) and
                (checks[key] == "PASS") == (errors[key] == []) for key in checks) and
            "FAIL" in checks.values(), "negative report is not a deterministic hard failure")
    suites = baseline.get("isolated_suites")
    expected_suites = {"decision": "PASS", "expected_unit_tests": 36,
                       "expected_regression_tests": 24, "exit_code": 0,
                       "image": gate.TEST_IMAGE, "network": "none", "read_only": True,
                       "timeout_seconds": 90, "memory_bytes": 536870912, "pids": 64}
    require(isinstance(suites, dict) and report.get("isolated_suites") == suites and
            all(suites.get(key) == value for key, value in expected_suites.items()),
            "negative evidence contains failed or missing isolated suites")
    if kill_injection:
        require(checks["security"] == "FAIL" and
                "M0 shadow kill switch policy changed" in errors["security"] and
                report["changed_file_sha256"].get(AI_PASS_FIXTURE_PATH) ==
                hashlib.sha256(AI_PASS_FIXTURE).hexdigest(),
                "hard failure lacks the intentional kill-switch injection")
    source = config["trusted_repo"]
    run_id, attempt = ref["trusted_run_id"], ref["trusted_run_attempt"]
    observed = api.get(f"repos/{source}/actions/runs/{run_id}")
    jobs = api.get(f"repos/{source}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    rows = jobs.get("jobs")
    require(observed.get("id") == run_id and observed.get("run_attempt") == attempt and
            observed.get("head_sha") == run["trusted_policy_sha"] and
            observed.get("status") == "completed" and observed.get("conclusion") == "failure" and
            isinstance(rows, list) and jobs.get("total_count") == len(rows) == 2 and
            {row.get("name") for row in rows if isinstance(row, dict)} == {"evaluate", "publish"} and
            all(isinstance(row, dict) and row.get("status") == "completed" and
                row.get("conclusion") == "failure" and
                row.get("head_sha") == run["trusted_policy_sha"] for row in rows),
            "negative run/jobs do not match completed failure publication")
    check_ids = {name: verify_app_check(api, config, target[key], app_id, run_id,
                                       attempt, artifact["report_sha256"], "failure")
                 for name, key in (("head", "head_sha"), ("merge", "merge_sha"))}
    published = verify_publisher_artifact(api, config, evidence, target, artifact,
                                          app_id, check_ids, "FAIL")
    _blocked_pr(api, config, target)
    return target, {"decision": "FAIL", "pr_number": ref["pr_number"],
                    "base_sha": target["base_sha"], "head_sha": target["head_sha"],
                    "merge_sha": target["merge_sha"], "trusted_policy_sha": run["trusted_policy_sha"],
                    "trusted_run_id": run_id, "trusted_run_attempt": attempt,
                    "artifact": artifact, "publisher_artifact": published,
                    "check_ids": check_ids, "hard_checks": checks,
                    "synthetic_ai_pass_fixture_sha256": (
                        hashlib.sha256(AI_PASS_FIXTURE).hexdigest() if kill_injection else None),
                    "changed_file_sha256": report["changed_file_sha256"]}


def verify_negative_evidence(api: ReadOnlyGitHub, config: dict, run: dict,
                              app_id: int) -> dict:
    validate_negative_evidence(run, config)
    negative = run["negative_evidence"]
    hard_target, hard = verify_failed_attestation(
        api, config, run, negative["hard_failure"], app_id, kill_injection=True)
    spoof_target, spoof = verify_failed_attestation(
        api, config, run, negative["workflow_spoof"], app_id, kill_injection=False)
    ref = negative["workflow_spoof"]
    require(spoof["changed_file_sha256"].get(ref["workflow_path"]) ==
            hashlib.sha256((ROOT / "fixtures/workflow-spoof.yml").read_bytes()).hexdigest(),
            "workflow spoof is not the reviewed required-check attack fixture")
    repo = config["target_repo"]
    blocked = api.get(f"repos/{repo}/actions/runs/{ref['blocked_run_id']}")
    links = blocked.get("pull_requests")
    pr = _blocked_pr(api, config, spoof_target)
    require(blocked.get("id") == ref["blocked_run_id"] and
            blocked.get("run_attempt") == ref["blocked_run_attempt"] and
            (blocked.get("repository") or {}).get("id") == config["target_repo_id"] and
            (blocked.get("head_repository") or {}).get("id") == config["target_repo_id"] and
            blocked.get("head_sha") == ref["head_sha"] and
            blocked.get("head_branch") == (pr.get("head") or {}).get("ref") and
            blocked.get("event") == "pull_request" and blocked.get("status") == "completed" and
            blocked.get("conclusion") == "startup_failure" and
            str(blocked.get("path", "")).split("@", 1)[0] == ref["workflow_path"] and
            isinstance(links, list) and len(links) == 1 and
            links[0].get("number") == ref["pr_number"] and
            (links[0].get("head") or {}).get("sha") == ref["head_sha"] and
            (links[0].get("base") or {}).get("sha") == run["base_sha"] and
            (links[0].get("head") or {}).get("repo", {}).get("id") == config["target_repo_id"] and
            (links[0].get("base") or {}).get("repo", {}).get("id") == config["target_repo_id"] and
            ref["workflow_path"] in spoof["changed_file_sha256"],
            "workflow spoof is not the exact policy-blocked PR run")
    jobs = api.get(f"repos/{repo}/actions/runs/{ref['blocked_run_id']}/attempts/"
                   f"{ref['blocked_run_attempt']}/jobs?per_page=100")
    require(jobs.get("total_count") == 0 and jobs.get("jobs") == [],
            "workflow spoof executed a job")
    wrong = negative["wrong_source"]
    statuses = api.listing(f"repos/{repo}/statuses/{hard_target['head_sha']}?per_page=100")
    require(len(statuses) < 100 and all(isinstance(row, dict) for row in statuses),
            "wrong-source status listing incomplete")
    matches = [row for row in statuses if row.get("id") == wrong["status_id"]]
    require(len(matches) == 1, "wrong-source status absent or duplicated")
    status = matches[0]
    failure = api.get(f"repos/{repo}/check-runs/{hard['check_ids']['head']}")
    require(status.get("state") == "success" and status.get("context") == config["check_name"] and
            (status.get("creator") or {}).get("login") == wrong["creator_login"] and
            (status.get("creator") or {}).get("type") == "User" and
            failure.get("id") == hard["check_ids"]["head"] and
            failure.get("head_sha") == hard_target["head_sha"] and
            (failure.get("app") or {}).get("id") == app_id and
            failure.get("conclusion") == "failure" and
            _time(status.get("created_at")) >= _time(failure.get("completed_at")),
            "wrong-source success did not coexist with the required App failure")
    for target in (hard_target, spoof_target):
        require(gate.verify_live_target(api, config, target["pr_number"], target["head_sha"]) == target,
                "negative PR moved during verification")
        _blocked_pr(api, config, target)
    return {"hard_failure": hard, "workflow_spoof": {
                **spoof, "blocked_run_id": ref["blocked_run_id"],
                "blocked_run_attempt": ref["blocked_run_attempt"], "executed_jobs": 0,
                "workflow_path": ref["workflow_path"]},
            "wrong_source": {"status_id": status["id"], "creator_login": wrong["creator_login"],
                "head_sha": hard_target["head_sha"], "context": status["context"],
                "state": status["state"], "required_app_id": app_id,
                "required_failure_check_id": failure["id"], "mergeable_state": "blocked",
                "status_record_sha256": hashlib.sha256(json.dumps(
                    status, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}}


def _session_rows(session_id: str, max_bytes: int) -> list[dict]:
    require(SESSION_ID.fullmatch(session_id) is not None, "session ID invalid")
    root = SESSION_ROOT.resolve(strict=True)
    matches = list(root.glob(f"????/??/??/rollout-*-{session_id}.jsonl"))
    require(len(matches) == 1, "session absent or ambiguous")
    path = matches[0]
    require(not path.is_symlink() and path.resolve(strict=True).is_relative_to(root) and
            path.stat().st_size <= max_bytes, "session path or size invalid")
    raw = path.read_bytes()
    require(len(raw) <= max_bytes, "session exceeds size limit")
    lines = raw.splitlines()
    require(lines and all(len(line) <= MAX_SESSION_LINE for line in lines),
            "session line invalid")
    rows = [json.loads(line) for line in lines]
    require(all(isinstance(row, dict) for row in rows), "session record invalid")
    return rows


def verify_writer(api: ReadOnlyGitHub, config: dict, run: dict) -> tuple[str, str, float]:
    writer = run["writer"]
    required = {"id", "session_id", "branch", "github_login", "checkout",
                "effective_provider", "effective_model", "lease_issued_at",
                "lease_expires_at", "commit_execution_id", "sha_execution_id",
                "commit_at", "sha_observed_at"}
    require(isinstance(writer, dict) and set(writer) == required and
            writer["id"] == "/root" and
            all(isinstance(writer[k], str) and writer[k] for k in required) and
            writer["branch"].startswith("codex/") and
            EXEC_ID.fullmatch(writer["commit_execution_id"]) is not None and
            EXEC_ID.fullmatch(writer["sha_execution_id"]) is not None,
            "writer identity or lease fields invalid")
    checkout = Path(writer["checkout"])
    require(checkout.is_absolute() and checkout.resolve(strict=True) != ROOT and
            not checkout.resolve(strict=True).is_relative_to(ROOT),
            "writer checkout identity invalid")
    issued, expires = _time(writer["lease_issued_at"]), _time(writer["lease_expires_at"])
    committed, observed = _time(writer["commit_at"]), _time(writer["sha_observed_at"])
    require(issued <= committed <= observed <= expires and
            (expires - issued).total_seconds() <= 3600,
            "writer lease or event order invalid")
    rows = _session_rows(writer["session_id"], MAX_SESSION)
    meta = (rows[0].get("payload") or {}) if rows[0].get("type") == "session_meta" else {}
    parent_thread_id = meta.get("parent_thread_id")
    require(meta.get("id") == writer["session_id"] and
            meta.get("agent_path") is None and
            (parent_thread_id is None or
             (isinstance(parent_thread_id, str) and
              SESSION_ID.fullmatch(parent_thread_id) is not None)) and
            meta.get("model_provider") == writer["effective_provider"],
            "writer session identity mismatch")
    selected: dict[str, tuple[int, datetime, dict, object, object]] = {}
    turn_starts: dict[str, datetime] = {}
    model: object = None
    for index, row in enumerate(rows):
        payload = row.get("payload") or {}
        if row.get("type") == "turn_context":
            model = payload.get("model")
        if row.get("type") == "event_msg" and payload.get("type") == "task_started":
            turn_id = payload.get("turn_id")
            if isinstance(turn_id, str):
                require(turn_id not in turn_starts, "duplicate writer turn start")
                turn_starts[turn_id] = _time(row.get("timestamp"))
        if row.get("type") != "event_msg" or payload.get("type") != "item_completed":
            continue
        item = payload.get("item")
        if isinstance(item, str):
            require(len(item) <= MAX_SESSION_LINE, "writer command item too large")
            item = ast.literal_eval(item)
        if not isinstance(item, dict) or item.get("type") != "CommandExecution":
            continue
        event_id = item.get("id")
        if event_id in {writer["commit_execution_id"], writer["sha_execution_id"]}:
            require(event_id not in selected, "duplicate writer execution")
            selected[event_id] = (index, _time(row.get("timestamp")), item, model,
                                  payload.get("turn_id"))
    commit = selected.get(writer["commit_execution_id"])
    sha = selected.get(writer["sha_execution_id"])
    require(commit is not None and sha is not None, "writer commit/SHA session events absent")
    def command(item: dict) -> str:
        raw = item.get("command")
        require(item.get("status") == "completed" and item.get("exit_code") == 0 and
                item.get("cwd") == "file://" + checkout.resolve(strict=True).as_posix() and
                isinstance(raw, list) and len(raw) == 3 and raw[:2] ==
                ["/bin/bash", "-lc"] and isinstance(raw[2], str),
                "writer command execution identity invalid")
        return raw[2]
    commit_cmd, sha_cmd = command(commit[2]), command(sha[2])
    require(re.fullmatch(
        r"git -c core\.abbrev=40 commit (?:-F /tmp/[A-Za-z0-9._-]+|--amend --no-edit)",
        commit_cmd) is not None and sha_cmd == "git rev-parse HEAD",
        "writer command form invalid")
    first_line = str(commit[2].get("stdout", "")).splitlines()
    match = re.fullmatch(r"\[([^ ]+) ([0-9a-f]{40})\].*", first_line[0]) if first_line else None
    require(match is not None and match.group(1) == writer["branch"] and
            match.group(2) == run["head_sha"] and
            str(sha[2].get("stdout", "")).strip() == run["head_sha"] and
            commit[0] < sha[0] and commit[1] == committed and sha[1] == observed and
            commit[3] == writer["effective_model"],
            "writer session does not bind exact commit/model")
    turn_id = commit[4]
    started = turn_starts.get(turn_id) if isinstance(turn_id, str) else None
    require(started is not None and sha[4] == turn_id and
            issued == started and expires == started + timedelta(seconds=3600) and
            started <= committed <= observed,
            "writer lease does not bind recorded turn start/end")
    pr = api.get(f"repos/{config['target_repo']}/pulls/{run['pr_number']}")
    commit_api = api.get(f"repos/{config['target_repo']}/commits/{run['head_sha']}")
    login = writer["github_login"]
    require(pr.get("user", {}).get("login") == login and
            pr.get("head", {}).get("ref") == writer["branch"] and
            pr.get("head", {}).get("sha") == run["head_sha"] and
            commit_api.get("sha") == run["head_sha"] and
            (commit_api.get("author") or {}).get("login") == login and
            (commit_api.get("committer") or {}).get("login") == login,
            "writer GitHub identity does not match exact PR commit")
    return (writer["session_id"], parent_thread_id or writer["session_id"],
            (observed - started).total_seconds())


def _report(root: Path, relative: object, digest: object) -> bytes:
    require(isinstance(relative, str) and relative and
            isinstance(digest, str) and SHA256.fullmatch(digest) is not None,
            "review report path or digest invalid")
    original = root / relative
    require(not original.is_symlink(), "review report symlink invalid")
    path = original.resolve(strict=True)
    require(path.is_relative_to(root.resolve(strict=True)) and path.is_file() and
            not path.is_symlink() and path.stat().st_size <= MAX_REPORT,
            "review report escapes evidence root or is oversized")
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, "review report digest mismatch")
    return raw


REVIEW_REPOSITORIES = frozenset({"xbroute/hayool-os",
                                   "xbroute/hayool-m0-trusted-gate"})
REVIEW_TOOL_ARGUMENTS = {
    "fetch_commit": ({"commit_sha", "repo_full_name"}, set()),
    "fetch_file": ({"path", "ref", "repository_full_name"},
                   {"encoding", "start_line", "end_line"}),
    "get_pr_info": ({"pr_number", "repository_full_name"}, set()),
    "fetch_pr_patch": ({"pr_number", "repo_full_name"}, set()),
}


def _review_api_call(item: dict, completed: bool) -> set[tuple[str, str]]:
    """Validate the actual server tool event, never model-written shell text.

    These connector methods have no write operation or credential argument.
    The hosting agent is not OS-sandboxed by this audit; any other executed
    tool makes its session ineligible. Transcripts remain unsigned local data.
    """
    action = item.get("actionName")
    require(item.get("server") == "codex_apps" and
            item.get("appName") == "GitHub" and
            isinstance(action, str) and action in REVIEW_TOOL_ARGUMENTS and
            item.get("tool") == "github." + action and
            item.get("readOnlyHint") is True,
            "reviewer used a tool outside the read-only GitHub surface")
    arguments = item.get("arguments")
    required, optional = REVIEW_TOOL_ARGUMENTS[action]
    require(isinstance(arguments, dict) and required <= set(arguments) and
            set(arguments) <= required | optional,
            "reviewer GitHub tool arguments mismatch")
    repo_key = "repo_full_name" if "repo_full_name" in required else "repository_full_name"
    repository = arguments[repo_key]
    require(isinstance(repository, str) and repository in REVIEW_REPOSITORIES,
            "reviewer repository is not allowlisted")
    exact_sha = None
    if action == "fetch_commit":
        exact_sha = arguments["commit_sha"]
        require(isinstance(exact_sha, str) and gate.SHA.fullmatch(exact_sha) is not None,
                "reviewer commit must use an exact SHA")
    elif action == "fetch_file":
        exact_sha = arguments["ref"]
        require(isinstance(exact_sha, str) and gate.SHA.fullmatch(exact_sha) is not None,
                "reviewer file must use an exact SHA ref")
        path = arguments["path"]
        require(isinstance(path, str) and
                re.fullmatch(r"[A-Za-z0-9._/-]+", path) is not None and
                not path.startswith(("/", "-", "~")) and
                all(part not in {"", ".", "..", ".git"} for part in path.split("/")),
                "reviewer file path is not a safe repository path")
        require(arguments.get("encoding", "utf-8") == "utf-8" and
                all(arguments.get(key) is None or
                    _positive(arguments[key]) for key in ("start_line", "end_line")) and
                not (arguments.get("start_line") and arguments.get("end_line") and
                     arguments["start_line"] > arguments["end_line"]),
                "reviewer file range or encoding invalid")
    else:
        require(_positive(arguments["pr_number"]), "reviewer PR number invalid")
    if not completed:
        return set()
    require(item.get("status") == "completed", "reviewer API call did not complete")
    result = item.get("result")
    require(isinstance(result, dict) and result.get("isError") is False and
            isinstance(result.get("structuredContent"), dict),
            "reviewer API read failed or has no structured result")
    content = result["structuredContent"]
    if action == "fetch_commit":
        commit = content.get("commit")
        require(isinstance(commit, dict) and commit.get("sha") == exact_sha and
                commit.get("repository_full_name") == repository and
                commit.get("url") ==
                f"https://api.github.com/repos/{repository}/commits/{exact_sha}",
                "reviewer commit response does not bind exact repository/SHA")
        return {(repository, exact_sha)}
    if action == "fetch_file":
        require(content.get("display_url") ==
                f"https://github.com/{repository}/blob/{exact_sha}/{arguments['path']}" and
                content.get("encoding") == "utf-8" and
                isinstance(content.get("content"), str) and
                gate.SHA.fullmatch(str(content.get("sha", ""))) is not None,
                "reviewer file response does not bind exact repository/ref/path")
    # A file range or PR patch is context, not whole-commit inspection. Every
    # eligible session must also independently fetch the exact commit record.
    return set()


def _review_invocation(source: object) -> tuple[str, str]:
    """Accept one literal API read, not a general JavaScript program.

    Actual connector events remain the read-only execution boundary. This
    closed wrapper also excludes tool calls that might not emit an audited
    item event, and binds every declared read to its completed server event.
    """
    prefix = "text(await tools.mcp__codex_apps__github_"
    require(isinstance(source, str) and len(source) <= MAX_SESSION_LINE,
            "reviewer orchestration is not one literal GitHub read")
    source = source.strip()
    require(source.startswith(prefix) and source.endswith("));"),
            "reviewer orchestration is not one literal GitHub read")
    action, separator, raw = source[len(prefix):].partition("(")
    require(separator == "(" and action in REVIEW_TOOL_ARGUMENTS,
            "reviewer orchestration method is not allowlisted")
    arguments = _json_bytes(raw[:-3].encode("utf-8"))
    _review_api_call({"server": "codex_apps", "appName": "GitHub",
        "actionName": action, "tool": "github." + action,
        "readOnlyHint": True, "arguments": arguments}, False)
    return action, json.dumps(arguments, sort_keys=True, separators=(",", ":"))


def _audit_read_only(rows: list[dict], target_sha: str,
                     target_repository: str = "xbroute/hayool-os") -> None:
    inspected: set[tuple[str, str]] = set()
    declared: set[tuple[str, str]] = set()
    observed: set[tuple[str, str]] = set()
    pending: dict[str, tuple[str, str]] = {}
    completed_ids: set[str] = set()
    for row in rows:
        payload = row.get("payload") or {}
        if row.get("type") == "response_item":
            if payload.get("type") == "custom_tool_call":
                require(payload.get("name") == "exec",
                        "reviewer used a direct non-read-only tool")
                signature = _review_invocation(payload.get("input"))
                require(signature not in declared and len(declared) < 100,
                        "duplicate reviewer read declaration or read limit exceeded")
                declared.add(signature)
            if payload.get("type") == "function_call":
                raise VerificationError("reviewer used a collaboration action")
        if row.get("type") != "event_msg" or payload.get("type") not in {
                "item_started", "item_completed"}:
            continue
        item = payload.get("item")
        if isinstance(item, str):
            require(len(item) <= MAX_SESSION_LINE, "reviewer event too large")
            item = ast.literal_eval(item)
        require(isinstance(item, dict), "reviewer event is not structured")
        kind = item.get("type")
        if kind in {"Reasoning", "AgentMessage", "UserMessage", "ContextCompaction"}:
            continue
        require(kind == "McpToolCall",
                "reviewer activity includes host execution, mutation or delegated work")
        event_id = item.get("id")
        require(isinstance(event_id, str) and bool(event_id), "reviewer tool ID missing")
        completed = payload["type"] == "item_completed"
        proof = _review_api_call(item, completed)
        signature = (item["actionName"], json.dumps(
            item["arguments"], sort_keys=True, separators=(",", ":")))
        require(signature in declared, "reviewer API event has no matching read declaration")
        if completed:
            require(event_id not in completed_ids and signature not in observed,
                    "duplicate reviewer API completion")
            require(event_id not in pending or pending[event_id] == signature,
                    "reviewer API start/completion identity mismatch")
            completed_ids.add(event_id)
            observed.add(signature)
            pending.pop(event_id, None)
            inspected.update(proof)
        else:
            require(event_id not in pending and event_id not in completed_ids,
                    "duplicate reviewer API start")
            pending[event_id] = signature
    require(not pending and declared == observed,
            "reviewer declared read did not complete or API evidence is unmatched")
    require((target_repository, target_sha) in inspected,
            "reviewer did not successfully inspect the exact candidate repository/SHA")


def verify_reviewers(run: dict, evidence_root: Path, writer_thread_id: str) -> None:
    reviewers = run["reviewers"]
    require(isinstance(reviewers, list) and len(reviewers) == 2,
            "two independent reviewers required")
    seen_ids: set[str] = set()
    seen_sessions: set[str] = set()
    seen_scopes: set[str] = set()
    for review in reviewers:
        required = {"id", "session_id", "agent_path", "response_item_id",
                    "report_path", "report_sha256", "target_sha", "verdict",
                    "effective_provider", "effective_model", "scope", "findings"}
        require(isinstance(review, dict) and set(review) == required and
                isinstance(review["id"], str) and review["id"].startswith("/root/review_") and
                review["agent_path"] == review["id"] and
                review["target_sha"] == run["head_sha"] and review["verdict"] == "PASS" and
                review["scope"] in {"security_ci_trust_boundary",
                                     "engineering_autonomy_architecture"} and
                isinstance(review["response_item_id"], str) and
                review["response_item_id"].startswith("msg_") and
                review["id"] not in seen_ids and review["session_id"] not in seen_sessions and
                review["scope"] not in seen_scopes,
                "reviewer identity, exact SHA, or verdict invalid")
        seen_ids.add(review["id"])
        seen_sessions.add(review["session_id"])
        seen_scopes.add(review["scope"])
        rows = _session_rows(review["session_id"], 32 * 1024 * 1024)
        _audit_read_only(rows, run["head_sha"], run["repository"])
        meta = (rows[0].get("payload") or {}) if rows[0].get("type") == "session_meta" else {}
        require(meta.get("id") == review["session_id"] and
                meta.get("agent_path") == review["agent_path"] and
                meta.get("parent_thread_id") == writer_thread_id and
                meta.get("model_provider") == review["effective_provider"],
                "reviewer session identity/provider mismatch")
        model: object = None
        selected: list[tuple[object, object]] = []
        finals: list[object] = []
        for row in rows:
            payload = row.get("payload") or {}
            if row.get("type") == "turn_context":
                model = payload.get("model")
            if row.get("type") == "response_item" and payload.get("type") == "message" and \
                    payload.get("role") == "assistant" and payload.get("phase") == "final_answer":
                finals.append(payload.get("id"))
            if row.get("type") == "response_item" and payload.get("id") == review["response_item_id"]:
                parts = payload.get("content")
                require(payload.get("phase") == "final_answer" and
                        payload.get("role") == "assistant" and
                        isinstance(parts, list) and len(parts) == 1 and
                        parts[0].get("type") == "output_text", "selected review is not final text")
                selected.append((model, parts[0].get("text")))
        require(len(selected) == 1 and finals and finals[-1] == review["response_item_id"] and
                selected[0][0] == review["effective_model"] and
                isinstance(selected[0][1], str),
                "reviewer final answer/model missing or superseded")
        raw = _report(evidence_root, review["report_path"], review["report_sha256"])
        require(raw == selected[0][1].encode("utf-8"),
                "review report is not exact final-answer bytes")
        report = _json_bytes(raw)
        require(isinstance(report, dict) and report.get("target_sha") == run["head_sha"] and
                report.get("read_only") is True and report.get("verdict") == "PASS" and
                report.get("scope") == review["scope"] and
                report.get("effective_provider") == review["effective_provider"] and
                report.get("effective_model") == review["effective_model"] and
                report.get("findings") == review["findings"],
                "review report content mismatch")
        findings = report.get("findings")
        require(isinstance(findings, list), "review findings missing")
        finding_ids: set[str] = set()
        for finding in findings:
            require(isinstance(finding, dict) and
                    set(finding) <= {"id", "severity", "status", "target_sha",
                                    "summary", "closure_evidence"} and
                    isinstance(finding.get("id"), str) and bool(finding["id"].strip()) and
                    finding["id"] not in finding_ids and
                    isinstance(finding.get("summary"), str) and
                    bool(finding["summary"].strip()) and
                    finding.get("target_sha") == run["head_sha"] and
                    finding.get("severity") in {"P0", "P1", "P2", "P3"} and
                    finding.get("status") in {"OPEN", "CLOSED"} and
                    finding["severity"] not in {"P0", "P1"},
                    "exact-SHA review has a P0/P1 finding; repair and re-review required")
            finding_ids.add(finding["id"])
    require(seen_scopes == {"security_ci_trust_boundary",
                            "engineering_autonomy_architecture"},
            "Security and Engineering review scopes incomplete")


def verify_limits_and_kill(api: ReadOnlyGitHub, config: dict, run: dict,
                           writer_elapsed: float) -> int:
    policy = _json_bytes(POLICY_FILE.read_bytes())
    require(isinstance(policy, dict) and policy.get("schema_version") == 1 and
            set(policy) == {"schema_version", "limits", "kill_switch"},
            "trusted ENG-RUN policy invalid")
    limits = run["limits"]
    cap = policy["limits"]
    require(isinstance(limits, dict) and set(limits) ==
            {"repair_iterations", "elapsed_seconds", "new_paid_cost_authorized_usd",
             "external_cost_cap_usd"} and
            type(limits["repair_iterations"]) is int and
            0 <= limits["repair_iterations"] <= cap["max_repair_iterations"] and
            type(limits["elapsed_seconds"]) in {int, float} and
            0 <= limits["elapsed_seconds"] <= cap["max_elapsed_seconds"] and
            limits["new_paid_cost_authorized_usd"] == 0 and
            limits["external_cost_cap_usd"] == cap["external_cost_cap_usd"] == 0,
            "repair/time/cost cap exceeded")
    require(abs(limits["elapsed_seconds"] - writer_elapsed) < 0.01,
            "declared elapsed time differs from recorded writer turn")
    commits = api.listing(f"repos/{config['target_repo']}/pulls/"
                          f"{run['pr_number']}/commits?per_page=100")
    require(1 <= len(commits) < 100 and
            all(isinstance(row, dict) and
                gate.SHA.fullmatch(str(row.get("sha", ""))) is not None
                for row in commits) and
            commits[-1]["sha"] == run["head_sha"] and
            limits["repair_iterations"] == len(commits) - 1,
            "repair count is not bound to current PR commit history")
    timeline = api.listing(f"repos/{config['target_repo']}/issues/"
                           f"{run['pr_number']}/timeline?per_page=100")
    require(len(timeline) < 100 and all(isinstance(row, dict) for row in timeline) and
            not any(row.get("event") == "head_ref_force_pushed" for row in timeline),
            "PR repair history includes a force push or incomplete timeline")
    require(run["kill_switch"] == policy["kill_switch"] and
            run["kill_switch"].get("engaged") is False and
            all(run["kill_switch"].get(key) is False for key in
                ("autonomous_writes_enabled", "merge_enabled", "deploy_enabled",
                 "external_calls_enabled")),
            "kill switch engaged or shadow authority mismatch")
    return len(commits) - 1


def evaluate(run: dict, api: ReadOnlyGitHub, evidence_root: Path,
             config: dict | None = None) -> dict:
    config = gate.load_config() if config is None else config
    validate_manifest(run, config)
    verify_local_policy(run["trusted_policy_sha"])
    app_id = verify_environment(api, config)
    verify_protection(api, config, app_id)
    verify_actions_policy(api, config)
    target, report, artifact = publisher.verify_publishable(
        api, api, config, run["pr_number"], run["head_sha"],
        run["trusted_repository"], run["trusted_policy_sha"],
        run["trusted_run_id"], run["trusted_run_attempt"])
    require(report["decision"] == "PASS" and
            report["base_sha"] == run["base_sha"] and
            target["base_sha"] == run["base_sha"] and
            artifact["artifact_id"] == run["artifact_id"] and
            artifact["artifact_digest"] == run["artifact_digest"] and
            artifact["report_sha256"] == run["report_sha256"],
            "independent artifact is not exact-SHA PASS evidence")
    require(isinstance(report.get("checks"), dict) and
            set(report["checks"]) == gate.HARD_CHECKS and
            all(value == "PASS" for value in report["checks"].values()) and
            isinstance(report.get("errors"), dict) and
            set(report["errors"]) == gate.HARD_CHECKS and
            all(value == [] for value in report["errors"].values()),
            "independent hard-check set failed or incomplete")
    trusted_run = api.get(f"repos/{config['trusted_repo']}/actions/runs/"
                          f"{run['trusted_run_id']}")
    require(trusted_run.get("id") == run["trusted_run_id"] and
            trusted_run.get("run_attempt") == run["trusted_run_attempt"] and
            trusted_run.get("head_sha") == run["trusted_policy_sha"] and
            trusted_run.get("status") == "completed" and
            trusted_run.get("conclusion") == "success",
            "trusted workflow run did not complete successfully on policy SHA")
    jobs = api.get(f"repos/{config['trusted_repo']}/actions/runs/"
                   f"{run['trusted_run_id']}/attempts/{run['trusted_run_attempt']}/jobs?per_page=100")
    rows = jobs.get("jobs")
    require(isinstance(rows, list) and jobs.get("total_count") == len(rows) == 2 and
            {row.get("name") for row in rows if isinstance(row, dict)} ==
            {"evaluate", "publish"} and
            all(isinstance(row, dict) and row.get("conclusion") == "success" and
                row.get("head_sha") == run["trusted_policy_sha"] for row in rows),
            "trusted job listing incomplete")
    published = [row for row in rows if isinstance(row, dict) and
                 row.get("name") == "publish"]
    require(len(published) == 1 and published[0].get("conclusion") == "success",
            "trusted App publisher job did not succeed")
    variable = api.get(f"repos/{config['trusted_repo']}/environments/"
                       f"{ENVIRONMENT}/variables/HAYOOL_GATE_APP_ID")
    require(_time(variable.get("updated_at")) <= _time(published[0].get("started_at")),
            "App ID environment variable changed after publisher began")
    verify_publisher_secret_metadata(api, config, published[0].get("started_at"))
    check_ids = {
        "head": verify_app_check(api, config, target["head_sha"], app_id,
                                 run["trusted_run_id"], run["trusted_run_attempt"],
                                 artifact["report_sha256"]),
        "merge": verify_app_check(api, config, target["merge_sha"], app_id,
                                  run["trusted_run_id"], run["trusted_run_attempt"],
                                  artifact["report_sha256"]),
    }
    publisher_artifact = verify_publisher_artifact(
        api, config, run, target, artifact, app_id, check_ids)
    writer_session, writer_thread_id, writer_elapsed = verify_writer(api, config, run)
    verify_reviewers(run, evidence_root, writer_thread_id)
    verify_migration_review(api, config, run["pr_number"], run["base_sha"])
    observed_repairs = verify_limits_and_kill(api, config, run, writer_elapsed)
    negative = verify_negative_evidence(api, config, run, app_id)
    require(gate.verify_live_target(api, config, run["pr_number"], run["head_sha"]) ==
            target and gate.verify_trusted_run(
                api, config, run["trusted_repository"], run["trusted_policy_sha"],
                run["trusted_run_id"], run["trusted_run_attempt"])["trusted_policy_sha"] ==
            run["trusted_policy_sha"], "PR, merge, or trusted policy moved")
    verify_protection(api, config, app_id)
    return {"schema_version": 4, "decision": "PASS", "repository": config["target_repo"],
            "pr_number": run["pr_number"], "base_sha": target["base_sha"],
            "head_sha": target["head_sha"], "merge_sha": target["merge_sha"],
            "tree_sha": target["head_tree_sha"], "trusted_policy_sha":
            run["trusted_policy_sha"], "trusted_run_id": run["trusted_run_id"],
            "trusted_run_attempt": run["trusted_run_attempt"],
            "artifact": artifact, "github_app_id": app_id, "check_ids": check_ids,
            "publisher_artifact": publisher_artifact,
            "hard_checks": report["checks"], "reviewer_sessions":
            [row["session_id"] for row in run["reviewers"]],
            "writer_session": writer_session, "limits": run["limits"],
            "observed_current_branch_commit_repairs": observed_repairs,
            "actual_external_spend_usd": None,
            "external_spend_measurement": "unavailable; zero new paid calls authorized",
            "session_evidence_assurance": "unsigned host-local consistency",
            "negative_evidence": negative,
            "kill_switch": run["kill_switch"], "errors": []}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = args.manifest.read_bytes()
        run = _json_bytes(raw)
        require(isinstance(run, dict), "ENG-RUN manifest is not an object")
        result = evaluate(run, ReadOnlyGitHub(os.environ.get("GH_READ_TOKEN", "")),
                          args.evidence_root)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (VerificationError, gate.GateError, OSError, ValueError, TypeError,
            KeyError, IndexError, SyntaxError, AttributeError, UnicodeError,
            subprocess.SubprocessError,
            urllib.error.URLError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        print(json.dumps({"schema_version": 4, "decision": "FAIL",
                          "errors": [str(error)]}, sort_keys=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
