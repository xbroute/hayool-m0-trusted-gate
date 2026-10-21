"""Offline ENG-RUN v4 source-binding and human-evidence regressions."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import engrun_v4 as v4
import gate

BASE = "9af7ac8a4b8cd7ea96c27a2eb5f4c69c92d33659"
HEAD = "da7c6f91a074d58dde35d7c032bae94230dea128"
SHADOW_HEAD = "e" * 40
SHADOW_BASE = "f" * 40
MERGE = "a5a5bd125247ef5ed7536c143ddfa162a2b31a85"
TREE = "866a419bb232638a32b53dc30ae5fef967bfb020"
POLICY = "a" * 40
WRITER_SESSION = "11111111-1111-4111-8111-111111111111"
THREAD_ID = "01a0df04-112c-7ff0-9349-7f36bb1e2b29"


def config() -> dict:
    return gate.load_config()


def target() -> dict:
    c = config()
    return {"repository": c["target_repo"], "repository_id": c["target_repo_id"],
            "pr_number": 8, "base_sha": SHADOW_BASE, "head_sha": SHADOW_HEAD,
            "head_tree_sha": TREE, "merge_sha": MERGE,
            "merge_parents": [SHADOW_BASE, SHADOW_HEAD], "merge_tree_sha": TREE}


def manifest() -> dict:
    c = config()
    def negative(number: int, run_id: int) -> dict:
        return {"pr_number": number, "head_sha": str(number) * 40,
                "trusted_run_id": run_id, "trusted_run_attempt": 1,
                "artifact_id": run_id, "artifact_digest": "sha256:" + "b" * 64,
                "report_sha256": "c" * 64}
    return {"schema_version": 4, "mode": "shadow", "ci_mode": "independent_app",
            "repository": c["target_repo"], "pr_number": 8, "base_sha": SHADOW_BASE,
            "head_sha": SHADOW_HEAD, "trusted_repository": c["trusted_repo"],
            "trusted_policy_sha": POLICY, "trusted_run_id": 99,
            "trusted_run_attempt": 1, "artifact_id": 50,
            "artifact_digest": "sha256:" + "b" * 64, "report_sha256": "c" * 64,
            "writer": {"github_login": "xbroute"}, "reviewers": [],
            "limits": {}, "kill_switch": {}, "negative_evidence": {
                "hard_failure": negative(3, 100),
                "workflow_spoof": {**negative(6, 200), "blocked_run_id": 300,
                    "blocked_run_attempt": 1,
                    "workflow_path": ".github/workflows/spoof-trusted-status.yml"},
                "wrong_source": {"status_id": 400, "creator_login": "xbroute"}}}


def zip_member(name: str, raw: bytes) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as bundle:
        bundle.writestr(name, raw)
    return stream.getvalue()


def connector_event(action: str = "fetch_commit", arguments: dict | None = None,
                    event_id: str = "mcp-read-1", completed: bool = True) -> dict:
    arguments = ({"commit_sha": HEAD, "repo_full_name": "xbroute/hayool-os"}
                 if arguments is None else arguments)
    content = {"commit": {"sha": arguments.get("commit_sha", HEAD),
               "repository_full_name": arguments.get("repo_full_name", "xbroute/hayool-os"),
               "url": "https://api.github.com/repos/" +
                      arguments.get("repo_full_name", "xbroute/hayool-os") +
                      "/commits/" + arguments.get("commit_sha", HEAD)}}
    if action == "fetch_file":
        content = {"content": "reviewed source", "encoding": "utf-8", "sha": "b" * 40,
                   "display_url": "https://github.com/" + arguments["repository_full_name"] +
                                  "/blob/" + arguments["ref"] + "/" + arguments["path"]}
    item = {"type": "McpToolCall", "id": event_id, "server": "codex_apps",
            "tool": "github." + action, "arguments": arguments,
            "appName": "GitHub", "actionName": action, "readOnlyHint": True,
            "status": "completed" if completed else "in_progress",
            "result": {"isError": False, "structuredContent": content}}
    return {"type": "event_msg", "payload": {
        "type": "item_completed" if completed else "item_started", "item": item}}


def connector_invocation(action: str = "fetch_commit", arguments: dict | None = None) -> dict:
    arguments = ({"commit_sha": HEAD, "repo_full_name": "xbroute/hayool-os"}
                 if arguments is None else arguments)
    return {"type": "response_item", "payload": {"type": "custom_tool_call",
        "name": "exec", "input": "text(await tools.mcp__codex_apps__github_" +
        action + "(" + json.dumps(arguments, sort_keys=True) + "));"}}


def declaration_for(row: dict) -> dict:
    item = row["payload"]["item"]
    return connector_invocation(item["actionName"], item["arguments"])


class FakeAPI:
    def __init__(self, routes: dict, archives: dict[int, bytes] | None = None):
        self.routes = routes
        self.archives = archives or {}

    def get(self, path: str) -> dict:
        if path not in self.routes:
            raise AssertionError(f"unmocked GitHub GET: {path}")
        return copy.deepcopy(self.routes[path])

    def listing(self, path: str) -> list:
        return self.get(path)

    def artifact(self, path: str) -> bytes:
        return self.archives[int(path.split("/")[-2])]


def routes(run: dict, target_value: dict, artifact: dict) -> tuple[dict, dict]:
    c = config()
    source = c["trusted_repo"]
    target_repo = c["target_repo"]
    app_id = 9876
    source_record = {"trusted_repo": source, "trusted_policy_sha": POLICY,
                     "trusted_run_id": 99, "trusted_run_attempt": 1,
                     "github_app_id": app_id}
    check_ids = {"merge": 901, "head": 902}
    publisher_result = {"schema_version": 1, "decision": "PASS",
                        "target": target_value, "source": source_record,
                        "artifact": artifact, "checks": [
                            {"sha": MERGE, "check_run_id": 901,
                             "app_id": app_id, "conclusion": "success"},
                            {"sha": SHADOW_HEAD, "check_run_id": 902,
                             "app_id": app_id, "conclusion": "success"}]}
    zipped = zip_member("publisher-result.json",
                        (json.dumps(publisher_result) + "\n").encode())
    publisher_row = {"id": 60, "name": "independent-publisher-99-1",
                     "expired": False, "size_in_bytes": len(zipped),
                     "digest": "sha256:" + hashlib.sha256(zipped).hexdigest(),
                     "workflow_run": {"id": 99, "repository_id": c["trusted_repo_id"],
                                      "head_repository_id": c["trusted_repo_id"],
                                      "head_branch": "main", "head_sha": POLICY}}
    policy_row = {"enforcement": "active",
                  "conditions": {"workflow_path": {"include": ["~ALL"], "exclude": []}},
                  "rules": [{"type": "restrict_action_events",
                             "parameters": {"allowed_events": ["pull_request_target"]}}]}
    def protection(context: str, source_id: int) -> dict:
        return {"required_status_checks": {"strict": True,
                                            "contexts": [context],
                                            "checks": [{"context": context,
                                                        "app_id": source_id}]},
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews": True,
                    "require_last_push_approval": True},
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False}}
    values = {
        f"repos/{source}/environments/{v4.ENVIRONMENT}": {
            "name": v4.ENVIRONMENT,
            "deployment_branch_policy": {"custom_branch_policies": True,
                                         "protected_branches": False}},
        f"repos/{source}/environments/{v4.ENVIRONMENT}/deployment-branch-policies?per_page=100": {
            "total_count": 1, "branch_policies": [{"name": "main"}]},
        f"repos/{source}/environments/{v4.ENVIRONMENT}/variables/HAYOOL_GATE_APP_ID": {
            "name": "HAYOOL_GATE_APP_ID", "value": str(app_id),
            "updated_at": "2026-09-28T00:00:00Z"},
        f"repos/{source}/environments/{v4.ENVIRONMENT}/secrets/HAYOOL_GATE_APP_PRIVATE_KEY": {
            "name": "HAYOOL_GATE_APP_PRIVATE_KEY",
            "created_at": "2026-09-28T00:00:00Z",
            "updated_at": "2026-09-28T00:00:00Z"},
        f"repos/{source}/branches/main/protection":
            protection("independent-gate-selftest", 15368),
        f"repos/{target_repo}/branches/main/protection":
            protection(c["check_name"], app_id),
        f"repos/{source}/actions/policies/5994": {
            **policy_row, "rules": [{"type": "restrict_action_events",
                                     "parameters": {"allowed_events":
                                                    ["pull_request_target",
                                                     "workflow_dispatch"]}}]},
        f"repos/{target_repo}/actions/policies/5892": policy_row,
        f"repos/{source}/actions/runs/99": {
            "id": 99, "run_attempt": 1, "head_sha": POLICY,
            "status": "completed", "conclusion": "success"},
        f"repos/{source}/actions/runs/99/attempts/1/jobs?per_page=100": {
            "total_count": 2, "jobs": [
                {"name": "evaluate", "conclusion": "success",
                 "head_sha": POLICY},
                {"name": "publish", "conclusion": "success", "head_sha": POLICY,
                 "started_at": "2026-09-29T00:00:00Z"}]},
        f"repos/{source}/actions/runs/99/artifacts?per_page=100": {
            "total_count": 1, "artifacts": [publisher_row]},
        f"repos/{target_repo}/pulls/7": {"number": 7, "state": "closed",
            "head": {"sha": HEAD, "repo": {"id": c["target_repo_id"]}},
            "user": {"login": "xbroute"},
            "merged_at": "2026-09-29T00:00:00Z", "merged_by": {"login": "erfanxt", "type": "User"},
            "merge_commit_sha": "3" * 40},
        f"repos/{target_repo}/git/commits/{'3' * 40}": {
            "sha": "3" * 40, "parents": [{"sha": BASE}, {"sha": HEAD}],
            "tree": {"sha": TREE}},
        f"repos/{target_repo}/git/commits/{HEAD}": {
            "sha": HEAD, "tree": {"sha": TREE}},
        f"repos/{target_repo}/compare/{'3' * 40}...{SHADOW_BASE}": {
            "merge_base_commit": {"sha": "3" * 40}, "status": "ahead"},
        f"repos/{target_repo}/pulls/7/reviews?per_page=100": [
            {"user": {"login": "erfanxt", "type": "User"}, "state": "APPROVED", "commit_id": HEAD}],
        f"repos/{target_repo}/pulls/8": {"number": 8, "created_at": "2026-09-29T00:01:00Z"},
        f"repos/{target_repo}/pulls/8/commits?per_page=100": [
            {"sha": "1" * 40}, {"sha": "2" * 40}, {"sha": SHADOW_HEAD}],
        f"repos/{target_repo}/issues/8/timeline?per_page=100": [
            {"event": "committed"}, {"event": "committed"},
            {"event": "committed"}],
    }
    for sha, check_id in ((SHADOW_HEAD, check_ids["head"]),
                          (MERGE, check_ids["merge"])):
        route = (f"repos/{target_repo}/commits/{sha}/check-runs?"
                 f"check_name={c['check_name']}&filter=latest&per_page=100")
        values[route] = {"total_count": 1, "check_runs": [{
            "id": check_id, "name": c["check_name"], "app": {"id": app_id},
            "head_sha": sha, "status": "completed", "conclusion": "success",
            "external_id": "99:1:" + artifact["report_sha256"],
            "details_url": f"https://github.com/{source}/actions/runs/99"}]}
    return values, {60: zipped}


class SourceBindingTests(unittest.TestCase):
    def test_isolated_cli_starts(self):
        result = subprocess.run([sys.executable, "-I", "-B", str(v4.ROOT / "engrun_v4.py"),
                                 "--help"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Read-only ENG-RUN v4", result.stdout)

    def setUp(self):
        self.run = manifest()
        self.c = config()
        self.target = target()
        self.artifact = {"artifact_id": 50, "artifact_digest": self.run["artifact_digest"],
                         "report_sha256": self.run["report_sha256"]}
        self.report = {"decision": "PASS", "base_sha": SHADOW_BASE,
                       "checks": {name: "PASS" for name in gate.HARD_CHECKS},
                       "errors": {name: [] for name in gate.HARD_CHECKS}}
        self.routes, self.archives = routes(self.run, self.target, self.artifact)

    def evaluate(self):
        api = FakeAPI(self.routes, self.archives)
        with patch.object(v4, "verify_local_policy"), \
             patch.object(v4.publisher, "verify_publishable",
                          return_value=(self.target, self.report, self.artifact)), \
             patch.object(v4, "verify_writer", return_value=(WRITER_SESSION, THREAD_ID, 1500.0)), \
             patch.object(v4, "verify_reviewers"), \
             patch.object(v4, "verify_limits_and_kill", return_value=2), \
             patch.object(v4, "verify_negative_evidence", return_value={"verified": True}), \
             patch.object(v4.gate, "verify_live_target", return_value=self.target), \
             patch.object(v4.gate, "verify_trusted_run",
                          return_value={"trusted_policy_sha": POLICY}):
            return v4.evaluate(self.run, api, Path("/tmp"), self.c)

    def test_exact_source_and_two_artifacts_pass(self):
        result = self.evaluate()
        self.assertEqual(result["decision"], "PASS")
        self.assertEqual(result["check_ids"], {"head": 902, "merge": 901})
        self.assertEqual(result["publisher_artifact"]["artifact_id"], 60)

    def test_wrong_app_check_fails(self):
        route = next(key for key in self.routes if f"commits/{SHADOW_HEAD}/check-runs" in key)
        self.routes[route]["check_runs"][0]["app"]["id"] = 15368
        with self.assertRaisesRegex(v4.VerificationError, "App check"):
            self.evaluate()

    def test_wrong_required_source_fails(self):
        route = f"repos/{self.c['target_repo']}/branches/main/protection"
        self.routes[route]["required_status_checks"]["checks"][0]["app_id"] = 15368
        with self.assertRaisesRegex(v4.VerificationError, "protection mismatch"):
            self.evaluate()

    def test_extra_legacy_required_status_fails(self):
        route = f"repos/{self.c['target_repo']}/branches/main/protection"
        self.routes[route]["required_status_checks"]["checks"].append({
            "context": "engineering-trusted-gate-status", "app_id": 15368})
        with self.assertRaisesRegex(v4.VerificationError, "protection mismatch"):
            self.evaluate()

    def test_hidden_legacy_context_fails_even_if_app_check_list_is_exact(self):
        route = f"repos/{self.c['target_repo']}/branches/main/protection"
        self.routes[route]["required_status_checks"]["contexts"].append(
            "engineering-trusted-gate-status")
        with self.assertRaisesRegex(v4.VerificationError, "protection mismatch"):
            self.evaluate()

    def test_publisher_artifact_wrong_check_id_fails(self):
        self.archives[60] = zip_member("publisher-result.json", json.dumps({
            "schema_version": 1, "decision": "PASS", "checks": []}).encode())
        self.routes[f"repos/{self.c['trusted_repo']}/actions/runs/99/artifacts?per_page=100"][
            "artifacts"][0]["digest"] = "sha256:" + hashlib.sha256(self.archives[60]).hexdigest()
        with self.assertRaisesRegex(v4.VerificationError, "publisher result conflicts"):
            self.evaluate()

    def test_publisher_artifact_digest_fails(self):
        self.archives[60] = self.archives[60] + b"tampered"
        with self.assertRaisesRegex(v4.VerificationError, "publisher ZIP digest"):
            self.evaluate()

    def test_missing_publisher_artifact_fails(self):
        route = f"repos/{self.c['trusted_repo']}/actions/runs/99/artifacts?per_page=100"
        self.routes[route] = {"total_count": 0, "artifacts": []}
        with self.assertRaisesRegex(v4.VerificationError, "publisher artifact absent"):
            self.evaluate()

    def test_hard_check_failure_fails(self):
        self.report["decision"] = "FAIL"
        self.report["checks"]["security"] = "FAIL"
        with self.assertRaisesRegex(v4.VerificationError, "PASS evidence"):
            self.evaluate()

    def test_success_artifact_from_failed_run_cannot_pass(self):
        route = f"repos/{self.c['trusted_repo']}/actions/runs/99"
        self.routes[route]["conclusion"] = "failure"
        with self.assertRaisesRegex(v4.VerificationError, "workflow run"):
            self.evaluate()

    def test_old_v3_and_legacy_mode_fail(self):
        self.run["schema_version"] = 3
        with self.assertRaisesRegex(v4.VerificationError, "unsupported ENG-RUN mode"):
            self.evaluate()

    def test_migration_pr_cannot_impersonate_shadow_run(self):
        self.run["pr_number"] = self.c["migration"]["pr_number"]
        with self.assertRaisesRegex(v4.VerificationError, "migration PR cannot"):
            self.evaluate()

    def test_shadow_pr_uses_merged_pr7_approval_not_shadow_approval(self):
        route = f"repos/{self.c['target_repo']}/pulls/7"
        v4.verify_migration_review(FakeAPI(self.routes), self.c, 8, SHADOW_BASE)
        self.routes[f"repos/{self.c['target_repo']}/git/commits/{'3' * 40}"][
            "tree"]["sha"] = "4" * 40
        with self.assertRaisesRegex(v4.VerificationError, "parents/tree"):
            v4.verify_migration_review(FakeAPI(self.routes), self.c, 8, SHADOW_BASE)
        self.routes[f"repos/{self.c['target_repo']}/git/commits/{'3' * 40}"][
            "tree"]["sha"] = TREE
        self.routes[route]["merged_at"] = None
        with self.assertRaisesRegex(v4.VerificationError, "not independently merged"):
            v4.verify_migration_review(FakeAPI(self.routes), self.c, 8, SHADOW_BASE)
        self.run["schema_version"] = 4
        self.run["ci_mode"] = "protected_main_pr_target"
        with self.assertRaisesRegex(v4.VerificationError, "unsupported ENG-RUN mode"):
            self.evaluate()

    def test_bot_cannot_supply_human_approval_or_merge(self):
        route = f"repos/{self.c['target_repo']}/pulls/7"
        self.routes[route]["merged_by"]["type"] = "Bot"
        with self.assertRaisesRegex(v4.VerificationError, "not independently merged"):
            v4.verify_migration_review(FakeAPI(self.routes), self.c, 8, SHADOW_BASE)
        self.routes[route]["merged_by"]["type"] = "User"
        self.routes[route + "/reviews?per_page=100"][0]["user"]["type"] = "Bot"
        with self.assertRaisesRegex(v4.VerificationError, "approval absent"):
            v4.verify_migration_review(FakeAPI(self.routes), self.c, 8, SHADOW_BASE)

    def test_preexisting_shadow_pr_is_rejected(self):
        self.routes[f"repos/{self.c['target_repo']}/pulls/8"]["created_at"] = "2026-09-28T00:00:00Z"
        with self.assertRaisesRegex(v4.VerificationError, "not created after"):
            v4.verify_migration_review(FakeAPI(self.routes), self.c, 8, SHADOW_BASE)


class ReviewerSessionTests(unittest.TestCase):
    def test_exact_latest_review_bytes_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            session_root = root / "sessions"
            evidence = root / "evidence"
            evidence.mkdir()
            day = session_root / "2026" / "09" / "29"
            day.mkdir(parents=True)
            run = {"head_sha": HEAD, "repository": "xbroute/hayool-os", "reviewers": []}
            for index in (1, 2):
                sid = f"{index:08d}-1111-4111-8111-111111111111"
                agent = f"/root/review_{index}"
                final_id = f"msg_{index}"
                report = {"target_sha": HEAD, "read_only": True,
                          "scope": ("security_ci_trust_boundary" if index == 1 else
                                    "engineering_autonomy_architecture"),
                          "verdict": "PASS", "effective_provider": "openai",
                          "effective_model": "gpt-6-sol", "findings": []}
                raw = json.dumps(report, sort_keys=True).encode()
                (evidence / f"review-{index}.json").write_bytes(raw)
                review = {"id": agent, "session_id": sid, "agent_path": agent,
                          "scope": report["scope"],
                          "response_item_id": final_id,
                          "report_path": f"review-{index}.json",
                          "report_sha256": hashlib.sha256(raw).hexdigest(),
                          "target_sha": HEAD, "verdict": "PASS",
                          "effective_provider": "openai",
                          "effective_model": "gpt-6-sol", "findings": []}
                run["reviewers"].append(review)
                rows = [
                    {"type": "session_meta", "payload": {"id": sid,
                        "agent_path": agent, "parent_thread_id": THREAD_ID,
                        "model_provider": "openai"}},
                    {"type": "turn_context", "payload": {"model": "gpt-6-sol"}},
                    connector_invocation(),
                    connector_event(),
                    {"type": "response_item", "payload": {"id": final_id,
                        "type": "message", "role": "assistant",
                        "phase": "final_answer", "content": [
                            {"type": "output_text", "text": raw.decode()}]}}]
                (day / f"rollout-2026-09-29-{sid}.jsonl").write_text(
                    "\n".join(json.dumps(row) for row in rows) + "\n")
            with patch.object(v4, "SESSION_ROOT", session_root):
                v4.verify_reviewers(run, evidence, THREAD_ID)
                run["reviewers"][1]["scope"] = run["reviewers"][0]["scope"]
                with self.assertRaisesRegex(v4.VerificationError, "reviewer identity"):
                    v4.verify_reviewers(run, evidence, THREAD_ID)
                run["reviewers"][1]["scope"] = "engineering_autonomy_architecture"
                run["reviewers"][0]["report_sha256"] = "0" * 64
                with self.assertRaisesRegex(v4.VerificationError, "digest mismatch"):
                    v4.verify_reviewers(run, evidence, THREAD_ID)
                run["reviewers"][0]["report_sha256"] = hashlib.sha256(
                    (evidence / "review-1.json").read_bytes()).hexdigest()
                path = next(day.glob("*"))
                with path.open("a") as stream:
                    stream.write(json.dumps({"type": "response_item", "payload": {
                        "id": "msg_later", "type": "message", "role": "assistant",
                        "phase": "final_answer", "content": [{"type": "output_text",
                        "text": "FAIL"}]}}) + "\n")
                with self.assertRaisesRegex(v4.VerificationError, "superseded"):
                    v4.verify_reviewers(run, evidence, THREAD_ID)


class ReviewerConductTests(unittest.TestCase):
    def command(self, value: str, started: bool = False) -> dict:
        return {"type": "event_msg", "payload": {
            "type": "item_started" if started else "item_completed",
            "item": {"type": "CommandExecution",
                     "command": ["/bin/bash", "-lc", value],
                     "status": "completed", "exit_code": 0,
                     "cwd": "file://" + v4.ROOT.as_posix()}}}

    def test_structured_connector_reads_are_accepted(self):
        commit = connector_event()
        begin = copy.deepcopy(commit)
        begin["payload"]["type"] = "item_started"
        begin["payload"]["item"]["status"] = "in_progress"
        file = connector_event("fetch_file", {"repository_full_name": "xbroute/hayool-os",
            "ref": HEAD, "path": "bootstrap/engrun.py", "start_line": 1, "end_line": 20}, "file-read")
        info = connector_event("get_pr_info", {"repository_full_name": "xbroute/hayool-os",
                                                "pr_number": 8}, "pr-read")
        patch = connector_event("fetch_pr_patch", {"repo_full_name": "xbroute/hayool-os",
                                                   "pr_number": 8}, "patch-read")
        v4._audit_read_only([declaration_for(commit), begin, commit,
                             declaration_for(file), file, declaration_for(info), info,
                             declaration_for(patch), patch], HEAD)

    def test_literal_host_reads_no_longer_establish_review(self):
        for command in ("git rev-parse HEAD",
                        f"git diff --no-ext-diff --no-textconv {BASE} {HEAD}",
                        f"git show --no-ext-diff --no-textconv {HEAD}:bootstrap/engrun.py",
                        "gh api repos/xbroute/hayool-os/pulls/7"):
            with self.subTest(command=command), self.assertRaises(v4.VerificationError):
                v4._audit_read_only([connector_invocation(), connector_event(), self.command(command)], HEAD)

    def test_shell_mutation_and_external_diff_are_rejected(self):
        for command in ("touch marker", "sed -n 1p -i engrun_v4.py",
                        "sed -n 1p --in-place engrun_v4.py", "sed -n 1p -e 1wmarker",
                        "cat foo/../../secret", "cat ./../../secret",
                        "cat symlink-to-secret", f"git show --no-ext-diff {HEAD}",
                        f"git log -p {HEAD}",
                        f"git show --no-ext-diff --no-textconv --textconv {HEAD}",
                        f"git diff --no-ext-diff --no-textconv {BASE} {HEAD} -- ../outside",
                        f"git show --no-ext-diff --no-textconv {HEAD}:../outside",
                        f"git diff --no-ext-diff --no-textconv {BASE} {HEAD}; touch marker",
                        "gh api repos/xbroute/hayool-os/pulls/7 -X POST",
                        "gh api repos/xbroute/hayool-os/../private-repo",
                        "gh api repos/xbroute/hayool-os/%2e%2e/private-repo", "gh api graphql"):
            for started in (False, True):
                with self.subTest(command=command, started=started), self.assertRaises(v4.VerificationError):
                    v4._audit_read_only([connector_invocation(), connector_event(), self.command(command, started)], HEAD)

    def test_patch_tool_and_delegation_are_rejected(self):
        for row in (
            {"type": "response_item", "payload": {"type": "custom_tool_call",
                "name": "apply_patch", "input": "mutation"}},
            {"type": "event_msg", "payload": {"type": "item_completed",
                "item": {"type": "FileChange"}}},
            {"type": "event_msg", "payload": {"type": "item_started",
                "item": {"type": "SubAgentActivity"}}},
            {"type": "response_item", "payload": {"type": "function_call",
                "name": "send_message", "arguments": "{}"}},
        ):
            with self.subTest(row=row), self.assertRaises(v4.VerificationError):
                v4._audit_read_only([connector_invocation(), connector_event(), row], HEAD)

    def test_failed_or_wrong_head_is_not_read_only_review_evidence(self):
        row = connector_event()
        row["payload"]["item"]["status"] = "failed"
        with self.assertRaises(v4.VerificationError):
            v4._audit_read_only([declaration_for(row), row], HEAD)
        row["payload"]["item"]["status"] = "completed"
        with self.assertRaisesRegex(v4.VerificationError, "exact candidate repository/SHA"):
            v4._audit_read_only([declaration_for(row), row], "a" * 40)

    def test_wrong_tool_hint_source_result_or_arguments_fail_closed(self):
        changes = [
            ("readOnlyHint", False), ("tool", "github.create_file"),
            ("server", "untrusted"), ("appName", "Other"),
            ("actionName", "create_file"),
            ("arguments", {"commit_sha": HEAD, "repo_full_name": "xbroute/private"}),
            ("arguments", {"commit_sha": "main", "repo_full_name": "xbroute/hayool-os"}),
            ("arguments", {"commit_sha": HEAD, "repo_full_name": "xbroute/hayool-os", "token": "forbidden"}),
            ("result", {"isError": True, "structuredContent": {}}),
            ("result", {"isError": False, "structuredContent": {"commit": {"sha": "a" * 40}}}),
        ]
        for key, value in changes:
            row = connector_event(); row["payload"]["item"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(v4.VerificationError):
                v4._audit_read_only([declaration_for(row), row], HEAD)

    def test_pending_write_or_duplicate_tool_event_cannot_hide(self):
        pending = connector_event(event_id="pending", completed=False)
        with self.assertRaises(v4.VerificationError):
            v4._audit_read_only([connector_invocation(), connector_event(), declaration_for(pending), pending], HEAD)
        write = connector_event("create_file", {}, "bad-write", completed=False)
        with self.assertRaises(v4.VerificationError):
            v4._audit_read_only([connector_invocation(), connector_event(), write], HEAD)
        with self.assertRaises(v4.VerificationError):
            v4._audit_read_only([connector_invocation(), connector_event(), connector_event()], HEAD)

    def test_file_read_cannot_replace_whole_exact_commit_inspection(self):
        args = {"repository_full_name": "xbroute/hayool-os", "ref": HEAD,
                "path": "bootstrap/engrun.py"}
        row = connector_event("fetch_file", args)
        with self.assertRaisesRegex(v4.VerificationError, "exact candidate repository/SHA"):
            v4._audit_read_only([declaration_for(row), row], HEAD)
        for key, value in (("ref", "main"), ("path", "../secret"),
                           ("path", "symlink/../../secret"), ("encoding", "base64"),
                           ("start_line", 0), ("end_line", -1)):
            bad = dict(args); bad[key] = value
            event = connector_event("fetch_file", bad, "bad-file")
            with self.subTest(key=key, value=value), self.assertRaises(v4.VerificationError):
                v4._audit_read_only([connector_invocation(), connector_event(), declaration_for(event), event], HEAD)
        row["payload"]["item"]["result"]["structuredContent"]["display_url"] = "https://example.com/secret"
        with self.assertRaises(v4.VerificationError):
            v4._audit_read_only([connector_invocation(), connector_event(), row], HEAD)

    def test_real_tool_record_trailing_newline_is_accepted(self):
        row = connector_invocation()
        row["payload"]["input"] += "\n"
        v4._audit_read_only([row, connector_event()], HEAD)

    def test_arbitrary_or_extra_orchestration_and_duplicate_json_are_rejected(self):
        good = connector_invocation()["payload"]["input"]
        sources = (
            "await tools.write_stdin({\"session_id\":1,\"chars\":\"mutation\"}); " + good,
            "await tools.exec_command({\"cmd\":\"mutation\"}); " + good,
            good + " await tools.write_stdin({});",
            "const r=await tools.mcp__codex_apps__github_fetch_commit({}); text(r);",
            good + good,
            "text(await tools.mcp__codex_apps__github_fetch_commit({\"commit_sha\":\"" + HEAD +
                "\",\"commit_sha\":\"" + HEAD + "\",\"repo_full_name\":\"xbroute/hayool-os\"}));",
        )
        for source in sources:
            row = connector_invocation(); row["payload"]["input"] = source
            with self.subTest(source=source), self.assertRaises((v4.VerificationError, ValueError)):
                v4._audit_read_only([row, connector_event()], HEAD)

    def test_declarations_must_match_actual_api_completion(self):
        declared = connector_invocation()
        actual = connector_event()
        changed = connector_event(arguments={"commit_sha": "a" * 40,
                                             "repo_full_name": "xbroute/hayool-os"})
        for rows in ([actual], [declared], [declared, changed],
                     [declared, declared, actual], [declared, actual, actual]):
            with self.subTest(rows=rows), self.assertRaises(v4.VerificationError):
                v4._audit_read_only(rows, HEAD)
        begin = connector_event(completed=False)
        file = connector_event("fetch_file", {"repository_full_name": "xbroute/hayool-os",
              "ref": HEAD, "path": "bootstrap/engrun.py"})
        with self.assertRaisesRegex(v4.VerificationError, "identity mismatch"):
            v4._audit_read_only([declared, declaration_for(file), begin, file], HEAD)


class PolicyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.run = manifest()
        self.c = config()
        self.routes, self.archives = routes(self.run, target(), {
            "artifact_id": 50, "artifact_digest": self.run["artifact_digest"],
            "report_sha256": self.run["report_sha256"]})
        self.run["limits"] = {"repair_iterations": 2, "elapsed_seconds": 1500.0,
                              "new_paid_cost_authorized_usd": 0,
                              "external_cost_cap_usd": 0}
        self.run["kill_switch"] = json.loads(v4.POLICY_FILE.read_text())[
            "kill_switch"]

    def verify(self):
        return v4.verify_limits_and_kill(FakeAPI(self.routes), self.c,
                                         self.run, 1500.0)

    def test_current_branch_history_and_recorded_time_bound_limits(self):
        self.assertEqual(self.verify(), 2)
        self.run["limits"]["elapsed_seconds"] = 1
        with self.assertRaisesRegex(v4.VerificationError, "recorded writer turn"):
            self.verify()

    def test_force_push_history_fails_even_if_current_branch_has_one_commit(self):
        route = f"repos/{self.c['target_repo']}/issues/8/timeline?per_page=100"
        self.routes[route].append({"event": "head_ref_force_pushed"})
        with self.assertRaisesRegex(v4.VerificationError, "force push"):
            self.verify()

    def test_self_reported_repair_count_cannot_understate_commits(self):
        self.run["limits"]["repair_iterations"] = 0
        with self.assertRaisesRegex(v4.VerificationError, "current PR commit"):
            self.verify()

    def test_protected_secret_metadata_must_predate_publisher_job(self):
        route = (f"repos/{self.c['trusted_repo']}/environments/"
                 f"{v4.ENVIRONMENT}/secrets/HAYOOL_GATE_APP_PRIVATE_KEY")
        api = FakeAPI(self.routes)
        v4.verify_publisher_secret_metadata(api, self.c,
                                            "2026-09-29T00:00:00Z")
        self.routes[route]["updated_at"] = "2026-09-30T00:00:00Z"
        with self.assertRaisesRegex(v4.VerificationError, "App key metadata"):
            v4.verify_publisher_secret_metadata(FakeAPI(self.routes), self.c,
                                                "2026-09-29T00:00:00Z")


class WriterSessionTests(unittest.TestCase):
    def test_actual_root_session_shape_binds_turn_commit_sha_and_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            checkout = root / "checkout"
            checkout.mkdir()
            session_root = root / "sessions"
            day = session_root / "2026" / "09" / "29"
            day.mkdir(parents=True)
            sid = "11111111-1111-4111-8111-111111111111"
            commit_id = "exec-22222222-2222-4222-8222-222222222222"
            sha_id = "exec-33333333-3333-4333-8333-333333333333"
            turn_id = "44444444-4444-4444-8444-444444444444"
            branch = "codex/m0-trust-migration"
            writer = {"id": "/root", "session_id": sid, "branch": branch,
                "github_login": "xbroute", "checkout": str(checkout),
                "effective_provider": "openai", "effective_model": "gpt-6-sol",
                "lease_issued_at": "2026-09-29T10:00:00Z",
                "lease_expires_at": "2026-09-29T11:00:00Z",
                "commit_execution_id": commit_id, "sha_execution_id": sha_id,
                "commit_at": "2026-09-29T10:10:00Z",
                "sha_observed_at": "2026-09-29T10:10:10Z"}
            api = FakeAPI({
                "repos/xbroute/hayool-os/pulls/7": {
                    "user": {"login": "xbroute"},
                    "head": {"ref": branch, "sha": HEAD}},
                f"repos/xbroute/hayool-os/commits/{HEAD}": {
                    "sha": HEAD, "author": {"login": "xbroute"},
                    "committer": {"login": "xbroute"}}})
            def event(at: str, event_id: str, command: str, stdout: str) -> dict:
                return {"timestamp": at, "type": "event_msg", "payload": {
                    "type": "item_completed", "turn_id": turn_id,
                    "item": {"type": "CommandExecution", "id": event_id,
                             "command": ["/bin/bash", "-lc", command],
                             "status": "completed", "exit_code": 0,
                             "cwd": "file://" + checkout.as_posix(),
                             "stdout": stdout}}}
            rows = [
                {"type": "session_meta", "payload": {"id": sid,
                    "agent_path": None, "parent_thread_id": None,
                    "model_provider": "openai"}},
                {"timestamp": "2026-09-29T10:00:00Z", "type": "event_msg",
                 "payload": {"type": "task_started", "turn_id": turn_id}},
                {"type": "turn_context", "payload": {"model": "gpt-6-sol"}},
                event("2026-09-29T10:10:00Z", commit_id,
                      "git -c core.abbrev=40 commit -F /tmp/commit",
                      f"[{branch} {HEAD}] exact commit\n"),
                event("2026-09-29T10:10:10Z", sha_id,
                      "git rev-parse HEAD", HEAD + "\n"),
            ]
            path = day / f"rollout-2026-09-29-{sid}.jsonl"
            def write():
                path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            with patch.object(v4, "SESSION_ROOT", session_root):
                write()
                self.assertEqual(v4.verify_writer(api, config(),
                                  {"writer": writer, "head_sha": HEAD,
                                   "pr_number": 7}), (sid, sid, 610.0))
                rows[0]["payload"]["parent_thread_id"] = THREAD_ID
                write()
                self.assertEqual(v4.verify_writer(api, config(),
                                  {"writer": writer, "head_sha": HEAD,
                                   "pr_number": 7})[1], THREAD_ID)
                writer["lease_issued_at"] = "2026-09-29T10:00:01Z"
                with self.assertRaisesRegex(v4.VerificationError, "recorded turn"):
                    v4.verify_writer(api, config(), {"writer": writer,
                        "head_sha": HEAD, "pr_number": 7})


if __name__ == "__main__":
    unittest.main()
