"""Required live negative-evidence contracts, using offline API fixtures."""

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

import engrun_v4 as v4
import gate
from test_engrun_v4 import FakeAPI, config, manifest, zip_member


class NegativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.run, self.c = manifest(), config()
        self.negative = self.run["negative_evidence"]
        self.routes, self.archives, self.targets, self.reports, self.artifacts = {}, {}, {}, {}, {}
        repo, source = self.c["target_repo"], self.c["trusted_repo"]
        self.app_id = 9876
        for name, merge in (("hard_failure", "b" * 40), ("workflow_spoof", "c" * 40)):
            ref = self.negative[name]
            number, run_id = ref["pr_number"], ref["trusted_run_id"]
            target = {"repository": repo, "repository_id": self.c["target_repo_id"],
                      "pr_number": number, "base_sha": self.run["base_sha"],
                      "head_sha": ref["head_sha"], "head_tree_sha": "d" * 40,
                      "merge_sha": merge, "merge_tree_sha": "d" * 40,
                      "merge_parents": [self.run["base_sha"], ref["head_sha"]]}
            self.targets[number] = target
            checks = {key: "PASS" for key in gate.HARD_CHECKS}
            errors = {key: [] for key in gate.HARD_CHECKS}
            checks["security"] = "FAIL"
            errors["security"] = ["M0 shadow kill switch policy changed"]
            suites = {"decision": "PASS", "expected_unit_tests": 36,
                      "expected_regression_tests": 24, "exit_code": 0,
                      "image": gate.TEST_IMAGE, "network": "none", "read_only": True,
                      "timeout_seconds": 90, "memory_bytes": 536870912, "pids": 64}
            baseline = {"schema_version": 2, "policy_source": "independent-trusted-repo",
                        "protected_main_policy_sha": self.c["policy_source_sha"],
                        "protected_main_baseline_sha256": self.c["baseline_sha256"],
                        "pr_number": number, "base_sha": self.run["base_sha"],
                        "target_sha": ref["head_sha"], "workspace_clean": True,
                        "migration_rule": "frozen_paths", "checks": checks,
                        "errors": errors, "isolated_suites": suites}
            self.reports[number] = {"decision": "FAIL", "baseline": baseline,
                "baseline_returncode": 1, "checks": checks, "errors": errors,
                "isolated_suites": suites, "changed_file_sha256": {
                    self.negative["workflow_spoof"]["workflow_path"]: hashlib.sha256(
                        (v4.ROOT / "fixtures/workflow-spoof.yml").read_bytes()).hexdigest()}}
            if name == "hard_failure":
                self.reports[number]["changed_file_sha256"][v4.AI_PASS_FIXTURE_PATH] = (
                    hashlib.sha256(v4.AI_PASS_FIXTURE).hexdigest())
            artifact = {key: ref[key] for key in
                        ("artifact_id", "artifact_digest", "report_sha256")}
            self.artifacts[number] = artifact
            check_ids = {"merge": run_id + 10, "head": run_id + 11}
            result = {"schema_version": 1, "decision": "FAIL", "target": target,
                      "source": {"trusted_repo": source,
                          "trusted_policy_sha": self.run["trusted_policy_sha"],
                          "trusted_run_id": run_id, "trusted_run_attempt": 1,
                          "github_app_id": self.app_id}, "artifact": artifact,
                      "checks": [{"sha": target[key + "_sha"],
                          "check_run_id": check_ids[key], "app_id": self.app_id,
                          "conclusion": "failure"} for key in ("merge", "head")]}
            zipped = zip_member("publisher-result.json", json.dumps(result).encode())
            self.archives[run_id + 1] = zipped
            self.routes[f"repos/{source}/actions/runs/{run_id}/artifacts?per_page=100"] = {
                "total_count": 1, "artifacts": [{"id": run_id + 1,
                    "name": f"independent-publisher-{run_id}-1", "expired": False,
                    "size_in_bytes": len(zipped),
                    "digest": "sha256:" + hashlib.sha256(zipped).hexdigest(),
                    "workflow_run": {"id": run_id, "repository_id": self.c["trusted_repo_id"],
                        "head_repository_id": self.c["trusted_repo_id"],
                        "head_branch": "main", "head_sha": self.run["trusted_policy_sha"]}}]}
            self.routes[f"repos/{source}/actions/runs/{run_id}"] = {
                "id": run_id, "run_attempt": 1, "head_sha": self.run["trusted_policy_sha"],
                "status": "completed", "conclusion": "failure"}
            self.routes[f"repos/{source}/actions/runs/{run_id}/attempts/1/jobs?per_page=100"] = {
                "total_count": 2, "jobs": [{"name": value, "status": "completed",
                    "conclusion": "failure", "head_sha": self.run["trusted_policy_sha"]}
                    for value in ("evaluate", "publish")]}
            self.routes[f"repos/{repo}/pulls/{number}"] = {"number": number, "state": "open",
                "head": {"sha": ref["head_sha"], "ref": f"codex/attack-{number}"},
                "base": {"sha": self.run["base_sha"]}, "mergeable_state": "blocked"}
            for key in ("head", "merge"):
                sha = target[key + "_sha"]
                check = {"id": check_ids[key], "name": self.c["check_name"],
                    "head_sha": sha, "app": {"id": self.app_id}, "status": "completed",
                    "conclusion": "failure", "external_id": f"{run_id}:1:{ref['report_sha256']}",
                    "details_url": f"https://github.com/{source}/actions/runs/{run_id}",
                    "completed_at": "2026-10-21T00:04:00Z"}
                route = (f"repos/{repo}/commits/{sha}/check-runs?"
                         f"check_name={self.c['check_name']}&filter=latest&per_page=100")
                self.routes[route] = {"total_count": 1, "check_runs": [check]}
                self.routes[f"repos/{repo}/check-runs/{check_ids[key]}"] = check
        ref = self.negative["workflow_spoof"]
        self.blocked_route = f"repos/{repo}/actions/runs/{ref['blocked_run_id']}"
        self.routes[self.blocked_route] = {"id": ref["blocked_run_id"], "run_attempt": 1,
            "repository": {"id": self.c["target_repo_id"]},
            "head_repository": {"id": self.c["target_repo_id"]},
            "head_sha": ref["head_sha"], "head_branch": f"codex/attack-{ref['pr_number']}",
            "path": ref["workflow_path"], "event": "pull_request", "status": "completed",
            "conclusion": "startup_failure", "pull_requests": [{"number": ref["pr_number"],
                "head": {"sha": ref["head_sha"], "repo": {"id": self.c["target_repo_id"]}},
                "base": {"sha": self.run["base_sha"], "repo": {"id": self.c["target_repo_id"]}}}]}
        self.routes[self.blocked_route + "/attempts/1/jobs?per_page=100"] = {
            "total_count": 0, "jobs": []}
        self.status_route = (f"repos/{repo}/statuses/"
                             f"{self.negative['hard_failure']['head_sha']}?per_page=100")
        self.routes[self.status_route] = [{"id": 400, "state": "success",
            "context": self.c["check_name"], "creator": {"login": "xbroute", "type": "User"},
            "created_at": "2026-10-21T00:05:00Z"}]

    def verify(self):
        def publishable(_source, _target, _config, number, *_args):
            return self.targets[number], self.reports[number], self.artifacts[number]
        with patch.object(v4.publisher, "verify_publishable", side_effect=publishable), \
             patch.object(v4.gate, "verify_live_target",
                          side_effect=lambda _api, _c, number, _sha: self.targets[number]):
            return v4.verify_negative_evidence(
                FakeAPI(self.routes, self.archives), self.c, self.run, self.app_id)

    def test_complete_negative_evidence_passes_and_binds_ids(self):
        result = self.verify()
        self.assertEqual(result["hard_failure"]["decision"], "FAIL")
        self.assertEqual(result["workflow_spoof"]["executed_jobs"], 0)
        self.assertEqual(result["wrong_source"]["status_id"], 400)

    def test_missing_attacks_fail_manifest_validation(self):
        del self.run["negative_evidence"]
        with self.assertRaisesRegex(v4.VerificationError, "fields mismatch"):
            v4.validate_manifest(self.run, self.c)

    def test_relabeled_pass_or_infrastructure_failure_is_rejected(self):
        report = self.reports[3]
        for key, value in (("decision", "PASS"), ("baseline_returncode", 0)):
            original = report[key]
            report[key] = value
            with self.subTest(key=key), self.assertRaises(v4.VerificationError):
                self.verify()
            report[key] = original
        report["baseline"]["isolated_suites"]["decision"] = "FAIL"
        with self.assertRaisesRegex(v4.VerificationError, "isolated suites"):
            self.verify()

    def test_kill_marker_and_exact_base_are_required(self):
        self.reports[3]["errors"]["security"] = ["unrelated failure"]
        with self.assertRaisesRegex(v4.VerificationError, "kill-switch"):
            self.verify()
        self.reports[3]["errors"]["security"] = ["M0 shadow kill switch policy changed"]
        self.targets[3]["base_sha"] = "0" * 40
        with self.assertRaisesRegex(v4.VerificationError, "exact-base"):
            self.verify()

    def test_missing_or_mutated_synthetic_ai_pass_fixture_is_rejected(self):
        hashes = self.reports[3]["changed_file_sha256"]
        del hashes[v4.AI_PASS_FIXTURE_PATH]
        with self.assertRaisesRegex(v4.VerificationError, "kill-switch"):
            self.verify()
        hashes[v4.AI_PASS_FIXTURE_PATH] = "0" * 64
        with self.assertRaisesRegex(v4.VerificationError, "kill-switch"):
            self.verify()

    def test_wrong_app_source_or_artifact_digest_is_rejected(self):
        ref = self.negative["hard_failure"]
        route = next(key for key in self.routes if
                     f"commits/{ref['head_sha']}/check-runs" in key)
        self.routes[route]["check_runs"][0]["app"]["id"] = 15368
        with self.assertRaisesRegex(v4.VerificationError, "App check"):
            self.verify()
        self.routes[route]["check_runs"][0]["app"]["id"] = self.app_id
        self.archives[101] += b"tampered"
        with self.assertRaisesRegex(v4.VerificationError, "ZIP digest"):
            self.verify()

    def test_spoof_wrong_pr_event_or_executed_job_is_rejected(self):
        blocked = self.routes[self.blocked_route]
        for key, value in (("event", "workflow_dispatch"), ("head_sha", "0" * 40)):
            original = blocked[key]
            blocked[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(v4.VerificationError, "policy-blocked"):
                self.verify()
            blocked[key] = original
        blocked["pull_requests"][0]["number"] = 9
        with self.assertRaisesRegex(v4.VerificationError, "policy-blocked"):
            self.verify()
        blocked["pull_requests"][0]["number"] = 6
        self.routes[self.blocked_route + "/attempts/1/jobs?per_page=100"] = {
            "total_count": 1, "jobs": [{"name": "forged-success"}]}
        with self.assertRaisesRegex(v4.VerificationError, "executed a job"):
            self.verify()

    def test_unreviewed_or_mutated_spoof_workflow_is_rejected(self):
        path = self.negative["workflow_spoof"]["workflow_path"]
        self.reports[6]["changed_file_sha256"][path] = "0" * 64
        with self.assertRaisesRegex(v4.VerificationError, "reviewed required-check attack"):
            self.verify()

    def test_wrong_source_state_context_creator_or_unblocked_pr_is_rejected(self):
        status = self.routes[self.status_route][0]
        for key, value in (("state", "pending"), ("context", "another-check"),
                           ("creator", {"login": "someone-else", "type": "User"}),
                           ("creator", {"login": "xbroute", "type": "Bot"})):
            original = copy.deepcopy(status[key])
            status[key] = value
            with self.subTest(key=key, value=value), self.assertRaisesRegex(
                    v4.VerificationError, "wrong-source"):
                self.verify()
            status[key] = original
        self.routes[f"repos/{self.c['target_repo']}/pulls/3"]["mergeable_state"] = "clean"
        with self.assertRaisesRegex(v4.VerificationError, "not blocked"):
            self.verify()

    def test_negative_jobs_or_required_app_success_cannot_be_relabelled(self):
        ref = self.negative["hard_failure"]
        route = f"repos/{self.c['trusted_repo']}/actions/runs/{ref['trusted_run_id']}"
        self.routes[route]["conclusion"] = "success"
        with self.assertRaisesRegex(v4.VerificationError, "failure publication"):
            self.verify()
        self.routes[route]["conclusion"] = "failure"
        route = next(key for key in self.routes if
                     f"commits/{ref['head_sha']}/check-runs" in key)
        self.routes[route]["check_runs"][0]["conclusion"] = "success"
        with self.assertRaisesRegex(v4.VerificationError, "App check"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
