"""Offline fail-closed regressions; no network, secrets or GitHub mutation."""

from __future__ import annotations

import copy
import io
import json
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import gate
import publisher

BASE = "9af7ac8a4b8cd7ea96c27a2eb5f4c69c92d33659"
HEAD = "da7c6f91a074d58dde35d7c032bae94230dea128"
MERGE = "a5a5bd125247ef5ed7536c143ddfa162a2b31a85"
TREE = "866a419bb232638a32b53dc30ae5fef967bfb020"
TRUST = "a" * 40
REPO = "xbroute/hayool-os"
SOURCE = "xbroute/independent-gate-example"


def config() -> dict:
    value = gate.load_config()
    value.update(trusted_repo=SOURCE, trusted_repo_id=2468, github_app_id=9876)
    return value


def target_routes() -> dict:
    return {
        f"repos/{REPO}": {"id": 1389639283, "full_name": REPO},
        f"repos/{REPO}/pulls/7": {
            "number": 7, "state": "open", "mergeable": True,
            "merge_commit_sha": MERGE,
            "head": {"sha": HEAD, "ref": "codex/m0-trust-migration",
                     "repo": {"id": 1389639283}},
            "base": {"sha": BASE, "ref": "main",
                     "repo": {"id": 1389639283}},
        },
        f"repos/{REPO}/git/ref/heads/main": {"object": {"sha": BASE}},
        f"repos/{REPO}/git/commits/{HEAD}": {"sha": HEAD,
                                                 "tree": {"sha": TREE}},
        f"repos/{REPO}/compare/{BASE}...{HEAD}": {
            "status": "ahead", "merge_base_commit": {"sha": BASE}},
        f"repos/{REPO}/git/commits/{MERGE}": {
            "sha": MERGE, "parents": [{"sha": BASE}, {"sha": HEAD}],
            "tree": {"sha": TREE}},
    }


def source_routes() -> dict:
    return {
        f"repos/{SOURCE}": {"id": 2468, "full_name": SOURCE},
        f"repos/{SOURCE}/git/ref/heads/main": {"object": {"sha": TRUST}},
        f"repos/{SOURCE}/actions/runs/99": {
            "id": 99, "run_attempt": 1, "event": "workflow_dispatch",
            "repository": {"id": 2468}, "head_repository": {"id": 2468},
            "head_branch": "main", "head_sha": TRUST,
            "path": ".github/workflows/hayool-independent-gate.yml@refs/heads/main",
            "workflow_id": 123,
        },
        f"repos/{SOURCE}/actions/workflows/hayool-independent-gate.yml": {
            "id": 123, "path": ".github/workflows/hayool-independent-gate.yml",
            "state": "active"},
    }


class FakeApi:
    def __init__(self, routes: dict):
        self.routes = routes
        self.paths = []

    def get(self, path: str) -> dict:
        self.paths.append(path)
        if path not in self.routes:
            raise AssertionError(f"unavailable scoped API path: {path}")
        return copy.deepcopy(self.routes[path])


def baseline() -> dict:
    c = config()
    checks = {name: "PASS" for name in gate.HARD_CHECKS}
    errors = {name: [] for name in gate.HARD_CHECKS}
    return {"schema_version": 2, "policy_source": "independent-trusted-repo",
            "protected_main_policy_sha": BASE,
            "protected_main_baseline_sha256": c["baseline_sha256"],
            "pr_number": 7, "base_sha": BASE,
            "target_sha": HEAD, "workspace_clean": True,
            "migration_rule": "exact_reviewed_PR7_bytes",
            "isolated_suites": {"decision": "PASS", "expected_unit_tests": 36,
                                "expected_regression_tests": 24,
                                "exit_code": 0, "image": gate.TEST_IMAGE,
                                "network": "none", "read_only": True,
                                "timeout_seconds": 90,
                                "memory_bytes": 536870912, "pids": 64},
            "checks": checks, "errors": errors}


class TargetBindingTests(unittest.TestCase):
    def setUp(self):
        self.routes = target_routes()
        self.c = config()

    def verify(self):
        return gate.verify_live_target(FakeApi(self.routes), self.c, 7, HEAD)

    def test_live_real_shaped_merge_tree_and_parents(self):
        result = self.verify()
        self.assertEqual(result["merge_sha"], MERGE)
        self.assertEqual(result["merge_tree_sha"], TREE)

    def test_wrong_repository_id_fails(self):
        self.routes[f"repos/{REPO}"]["id"] = 999
        with self.assertRaisesRegex(gate.GateError, "repository identity"):
            self.verify()

    def test_wrong_pr_head_fails(self):
        self.routes[f"repos/{REPO}/pulls/7"]["head"]["sha"] = "b" * 40
        with self.assertRaisesRegex(gate.GateError, "head/base"):
            self.verify()

    def test_stale_base_fails(self):
        self.routes[f"repos/{REPO}/git/ref/heads/main"]["object"]["sha"] = "b" * 40
        with self.assertRaisesRegex(gate.GateError, "current main"):
            self.verify()

    def test_test_merge_wrong_parent_fails(self):
        self.routes[f"repos/{REPO}/git/commits/{MERGE}"]["parents"][1]["sha"] = "b" * 40
        with self.assertRaisesRegex(gate.GateError, "parents/tree"):
            self.verify()

    def test_test_merge_changed_tree_fails(self):
        self.routes[f"repos/{REPO}/git/commits/{MERGE}"]["tree"]["sha"] = "b" * 40
        with self.assertRaisesRegex(gate.GateError, "parents/tree"):
            self.verify()


class TrustedSourceTests(unittest.TestCase):
    def setUp(self):
        self.routes = source_routes()
        self.c = config()

    def test_workflow_filename_endpoint_and_main_sha(self):
        api = FakeApi(self.routes)
        result = gate.verify_trusted_run(api, self.c, SOURCE, TRUST, 99, 1)
        self.assertEqual(result["trusted_policy_sha"], TRUST)
        self.assertIn(f"repos/{SOURCE}/actions/workflows/hayool-independent-gate.yml", api.paths)

    def test_candidate_owned_workflow_spoof_fails(self):
        self.routes[f"repos/{SOURCE}/actions/runs/99"]["path"] = ".github/workflows/evil.yml@refs/heads/main"
        with self.assertRaisesRegex(gate.GateError, "workflow source"):
            gate.verify_trusted_run(FakeApi(self.routes), self.c, SOURCE, TRUST, 99, 1)

    def test_alternate_ref_workflow_dispatch_fails(self):
        self.routes[f"repos/{SOURCE}/actions/runs/99"]["head_branch"] = "attacker"
        with self.assertRaisesRegex(gate.GateError, "workflow source"):
            gate.verify_trusted_run(FakeApi(self.routes), self.c, SOURCE, TRUST, 99, 1)

    def test_wrong_trusted_repository_fails(self):
        with self.assertRaisesRegex(gate.GateError, "not configured"):
            gate.verify_trusted_run(FakeApi(self.routes), self.c, REPO, TRUST, 99, 1)


class DeterministicGateTests(unittest.TestCase):
    def setUp(self):
        self.c = config()
        self.t = gate.verify_live_target(FakeApi(target_routes()), self.c, 7, HEAD)
        self.changes = self.c["migration"]["changed_paths"][:]

    def test_new_independent_policy_accepts_all_fresh_hard_checks(self):
        result = gate.verify_report(baseline(), 0, self.t, self.changes, self.c)
        self.assertEqual(result["decision"], "PASS")
        self.assertEqual(result["migration_policy_rule"], "exact_reviewed_PR7_bytes")
        self.assertEqual(set(result["checks"].values()), {"PASS"})

    def test_added_executable_path_rejected(self):
        with self.assertRaisesRegex(gate.GateError, "integrity rule mismatch"):
            gate.verify_report(baseline(), 0, self.t,
                               self.changes + ["A\tbootstrap/poison.py"], self.c)

    def test_changed_frozen_path_reason_rejected(self):
        value = baseline()
        value["checks"]["test_integrity"] = "FAIL"
        value["errors"]["test_integrity"].append("migration file-byte hashes differ")
        with self.assertRaisesRegex(gate.GateError, "independent hard check failed: test_integrity"):
            gate.verify_report(value, 1, self.t, self.changes, self.c)

    def test_legacy_failed_baseline_cannot_be_relabelled_pass(self):
        value = baseline()
        value["schema_version"] = 1
        value["policy_source"] = "independent-pinned-main"
        value["checks"]["test_integrity"] = "FAIL"
        value["ai_votes"] = [{"decision": "PASS"}] * 5
        with self.assertRaisesRegex(gate.GateError, "independent policy/head"):
            gate.verify_report(value, 1, self.t, self.changes, self.c)

    def test_failed_unit_cannot_be_overridden_by_ai_pass(self):
        value = baseline()
        value["checks"]["unit"] = "FAIL"
        value["errors"]["unit"] = ["test failed"]
        value["ai_votes"] = [{"decision": "PASS"}, {"decision": "PASS"}]
        with self.assertRaisesRegex(gate.GateError, "independent hard check failed: unit"):
            gate.verify_report(value, 1, self.t, self.changes, self.c)

    def test_failed_security_or_kill_switch_cannot_be_overridden(self):
        value = baseline()
        value["checks"]["security"] = "FAIL"
        value["errors"]["security"] = ["M0 shadow kill switch policy changed"]
        value["ai_votes"] = [{"decision": "PASS"}]
        with self.assertRaisesRegex(gate.GateError, "independent hard check failed: security"):
            gate.verify_report(value, 1, self.t, self.changes, self.c)

    def test_candidate_report_lies_about_process_exit(self):
        with self.assertRaisesRegex(gate.GateError, "policy process failed"):
            gate.verify_report(baseline(), 1, self.t, self.changes, self.c)

    def test_forged_suite_success_without_36_units_fails(self):
        value = baseline()
        value["isolated_suites"]["expected_unit_tests"] = 0
        with self.assertRaisesRegex(gate.GateError, "isolated reviewed suites"):
            gate.verify_report(value, 0, self.t, self.changes, self.c)

    def test_migration_file_byte_mutation_fails_before_policy_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "bootstrap").mkdir()
            (root / "bootstrap/engrun.py").write_text("malicious mutation")
            c = config()
            c["migration"]["changed_paths"] = ["M\tbootstrap/engrun.py"]
            c["migration"]["reviewed_file_sha256"] = {
                "bootstrap/engrun.py": hashlib.sha256(b"reviewed code").hexdigest()}
            def fake_git(_root, *args):
                if args == ("rev-parse", "HEAD"):
                    return HEAD
                if args == ("status", "--porcelain"):
                    return ""
                if args[0] == "merge-base":
                    return BASE
                if args[0] == "diff":
                    return "M\tbootstrap/engrun.py"
                raise AssertionError(args)
            with patch.object(gate, "git", side_effect=fake_git):
                with self.assertRaisesRegex(gate.GateError, "paths or bytes changed"):
                    gate.verify_checkout(root, self.t, c)


class PublisherBoundaryTests(unittest.TestCase):
    def test_app_id_only_from_protected_environment_variable(self):
        c = gate.load_config()
        self.assertIsNone(c["github_app_id"])
        self.assertEqual(publisher.configured_app(c, "9876")["github_app_id"], 9876)
        for raw in ("", "0", "abc", "9876;echo unsafe"):
            with self.subTest(raw=raw), self.assertRaises(publisher.gate.GateError):
                publisher.configured_app(c, raw)

    def test_wrong_pinned_app_id_fails(self):
        with self.assertRaisesRegex(publisher.gate.GateError, "differs"):
            publisher.configured_app(config(), "9999")

    def test_overprivileged_app_installation_fails(self):
        class Overprivileged:
            def __init__(self, token):
                self.token = token
            def get(self, path):
                return {"id": 55, "app_id": 9876, "suspended_at": None,
                        "permissions": {"checks": "write", "contents": "read",
                                        "pull_requests": "read",
                                        "administration": "write"}}
        with patch.object(publisher, "app_jwt", return_value="test-jwt"):
            with self.assertRaisesRegex(publisher.gate.GateError, "least-privilege"):
                publisher.installation_token(config(), "opaque", transport=Overprivileged)

    def test_unconfigured_app_cannot_mint_token(self):
        c = gate.load_config()
        with self.assertRaisesRegex(publisher.gate.GateError, "not configured"):
            publisher.installation_token(c, "not-a-real-key")

    def test_wrong_app_identity_in_readback_fails(self):
        c = config()
        t = gate.verify_live_target(FakeApi(target_routes()), c, 7, HEAD)
        report = {"decision": "PASS"}
        art = {"artifact_id": 1, "report_sha256": "a" * 64}
        class App(FakeApi):
            def __init__(self):
                super().__init__(target_routes())
            def post(self, path, body):
                return {"id": 1234}
            def get(self, path):
                if path.endswith("check-runs/1234"):
                    return {"id": 1234, "app": {"id": 9999}}
                return super().get(path)
        with patch.object(publisher, "verify_publishable", return_value=(t, report, art)), \
             patch.dict("os.environ", {"GITHUB_REF": "refs/heads/main"}):
            with self.assertRaisesRegex(publisher.gate.GateError, "readback identity"):
                publisher.publish(FakeApi({}), App(), c, 7, HEAD, SOURCE, TRUST, 99, 1)

    def test_alternate_ref_has_no_app_key_in_workflow(self):
        body = (Path(__file__).resolve().parents[1] / ".github/workflows/hayool-independent-gate.yml").read_text()
        publish = body.split("  publish:", 1)[1]
        evaluate = body.split("  evaluate:", 1)[1].split("  publish:", 1)[0]
        self.assertIn("if: always() && github.ref == 'refs/heads/main'", publish)
        self.assertIn("environment: hayool-trusted-publisher", publish)
        self.assertIn("vars.HAYOOL_GATE_APP_ID", publish)
        self.assertIn("secrets.HAYOOL_GATE_APP_PRIVATE_KEY", publish)
        self.assertNotIn("vars.HAYOOL_GATE_APP_ID", evaluate)
        self.assertNotIn("secrets.HAYOOL_GATE_APP_PRIVATE_KEY", evaluate)

    def test_publisher_uses_separate_source_and_target_api_scopes(self):
        c = config()
        source = FakeApi(source_routes())
        target = FakeApi(target_routes())
        # A source token scoped only to the separate gate repo cannot read the
        # target; the target App token cannot read the gate repo. This is the
        # explicit boundary used by verify_publishable().
        gate.verify_trusted_run(source, c, SOURCE, TRUST, 99, 1)
        gate.verify_live_target(target, c, 7, HEAD)
        self.assertTrue(all(path.startswith(f"repos/{SOURCE}/") or path == f"repos/{SOURCE}" for path in source.paths))
        self.assertTrue(all(path.startswith(f"repos/{REPO}/") or path == f"repos/{REPO}" for path in target.paths))

    def test_wrong_trusted_artifact_digest_fails_before_status(self):
        c = config()
        class ArtifactApi:
            def get(self, path):
                return {"total_count": 1, "artifacts": [{
                    "id": 111, "name": f"independent-gate-99-1-{HEAD}",
                    "expired": False, "size_in_bytes": 16,
                    "digest": "sha256:" + "0" * 64,
                    "workflow_run": {"id": 99, "head_sha": TRUST,
                                     "head_branch": "main", "repository_id": 2468,
                                     "head_repository_id": 2468}}]}
            def artifact(self, path):
                return b"not the recorded ZIP digest"
        with self.assertRaisesRegex(publisher.gate.GateError, "digest mismatch"):
            publisher.verified_artifact(ArtifactApi(), c, 99, 1, HEAD,
                                        {"trusted_policy_sha": TRUST})


if __name__ == "__main__":
    unittest.main()
