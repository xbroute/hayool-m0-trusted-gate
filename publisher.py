"""Minimal GitHub App check publisher; never clones or executes candidate code.

The App PEM is supplied only as a protected environment secret in this job.
It is never stored in the repository, output artifact, logs, or AI context.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

_spec = importlib.util.spec_from_file_location("trusted_gate_module", Path(__file__).resolve().with_name("gate.py"))
assert _spec is not None and _spec.loader is not None
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

MAX_RESPONSE = 2_000_000
MAX_ZIP = 2_000_000
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


class Http:
    def __init__(self, token: str) -> None:
        gate.need(bool(token), "GitHub API token missing")
        self.token = token

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        gate.need(path.startswith(("repos/", "app/", "installation/")) and
                  not any(part in {"", ".", ".."} for part in path.split("/")),
                  "invalid GitHub API path")
        data = None if body is None else json.dumps(body, sort_keys=True).encode()
        headers = {"Accept": "application/vnd.github+json",
                   "Authorization": "Bearer " + self.token,
                   "User-Agent": "hayool-independent-publisher/1",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request("https://api.github.com/" + path,
                                         data=data, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(MAX_RESPONSE + 1)
        gate.need(len(raw) <= MAX_RESPONSE, "GitHub response too large")
        value = json.loads(raw)
        gate.need(isinstance(value, dict), "GitHub returned non-object")
        return value

    def get(self, path: str) -> dict:
        return self.request("GET", path)

    def post(self, path: str, body: dict) -> dict:
        return self.request("POST", path, body)

    def artifact(self, path: str) -> bytes:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                return None

        gate.need(path.startswith("repos/"), "invalid artifact path")
        request = urllib.request.Request(
            "https://api.github.com/" + path,
            headers={"Accept": "application/vnd.github+json",
                     "Authorization": "Bearer " + self.token,
                     "User-Agent": "hayool-independent-publisher/1"})
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
                data = response.read(MAX_ZIP + 1)
        except urllib.error.HTTPError as error:
            if error.code not in {301, 302, 303, 307, 308}:
                raise
            location = error.headers.get("Location", "")
            parsed = urllib.parse.urlsplit(location)
            gate.need(parsed.scheme == "https" and bool(parsed.hostname),
                      "unsafe artifact redirect")
            # The API token is deliberately not forwarded to the signed CDN URL.
            with urllib.request.urlopen(
                urllib.request.Request(location, headers={"User-Agent":
                                          "hayool-independent-publisher/1"}),
                timeout=20) as response:
                data = response.read(MAX_ZIP + 1)
        gate.need(len(data) <= MAX_ZIP, "artifact ZIP too large")
        return data


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def app_jwt(app_id: int, private_key: str) -> str:
    """Sign a short-lived JWT without a third-party Python package."""
    gate.need(type(app_id) is int and app_id > 0 and bool(private_key),
              "GitHub App identity or private key missing")
    now = int(time.time())
    payload = _b64url(json.dumps({"iat": now - 60, "exp": now + 540,
                                  "iss": app_id}, separators=(",", ":")).encode())
    unsigned = (_b64url(b'{"alg":"RS256","typ":"JWT"}') + "." + payload).encode()
    fd, key_path = tempfile.mkstemp(prefix="hayool-app-key-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(private_key.encode())
        result = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_path],
                                input=unsigned, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=True, timeout=10)
        return unsigned.decode() + "." + _b64url(result.stdout)
    finally:
        os.unlink(key_path)


def configured_app(config: dict, raw_app_id: str) -> dict:
    """Read App ID only from a selected-main protected environment variable."""
    gate.need(re.fullmatch(r"[1-9][0-9]*", raw_app_id or "") is not None,
              "protected environment GitHub App ID missing or invalid")
    app_id = int(raw_app_id)
    pinned = config.get("github_app_id")
    gate.need(pinned is None or pinned == app_id,
              "protected environment App ID differs from pinned config")
    return {**config, "github_app_id": app_id}


def installation_token(config: dict, private_key: str, transport=Http) -> str:
    app_id = config.get("github_app_id")
    gate.need(type(app_id) is int and app_id > 0,
              "GitHub App ID not configured; publisher remains disabled")
    jwt = app_jwt(app_id, private_key)
    app = transport(jwt)
    repo = config["target_repo"]
    installation = app.get(f"repos/{repo}/installation")
    permissions = installation.get("permissions")
    gate.need(installation.get("app_id") == app_id and
              isinstance(permissions, dict) and
              permissions.get("checks") == "write" and
              permissions.get("contents") == "read" and
              permissions.get("pull_requests") == "read" and
              set(permissions).issubset({"checks", "metadata", "contents", "pull_requests"}) and
              installation.get("suspended_at") is None,
              "GitHub App installation/least-privilege mismatch")
    install_id = installation.get("id")
    gate.need(type(install_id) is int and install_id > 0,
              "installation ID missing")
    token_result = app.post(f"app/installations/{install_id}/access_tokens", {
        "repositories": [repo.split("/", 1)[1]],
        "permissions": {"checks": "write", "contents": "read",
                        "pull_requests": "read"},
    })
    token = token_result.get("token")
    gate.need(isinstance(token, str) and bool(token),
              "scoped installation token missing")
    scoped = transport(token)
    repositories = scoped.get("installation/repositories?per_page=100")
    rows = repositories.get("repositories")
    gate.need(repositories.get("total_count") == 1 and isinstance(rows, list) and
              len(rows) == 1 and rows[0].get("id") == config["target_repo_id"] and
              rows[0].get("full_name") == repo,
              "App token is not scoped to exact target repository")
    return token


def verified_artifact(api: Http, config: dict, run_id: int, attempt: int,
                      expected_head: str, source: dict) -> tuple[dict, dict]:
    repo = config["trusted_repo"]
    listing = api.get(f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100")
    rows = listing.get("artifacts")
    gate.need(isinstance(rows, list) and listing.get("total_count") == len(rows),
              "trusted artifact listing incomplete")
    name = f"independent-gate-{run_id}-{attempt}-{expected_head}"
    matching = [row for row in rows if isinstance(row, dict) and row.get("name") == name]
    gate.need(len(matching) == 1, "trusted artifact missing or duplicated")
    artifact = matching[0]
    origin = artifact.get("workflow_run")
    digest = artifact.get("digest")
    gate.need(type(artifact.get("id")) is int and artifact.get("expired") is False and
              isinstance(artifact.get("size_in_bytes"), int) and
              artifact["size_in_bytes"] <= MAX_ZIP and
              isinstance(origin, dict) and origin.get("id") == run_id and
              origin.get("head_sha") == source["trusted_policy_sha"] and
              origin.get("head_branch") == "main" and
              origin.get("repository_id") == config["trusted_repo_id"] and
              origin.get("head_repository_id") == config["trusted_repo_id"] and
              isinstance(digest, str) and SHA256.fullmatch(digest) is not None,
              "trusted artifact origin/digest mismatch")
    data = api.artifact(f"repos/{repo}/actions/artifacts/{artifact['id']}/zip")
    gate.need(hashlib.sha256(data).hexdigest() == digest[7:],
              "trusted artifact ZIP digest mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        gate.need(archive.namelist() == ["gate-result.json"],
                  "trusted artifact members invalid")
        raw = archive.read("gate-result.json")
    gate.need(len(raw) <= gate.MAX_REPORT, "trusted report too large")
    report = json.loads(raw)
    gate.need(isinstance(report, dict), "trusted report invalid")
    return report, {"artifact_id": artifact["id"], "artifact_digest": digest,
                    "report_sha256": hashlib.sha256(raw).hexdigest()}


def verify_publishable(source_api: Http, target_api: Http, config: dict,
                       number: int, expected_head: str,
                       trusted_repo: str, policy_sha: str, run_id: int,
                       attempt: int) -> tuple[dict, dict, dict]:
    gate.policy_digest(config)
    source = gate.verify_trusted_run(source_api, config, trusted_repo, policy_sha,
                                     run_id, attempt)
    target = gate.verify_live_target(target_api, config, number, expected_head)
    report, artifact = verified_artifact(source_api, config, run_id, attempt,
                                         expected_head, source)
    for key, value in {**source, **target}.items():
        gate.need(report.get(key) == value, "trusted report identity mismatch: " + key)
    gate.need(report.get("schema_version") == 1 and
              report.get("policy_source_sha") == config["policy_source_sha"] and
              report.get("baseline_sha256") == config["baseline_sha256"] and
              report.get("independent_policy_sha256") == config["independent_policy_sha256"] and
              isinstance(report.get("baseline"), dict) and
              isinstance(report.get("changed_paths"), list) and
              isinstance(report.get("changed_file_sha256"), dict),
              "trusted report policy or hard-check evidence missing")
    if number == config["migration"]["pr_number"]:
        gate.need(report["changed_paths"] == config["migration"]["changed_paths"] and
                  report["changed_file_sha256"] ==
                  config["migration"]["reviewed_file_sha256"],
                  "reviewed migration file bytes absent from artifact")
    jobs = source_api.get(f"repos/{trusted_repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    rows = jobs.get("jobs")
    gate.need(isinstance(rows, list) and jobs.get("total_count") == len(rows),
              "trusted job listing incomplete")
    matches = [row for row in rows if isinstance(row, dict) and row.get("name") == "evaluate"]
    gate.need(len(matches) == 1 and matches[0].get("head_sha") == policy_sha,
              "trusted evaluate job missing or wrong SHA")
    verdict = report.get("decision")
    gate.need(verdict in {"PASS", "FAIL"}, "trusted report has no final decision")
    if verdict == "PASS":
        gate.need(matches[0].get("conclusion") == "success",
                  "PASS artifact conflicts with trusted job result")
        computed = gate.verify_report(report["baseline"],
                                      report.get("baseline_returncode"),
                                      target, report["changed_paths"], config)
        gate.need(report.get("checks") == computed["checks"] and
                  report.get("errors") == computed["errors"] and
                  report.get("migration_policy_rule") ==
                  computed["migration_policy_rule"] and
                  report.get("isolated_suites") ==
                  report["baseline"].get("isolated_suites"),
                  "independent hard-check evidence conflicts with policy report")
    else:
        gate.need(matches[0].get("conclusion") == "failure",
                  "FAIL artifact conflicts with trusted job result")
    return target, report, artifact


def publish(source_api: Http, app_api: Http, config: dict, number: int,
            expected_head: str, trusted_repo: str, policy_sha: str,
            run_id: int, attempt: int) -> dict:
    gate.need(os.environ.get("GITHUB_REF") == "refs/heads/main",
              "publisher did not run on main")
    target, report, artifact = verify_publishable(source_api, app_api, config, number,
                                                   expected_head, trusted_repo,
                                                   policy_sha, run_id, attempt)
    conclusion = "success" if report["decision"] == "PASS" else "failure"
    evidence = {"schema_version": 1, "decision": report["decision"],
                "target": target, "source": {
                    "trusted_repo": trusted_repo, "trusted_policy_sha": policy_sha,
                    "trusted_run_id": run_id, "trusted_run_attempt": attempt,
                    "github_app_id": config["github_app_id"]},
                "artifact": artifact, "checks": []}
    # GitHub may require the synthetic test-merge commit. Its verified tree is
    # equal to the exact tested head tree, so publish to both SHA identities.
    for sha in (target["merge_sha"], target["head_sha"]):
        gate.need(gate.verify_live_target(app_api, config, number, expected_head) == target,
                  "PR/base/test merge changed before App check publication")
        body = {
            "name": config["check_name"], "head_sha": sha,
            "status": "completed", "conclusion": conclusion,
            "external_id": f"{run_id}:{attempt}:{artifact['report_sha256']}",
            "details_url": f"https://github.com/{trusted_repo}/actions/runs/{run_id}",
            "output": {"title": "Hayool independent engineering gate",
                       "summary": f"{report['decision']} for PR #{number}, exact head {expected_head}; "
                                  f"trusted run {run_id}/{attempt}; artifact {artifact['artifact_id']}"},
        }
        posted = app_api.post(f"repos/{config['target_repo']}/check-runs", body)
        check_id = posted.get("id")
        gate.need(type(check_id) is int and check_id > 0,
                  "GitHub did not create a check run")
        observed = app_api.get(f"repos/{config['target_repo']}/check-runs/{check_id}")
        gate.need(observed.get("id") == check_id and
                  observed.get("app", {}).get("id") == config["github_app_id"] and
                  observed.get("name") == config["check_name"] and
                  observed.get("head_sha") == sha and
                  observed.get("status") == "completed" and
                  observed.get("conclusion") == conclusion and
                  observed.get("external_id") == body["external_id"],
                  "posted App check readback identity mismatch")
        evidence["checks"].append({"sha": sha, "check_run_id": check_id,
                                   "app_id": config["github_app_id"],
                                   "conclusion": conclusion})
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        config = gate.load_config()
        gate.need(os.environ.get("GITHUB_REF") == "refs/heads/main",
                  "publisher did not run on protected main")
        config = configured_app(config, os.environ.get("HAYOOL_GATE_APP_ID", ""))
        gate.need(bool(config.get("trusted_repo")),
                  "trusted repository not configured; no check posted")
        api = Http(os.environ.get("GITHUB_TOKEN", ""))
        token = installation_token(config, os.environ.get("HAYOOL_GATE_APP_PRIVATE_KEY", ""))
        evidence = publish(api, Http(token), config, args.pr, args.expected_head,
                           os.environ.get("GITHUB_REPOSITORY", ""),
                           os.environ.get("GITHUB_SHA", ""),
                           int(os.environ.get("GITHUB_RUN_ID", "0")),
                           int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")))
        args.output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
        print(json.dumps({"decision": evidence["decision"], "checks_posted":
                          len(evidence["checks"])}))
        return 0 if evidence["decision"] == "PASS" else 1
    except (gate.GateError, OSError, ValueError, subprocess.SubprocessError,
            json.JSONDecodeError, zipfile.BadZipFile) as error:
        # Never include the key or token in this exception report.
        failure = {"schema_version": 1, "decision": "FAIL", "reason":
                   str(error), "checks_posted": "none_or_partial; inspect live API"}
        args.output.write_text(json.dumps(failure, sort_keys=True, indent=2) + "\n",
                               encoding="utf-8")
        print(json.dumps({"decision": "FAIL", "reason": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
