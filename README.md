# Independent M0 trusted gate bridge

Status: **first live gate attempt failed; no GitHub App check has been published**. The
separate public repository is `xbroute/hayool-m0-trusted-gate` (ID
`1395856214`). The `hayool-trusted-publisher` environment with selected-main
branch restriction has been created and read back; it has **zero secrets**.
The gate repository's `main` is protected with required
`independent-gate-selftest` from GitHub Actions App ID `15368`, one nonauthor
approval, stale-review dismissal, latest-push approval, admin enforcement,
no force push and no deletion. Actions event policy `5994` is active. The App
and target required-check source still need live setup/readback. `config.json` deliberately
has `github_app_id: null`; the publisher requires a positive App ID from a
selected-main protected environment variable. Local PASS is not M0.0 PASS.

The first live dispatch [run 36596893643](https://github.com/xbroute/hayool-m0-trusted-gate/actions/runs/36596893643)
failed `unit` and `test_integrity`: the Docker CLI inherited the former 1 GiB
host `RLIMIT_AS` and its Go runtime reported `runtime/cgo: pthread_create
failed: Resource temporarily unavailable`. Its artifact ID is `11046163455`
with GitHub ZIP SHA-256
`ab28ee021668fd12216f0b76367fe79fd26b52cbc939f2895bb2ea203ad1d0d2`.
This branch removes that host address-space cap; only a new exact-SHA live run
can establish whether the repair works on GitHub.

## Boundary and report

`gate.py` is read-only. It verifies live target repository ID `1389639283`,
PR/head/base, main ref, commit ancestry, the GitHub synthetic test-merge
commit's ordered parents and byte-identical tree, plus the separate workflow's
repository ID, main SHA, event, path, ID and attempt. It executes only trusted
`policy/independent_policy.py`, whose SHA-256 is pinned in `config.json`.
That policy re-runs all eight hard checks. Candidate unit tests (36) and gate
regressions (24) execute only inside a digest-pinned Python Docker image with
no network, read-only mount/root filesystem, nonroot UID, no capabilities, a
90-second wall limit, 512 MiB memory and 64-process cap. The host evaluator
receives no App key, write token, or production credential. A missing Docker
daemon/image, changed SHA, failed test, incomplete report or timeout fails.
The trusted host policy subprocess adds no `RLIMIT_AS` cap, allowing its
Docker client to start. The runner VM's physical memory still bounds the
trusted process; it also has a 180-second CPU limit, a 420-second wall limit,
and a 4 MiB file-size limit. The workflow has a
10-minute job limit. `baseline_memory_bytes: null` in the JSON report means
there is no additional host `RLIMIT_AS`, not that candidate memory is
unbounded: the untrusted test container still has its separate 512 MiB cap.

PR #7's migration is exactly `9af7ac8a4b8cd7ea96c27a2eb5f4c69c92d33659`
to `da7c6f91a074d58dde35d7c032bae94230dea128`, with the ten changed
paths and SHA-256 file hashes in `config.json`. The independent
`test_integrity` rule validates those bytes, retains every existing Python
test path, and requires both isolated suites. Other PRs use the original
frozen-path rule. No AI vote enters a hard-check decision.

The protected-main legacy baseline was run separately on that exact PR #7
head. It recorded seven PASS checks and `test_integrity=FAIL` for these five
ADR-034 frozen-path findings: `bootstrap/engrun.py`,
`bootstrap/regression_tests/test_target_gate.py`,
`bootstrap/tests/test_engrun_pr_target_binding.py`,
`bootstrap/tests/test_pr_target_runtime_binding.py`, and
`bootstrap/trusted_gate.py`. The unchanged diagnostic JSON is outside this
deployable source tree at
`engineering-evidence/m0-independent-gate-local/local-baseline-pr7.json`
(SHA-256 `29d1730e0448d435db92e7ba38ff6c6c64c8a60a49c2645011b0138d79c41140`).
No legacy FAIL is converted into PASS. The new independent policy produced its
own eight PASS results locally; that local report is also outside this tree.
The `migration.test_integrity_errors` list in `config.json` is retained only
as a historical audit record; neither evaluator nor publisher reads it to
decide PASS. An attempted deletion was rejected by automatic approval review.

The evaluator writes one JSON report containing exact target and external
policy SHA, repository IDs, PR, base/head/test-merge/tree SHA, run/attempt,
all hard checks, explicit migration rule, changed-file hashes, isolated-suite
evidence and resource limits. The separate `publisher.py` never checks out PR
code. It retrieves the trusted artifact by run/attempt/name, verifies its
SHA-256 and source metadata, re-queries the live PR before each publication,
and posts completed success/failure GitHub App checks to the verified
test-merge SHA and head SHA. It reads both check runs back and verifies App ID,
name, SHA, conclusion and external ID. No report or AI vote can mint a check
without the protected environment's PEM and verified GitHub App installation.

## Owner setup and readback

1. Review this source and merge it into the separate gate repository's
   protected `main` through independent human approval. Restrict gate-repository
   writers and read back the exact main SHA and protection through GitHub API.
   The `selftest.yml`
   runs on protected-main PR events and main pushes; do not call it a
   tamper-proof required source unless the gate repository's event policy and
   source binding are separately proved.
2. Re-read the already created `hayool-trusted-publisher` environment under
   **Settings → Environments**. It must have deployment branches set to
   **Selected branches: `main` only**. This is the
   enforceable barrier against a `workflow_dispatch` run on another ref.
   The publisher job also checks `github.ref == refs/heads/main`, but that
   code check alone does not protect a secret before job start.
3. Create a GitHub App in Owner settings with target permissions **Checks:
   read/write**, **Contents: read-only**, **Pull requests: read-only** and
   implicit Metadata read. Do not grant administration, workflows, actions
   write, deployments or secrets access. Install it on selected repository
   `xbroute/hayool-os` only. Put its numeric App ID in the gate repository
   environment variable `HAYOOL_GATE_APP_ID`. Generate its private key and
   put it **only** in that environment's secret
   `HAYOOL_GATE_APP_PRIVATE_KEY`; never send the PEM through chat, add it to
   any repo, or put it in a general repository secret. Read back App ID,
   installation ID, selected repository and permission scope. The publisher
   mints a one-hour installation token scoped to the target repo and required
   permissions, then discards it.
4. Dispatch the protected workflow on `main` for the immutable PR #7 head:

   ```text
   gh workflow run hayool-independent-gate.yml --repo xbroute/hayool-m0-trusted-gate --ref main -f pr_number=7 -f head_sha=da7c6f91a074d58dde35d7c032bae94230dea128
   ```

   Read back run path/ref/SHA/attempt, eight PASS checks, 36+24 isolated tests,
   artifact digest, App check IDs and App source ID on both exact head and
   synthetic merge SHA. A failed or absent check remains blocking.
5. Only after the independent App check is live and verified, migrate target
   required checks in **two protected updates**. First PATCH
   `required_status_checks` with `strict=true` and **both** the old
   `engineering-trusted-gate-status` (GitHub Actions App ID `15368`) and new
   `engineering-independent-gate` (observed new App ID); read back both.
   Then PATCH the same endpoint with `strict=true` and **only** the new
   App-bound check; read back again. Never submit an empty check list. Preserve
   human review, stale dismissal, latest-push approval, admin enforcement,
   no force push/deletion and target Actions policy 5892 throughout. If either
   update cannot be confirmed, stop; do not temporarily disable protection or
   use an admin bypass.
6. Obtain independent GitHub human approval on PR #7's unchanged final head,
   then merge through normal protection. Re-dispatch Shadow, hard failure,
   workflow spoof and wrong-source check cases from the new `main`, retaining
   their real artifacts and readbacks. M0.0 remains PENDING until those live
   runs, exact-SHA reviews and a final ENG-RUN all satisfy the Source of Truth.

The gate repo's selftest is advisory at seed time. The required target check
must be bound to the new App ID, not the shared `github-actions` source.
Workflow dispatch inputs never select a policy branch or App ID; alternate
refs cannot obtain the PEM because of the protected environment branch rule.
Use standard hosted runners only. Both bounded JSON artifacts currently have
30-day retention so evidence survives M0 review; monitor public-repository
artifact storage against the free allowance and stop before any paid usage.
No larger runner, paid service, or new infrastructure spend is authorized.

Official references: [workflow_dispatch and ref semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows),
[GitHub App installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app),
[GitHub App check runs](https://docs.github.com/en/rest/guides/using-the-rest-api-to-interact-with-checks).
