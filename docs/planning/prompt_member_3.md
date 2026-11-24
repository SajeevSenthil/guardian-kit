# Prompt — Member 3 (M3): remedies with UI approval, sandbox verification, report

Setup (in a terminal, before opening Claude Code):
```
git fetch origin && git checkout v2-any-repo && git pull
```
Then start Claude Code in the repo, run `/clear` and paste the block below.

```text
I am M3 on a 3-person team with a 2-hour deadline. Read docs/V2_TEAM_CONTRACT.md completely
first. It is binding: the file ownership, stage ids, function signatures, page module API, CSS
tokens and classes, the honesty rules and "approvals only from a human click" are fixed. Then
read new_plan.md §3 (pages 8–10) for the intent. We wrap the existing v1 pipeline; we do not
rebuild it. Work on branch v2-any-repo only. Edit only the files the contract gives to M3:
- guardian/v2/stages_fix.py
- guardian/api/routes_fix.py
- guardian/api/static/pages/{remedies,verify,report}.js
- tests/unit/test_v2_fix.py
- docs/V2_DEMO.md
Read the v1 code first: guardian/cli.py (cmd_plan, cmd_approve, cmd_withdraw, cmd_validate),
guardian/remediate.py (plan generation, compute_plan_hash, approve, check_approval, withdraw),
guardian/validate.py (validate, compare, _docker), guardian/loop.py (close_loop),
guardian/report.py (render) and guardian/review.py (sec_remedies).

Until M1's skeleton lands (about T+30), develop against the fake workspace in contract §7,
using runs/20261124T053859Z-8e1c (it already has 4 plans).

IMPORTANT: Guardian v2 supports ANY ecosystem (pip, npm, Go, Maven, Cargo…); read contract §0.
ws.v1_run is None for non-npm repos, and every stage must still work.

1. run_remedies(ws, opts):
   - npm with ws.v1_run: with bridge.use_target(ws), do what cmd_plan does (candidates in
     throwaway clones, policy gate, Remediation Planner if live) for the prioritised top npm
     items;
   - other ecosystems: generic "bump to fixed version" plans from M2's prioritised rows (fixed
     versions come from the advisories):
     - choose the lowest fixed version that fixes ALL advisories of that package; ask OSV
       (querybatch, already in v1) whether that version has its own advisories, and if so go
       higher;
     - edit the exact line in the manifest that pins it: requirements*.txt `pkg==x` → `pkg==y`;
       pyproject (poetry/PEP 621); go.mod `require`; Cargo.toml; pom.xml `<version>`. If the
       lockfile also pins it (poetry.lock, Cargo.lock, go.sum…), say "lockfile must be
       regenerated in the sandbox". We never run the resolver outside the container;
     - a transitive-only package (not in any manifest): plan kind "add a constraint/override"
       where the ecosystem supports it (pip constraints line, npm overrides, Cargo [patch]), or
       else "manual: upgrade parent <x>". Honest;
     - produce the patch with `git diff` in a throwaway clone. patch_sha256 and plan_hash use
       remediate.compute_plan_hash with the same fields as npm plans; prediction = {resolves:
       the advisory ids, new_vulns_on_fix_version: from OSV, breaking: "not computed"};
   - result.json: per plan the id, finding, title, chosen candidate + why, edits, prediction
     (resolves, new vulnerabilities on the fix version, dangling requires), policy gate, rejected
     alternatives with reasons, rollback, patch path, patch_sha256, plan_hash, and decision
     (pending/approved/rejected/deferred + by + at);
   - flag conflicts: two plans changing the same package to different versions;
   - end with ws.set_status("remedies", "awaiting_approval", summary={plans, decided,
     approved}) and return the summary. The runner keeps that status (contract §5).

2. routes_fix.py (the human gate; the ONLY way to approve):
   - POST /api/ws/{id}/plans/{plan_id}/decision {decision: approve|reject|defer, approver,
     plan_hash, note}:
     - approver must not be empty;
     - re-compute the plan hash with remediate.compute_plan_hash and refuse a mismatch with 409;
     - approve calls remediate.approve(run, plan_id, approver), reject calls it with
       reject=True, defer is recorded only;
     - each decision goes to audit (ws.audit) and updates stages/remedies/result.json;
     - refuse decisions after the batch is sent;
     - refuse approving two conflicting plans;
   - POST /api/ws/{id}/remedies/send-to-sandbox:
     - requires every plan decided and at least one approved;
     - writes stages/remedies/approved_set.json (plan ids, hashes, approvers, time);
     - sets remedies to ok;
     - starts the verify stage through the runner.
   - Add a test that no module under guardian/v2/stages_* or guardian/agents imports or calls
     the decision handler or remediate.approve (grep-based test is fine).
   Note: the project hook stops Claude from running `guardian approve`; that is intended. You
   test the API through FastAPI TestClient in pytest, and the human clicks it in the UI.

3. run_verify(ws, opts), the proof:
   - read approved_set.json; re-check every plan hash (a mismatch stops with FAILED);
   - npm plans: with bridge.use_target(ws), for each approved npm plan run
     guardian.validate.validate(run, plan_id). It already does: approval check, apply in a
     throwaway clone, `npm ci --ignore-scripts`, static start, rescan, SBOM diff, new findings,
     policy, prediction. Collect its checks.
   - Every plan of every ecosystem then goes into the combined proof below.
   - Combined proof on ONE clone with ALL approved patches applied together: clone ws.src into
     ws.dir/work/verify-<n>/ with `git clone -c core.autocrlf=false --no-hardlinks`, then
     `git apply` each patch in order (a patch that fails to apply → FAILED);
     for npm also `npm ci --ignore-scripts`.
   - Install and tests: a per-ecosystem table in stages_fix.py, only if docker is available
     (validate._docker()). There are two container steps:
     (1) install, with network, no secrets: python `python:3.12-slim` → `pip install -r
         requirements.txt` (or `pip install .` / `poetry install`), then regenerate the
         lockfile if the plan says so; node `node:20-bookworm-slim` → `npm ci`; go
         `golang:1.22` → `go mod download`;
     (2) tests, with `--network none`: python `pytest -q` (or `python -m unittest`); node
         `npm test`; go `go test ./...`.
     Both steps use `--memory 2g --cpus 2 --pids-limit 512`, the clone mounted at /app, no -e
     flags and a 600 s timeout. Other ecosystems → "not run (no test runner configured for
     <eco>)".
     - parse the pass/fail counts when recognisable (pytest, mocha/jest/tap, go test),
       otherwise use the exit code;
     - no tests found → "not run (repo has no tests)";
     - no docker → "not run (docker not installed)". Never "passed".
   - Rescan the combined clone with the same tools as stage 4: Syft → OSV-Scanner + Grype (M2's
     run_vulns helpers, imported read-only), and the v1 fast path too for npm.
   - Before/after per approved plan: targeted advisories gone/still present; new advisories
     (must be 0); SBOM diff (added/removed/changed); remaining advisories not covered by any
     approved plan (listed, never hidden).
   - Verdict by code:
     - VERIFIED: all checks passed, tests ran and passed, every target is gone, 0 new;
     - PARTIAL: something didn't run (list it);
     - FAILED: something failed. Then call close_loop/the Diagnostician as cmd_validate does,
       mark the plan "needs revision" in remedies/result.json and set remedies back to
       awaiting_approval.
   - Headline: "Targeted vulnerabilities fixed: X of Y · new: Z · tests: … · remaining: R".
   - Save all logs under stages/verify/ and link them.

4. run_report(ws, opts):
   - with bridge.use_target(ws): report.render(run) and review.render(run);
   - result.json with links to report.html/md/json, vex.json, review.html, the audit chain
     check, and stage coverage (each of the 10 stages ok / not run).

5. Pages:
   remedies.js:
   - G.header;
   - a progress bar "k of n decided";
   - per plan a card: what it fixes, chosen fix + why, edits, prediction, policy gate badge,
     rejected alternatives, rollback, a patch link (opens the .patch), plan_hash (.mono);
   - the Planner text inside .ai-box;
   - buttons Approve / Reject / Defer. Approve opens an inline form with "Your name" and shows
     the hash being approved;
   - conflict warning;
   - "Send approved remedies to sandbox" (disabled until every plan is decided), which then
     navigates to the Sandbox tab.
   verify.js ("Sandbox verification"):
   - the approved set (who, what, hash);
   - a live check list (polling) with pass / fail / not run, each opening its log;
   - a test results box;
   - a before/after table per plan;
   - a "New vulnerabilities" tile (must say 0);
   - the SBOM diff; the remaining-advisories list;
   - a big verdict banner (VERIFIED green / PARTIAL amber with what didn't run / FAILED red with
     the Diagnostician card in .ai-box and a "Back to Remedies" link);
   - G.sources.
   report.js:
   - stage coverage;
   - buttons to open review.html and report.html;
   - downloads (report.json, report.md, vex.json, audit.jsonl);
   - the audit chain status.

6. tests/unit/test_v2_fix.py:
   - decision API: hash mismatch → 409, empty approver → 400, decision after send → 409,
     conflict refused;
   - send-to-sandbox requires all plans decided;
   - verdict table: all pass → VERIFIED; tests not run → PARTIAL; target still present →
     FAILED; new advisory → FAILED;
   - the docker command contains --network none and no -e;
   - the source tree hash is unchanged after verify;
   - the no-approval-from-code grep test.

Acceptance (T+75, integration 1), on BOTH team repos (npm and Python):
- Python: a pypi plan edits the requirements line, gets approved in the UI and is verified by
  the OSV-Scanner rescan, with the advisory gone and 0 new.
- On M1's workspace (after M2's stages 4–6), run Remedies from the UI → awaiting approval.
- Approve one plan, reject one, defer the rest → Send to sandbox → the Sandbox tab runs live
  and ends in a verdict with every check shown. Without docker it is PARTIAL with "tests: not
  run (docker not installed)", which is honest.
- The Report page opens review.html and report.html. `python -m pytest -q` passes.
- Commit "[M3] stages 8-10 and pages", pull --rebase, push.
After T+75: fix integration bugs in your files. T+100–115: write docs/V2_DEMO.md, the 6-minute
demo script: URL → SBOM → graph → vulns → prioritised → agents → remedies (approve in the UI)
→ sandbox verdict → report, with what to say on each page; merge in M2's notes.
```
