# Guardian v2-lite — team contract (READ FIRST, all 3 members)

The 2-hour version of `new_plan.md`. **We do not rebuild v1. We wrap it.** The v1 pipeline (fast
path scan → prioritise → agents → plan → approve → validate → report) already works. v2-lite
adds:
- any repo as input (a git URL, a zip or a local path);
- a web UI with one page per stage;
- each stage runnable on its own;
- per-remedy approval in the UI;
- a Sandbox tab that proves the fixes.

Anything in `new_plan.md` that isn't in this file is **out of scope for today**.

## 1. One branch, one workflow

- **Branch:** `v2-any-repo`. Everyone works on it. No other branches, no force-push.
- **Start:**
  ```
  git fetch origin
  git checkout v2-any-repo
  git pull
  ```
- **Every 20–30 min:** commit only your own files, then
  ```
  git pull --rebase origin v2-any-repo
  git push origin v2-any-repo
  ```
- **You only edit files you own (§3).** If you need a change in someone else's file, message
  them. Never edit it yourself. That is what keeps rebases conflict-free.
- Commit messages start with your tag: `[M1]`, `[M2]` or `[M3]`.
- Never commit `runs/`, `workspaces/`, `target/`, `.env` or `tools/bin/`. M1 adds them to
  `.gitignore` in the first commit.
- Run the v1 tests before every push: `python -m pytest -q`. Don't break v1.

## 2. Timeline (T = start)

| Time | M1 | M2 | M3 |
|---|---|---|---|
| T+0–5 | read this file | read this file | read this file |
| T+5–30 | **skeleton** (§4–§6); push by **T+30** | backend for stages 4–7 against an existing v1 run (§7); tests | backend for stages 8–10 against an existing v1 run; tests |
| T+30 | **skeleton pushed** → everyone pulls | pull | pull |
| T+30–75 | stages 1–3 and their pages | pages for stages 4–7 | pages for stages 8–10 |
| **T+75** | **integration 1:** each member runs the whole flow on the same small repo | | |
| T+75–100 | fix, polish | fix, polish | fix, polish |
| **T+100** | **feature freeze.** Only bug fixes after this. | | |
| T+100–115 | final run on the demo repo; screenshots | write their pages' README section | `docs/V2_DEMO.md` |
| T+120 | demo | | |

Until the skeleton lands, M2 and M3 develop against the existing run
`runs/20261124T053859Z-8e1c` (it has findings, a graph, prioritised.json, plans and a report).

## 3. File ownership (do not edit outside your column)

| M1: foundation and discovery | M2: detection and investigation | M3: remedies, sandbox, report |
|---|---|---|
| `guardian/v2/__init__.py`, `workspace.py`, `runner.py`, `bridge.py`, `stages_discover.py` | `guardian/v2/stages_detect.py` | `guardian/v2/stages_fix.py` |
| `guardian/api/__init__.py`, `app.py`, `routes_core.py` | `guardian/api/routes_detect.py` | `guardian/api/routes_fix.py` |
| `guardian/api/static/index.html`, `styles.css`, `app.js`, `pages/start.js`, `pages/sbom.js`, `pages/graph.js` | `guardian/api/static/pages/vulns.js`, `signals.js`, `prioritise.js`, `investigate.js` | `guardian/api/static/pages/remedies.js`, `verify.js`, `report.js` |
| `guardian/cli.py` (only adding `ui`, `ws`, `stage`), `.gitignore`, `guardian.toml` `[sources]`, `CLAUDE.md` scope line, `scripts/setup_tools.*` | `tests/unit/test_v2_detect.py` | `tests/unit/test_v2_fix.py`, `docs/V2_DEMO.md` |
| `tests/unit/test_v2_core.py` | | |

v1 modules (`guardian/*.py`, `fastpath/`) are **read-only for everyone**. If v1 needs a fix, the
owner of the stage that needs it makes the smallest change and says so in the commit message.

## 4. Workspace (M1 builds it; everyone uses it exactly like this)

```
workspaces/<ws_id>/
  workspace.json        {"id", "source": {"kind": "git|zip|path", "value"}, "ref", "sha", "created",
                         "consent": {"by", "at"}, "v1_run": "<abs path to runs/<id>>",
                         "stages": {"<stage>": {"status", "started", "finished", "summary", "error"}}}
  src/                  the repo, always a git repo (a zip or path is git-init'ed + committed by ingest)
  stages/<stage>/result.json   what that stage's page renders (plus any raw files next to it)
```

```python
from guardian.v2.workspace import Workspace
ws = Workspace.load(ws_id)          # or Workspace.create(source_kind, value, ref, consent_by)
ws.id, ws.dir, ws.src               # Path objects
ws.v1_run                           # Path to the v1 run dir (set by the "sbom" stage), or None
ws.stage_dir("vulns")               # Path, created on demand
ws.write("vulns", data)             # writes stages/vulns/result.json
ws.read("vulns")                    # dict or None
ws.set_status("vulns", status, summary=None, error=None)
ws.audit(event, **fields)           # append to the v1 run's hash-chained audit.jsonl
```

**Calling v1 code on a workspace (everyone).** v1 reads the repo path from module variables
(`guardian.runs.TARGET`, `fastpath/build.py TARGET/OUT`). M1's `guardian/v2/bridge.py` provides:
```python
from guardian.v2 import bridge
bridge.scan(ws, offline=False)      # v1 fast path on ws.src (base = head = snapshot), sets ws.v1_run
with bridge.use_target(ws):         # points every v1 TARGET at ws.src while inside; global lock
    prioritise(...) / analyse(...) / remediate... / validate(...)
```
**Wrap every v1 call that touches the repo in `bridge.use_target(ws)`.**

**Stage status values:** `not_run`, `running`, `ok`, `failed`, `stale`, `awaiting_approval`.

## 5. Stages: fixed ids, order and owners

| # | id | Owner | What it does (v1 function it wraps) |
|---|---|---|---|
| 1 | `ingest` | M1 | clone, unpack or copy into `src/`; list lockfiles, manifests, Dockerfiles, CI files |
| 2 | `sbom` | M1 | `bridge.scan(ws)`: runs the v1 fast path with base = head = the chosen ref; copies SBOMs; also runs **Syft** if `tools/bin/syft` exists, with a parser-vs-Syft cross-check |
| 3 | `graph` | M1 | from the v1 `graph.json`: nodes, edges, direct/transitive, paths, stats |
| 4 | `vulns` | M2 | vulnerability findings from v1 (OSV) plus **OSV-Scanner** and **Grype** if they're in `tools/bin`; merged per advisory with a reported-by column |
| 5 | `signals` | M2 | supply-chain findings from v1 that aren't CVEs (install scripts, typosquat, Docker, CI…) |
| 6 | `prioritise` | M2 | `guardian.prioritise` (as `cmd_prioritise` in `guardian/cli.py` calls it) + reasons |
| 7 | `investigate` | M2 | `guardian.agents.runner.analyse(run, mode, top_n)` → agent cards |
| 8 | `remedies` | M3 | `cmd_plan` logic → plans; ends in `awaiting_approval` |
| 9 | `verify` | M3 | for the approved set: `guardian.validate.validate` per plan + `npm test` in a container if docker + a before/after rescan; verdict |
| 10 | `report` | M3 | `guardian.report.render` + `guardian.review.render`; links |

**Stage function signature.** Everyone uses exactly this:
```python
def run_<id>(ws: Workspace, opts: dict) -> dict:   # returns the summary dict shown in the page header
    ...                                            # must call ws.write("<id>", result)
```

- M1's `runner.py` has a fixed registry: `{"vulns": "guardian.v2.stages_detect:run_vulns", ...}`
  for all 10 stages, imported lazily. **M2 and M3 never edit `runner.py`.** If the module or
  function doesn't exist yet, the runner reports "not built yet".
- If a stage function itself set its status to `awaiting_approval` (remedies does), the runner
  keeps that status instead of overwriting it with `ok`.
- The runner handles status, timing, errors (stored as one line; traceback only with
  `GUARDIAN_DEBUG=1`), the upstream check (`needs`), and marking downstream stages stale.

**`needs`:**
- sbom ← ingest; graph ← sbom; vulns ← sbom; signals ← sbom;
- prioritise ← vulns, signals, graph;
- investigate ← prioritise; remedies ← prioritise;
- verify ← remedies (status ok, which means the approved set has been sent);
- report ← nothing. It uses whatever exists and says "not run" for the rest.

## 6. API and UI contract

**API (FastAPI, `python -m guardian ui`, http://127.0.0.1:8080, localhost only):**
- `POST /api/ws` `{kind, value, ref?, consent_by}` → `{id}`; `GET /api/ws`; `GET /api/ws/{id}`
  returns `workspace.json`.
- `POST /api/ws/{id}/stages/{stage}/run` (runs in a background thread) and
  `POST /api/ws/{id}/run-until/{stage}`.
- `GET /api/ws/{id}/stages/{stage}` → `{status, summary, result}`.
- `GET /api/ws/{id}/file?path=…` → a file from the workspace or the v1 run dir (read-only,
  path-traversal safe). Use this for every **Source files** link.
- `app.py` includes `routes_detect.router` and `routes_fix.router` with
  `try: import ... except ImportError: pass`. **M2 and M3 put any extra endpoints in their own
  routes file under `/api/ws/{id}/...`; they never edit `app.py`.**

**UI (plain HTML, CSS and JS; no build step; no frameworks; vis-network 9.1.9 from cdnjs for
graphs):**
- `index.html` (M1) has the left nav with all 10 stages in the order of §5, a status chip per
  stage, and loads `app.js` and **all 10** `pages/*.js` files from the start. A missing file just
  shows "not built yet".
- **Page module API.** Every page file does exactly this:
  ```js
  G.page("vulns", {
    title: "Vulnerabilities",
    async render(el, ctx) { /* ctx = {wsId, stage, status, summary, result} */ }
  });
  ```
- **Helpers in `app.js`. Use these, don't write your own versions:**
  - `G.api(path, opts)` → JSON;
  - `G.fileUrl(path)` → href;
  - `G.header(el, ctx)` renders the standard stage header: title, status chip, Run / Re-run
    button, last run time, summary chips. **Every page calls this first**;
  - `G.tiles(el, [{label, value, tone}])` with tone one of `crit|high|med|low|ok|info`;
  - `G.table(el, columns, rows, {search: true, pageSize: 50})`;
  - `G.badge(text, tone)` → html;
  - `G.chip(kind)` with kind one of `verified|derived|inferred|unknown|not-run`;
  - `G.card(el, {title, body, tone})`;
  - `G.sources(el, [{label, path}])` renders the "Source files" row;
  - `G.json(el, obj)` is a collapsible raw view;
  - `G.esc(s)` escapes HTML.
- **Styles (`styles.css`, M1). Only these tokens and classes; no inline colours, no other CSS
  files:**
  - tokens: `--bg --panel --text --muted --border --accent --crit --high --med --low --ok
    --info --inferred`;
  - dark mode through `@media (prefers-color-scheme: dark)`;
  - font: system-ui; monospace for ids, purls, hashes and file paths (`.mono`);
  - classes: `.page .section .tiles .tile .card .badge .tone-* .chip .chip-* .table .btn
    .btn-primary .btn-danger .muted .mono .row .col .split .ai-box`. `.ai-box` is the dashed
    border used for **every** AI output, labelled "AI · inferred".
- **Honesty rules in the UI (everyone):**
  - a tool that didn't run shows `G.chip("not-run")`, never 0;
  - AI text always goes inside `.ai-box`;
  - every page ends with `G.sources(...)` linking the real files;
  - no "No vulnerabilities" unless every tool that ran returned zero.

## 7. Developing before the skeleton exists (M2 and M3, T+5–30)

Write your stage functions against a **fake workspace**:
```python
from types import SimpleNamespace
from pathlib import Path
run = Path("runs/20261124T053859Z-8e1c")
ws = SimpleNamespace(v1_run=run, src=Path("target"), dir=Path("workspaces/_dev"), ...)
```
- Read your inputs only from `ws.v1_run` and `ws.read(...)`.
- Put pure logic in helper functions that take dicts, so the unit tests need no network.
- When the skeleton lands, switch to the real `Workspace`.

## 8. Scope and safety (unchanged rules, applied to v2)

- Git URLs: allowed only if their host and owner are in `guardian.toml [sources] allow`.
  Cloning uses `--depth 50 --no-recurse-submodules -c core.hooksPath=` plus a size cap. Zip
  extraction rejects `..`, absolute paths and symlinks. A consent name is required and audited.
- **Never run the repo's code, except `npm test` inside a `--network none` Docker container in
  the verify stage.** No docker means "not run".
- `npm` always runs with `--ignore-scripts` outside that container.
- **Approvals only come from a human click in the UI** (an HTTP POST with a typed name and the
  plan hash). No stage or agent code calls the approve function.
- Never print or log API keys. Keys come from `.env` only.
