# Prompt — Member 1 (M1): foundation, intake, SBOM, dependency graph

Setup (in a terminal, before opening Claude Code):
```
git fetch origin && git checkout v2-any-repo && git pull
```
Then start Claude Code in the repo, run `/clear` and paste the block below.

```text
I am M1 on a 3-person team with a 2-hour deadline. Read docs/V2_TEAM_CONTRACT.md completely
first. It is binding: the file ownership, stage ids, function signatures, API, page module API,
CSS tokens and classes are fixed. Then skim new_plan.md §3 (pages 1–3) for the intent. We wrap
the existing v1 pipeline; we do not rebuild it. Work on branch v2-any-repo only. Edit only the
files the contract gives to M1.

Guardian v2 supports ANY ecosystem (pip, npm, Go, Maven, Cargo…); read contract §0 carefully.
Syft and OSV-Scanner are required tools. npm with package-lock.json gets the extra v1 deep
layer.

PART A — SKELETON. Must be committed and pushed by T+30 min; the others are waiting on it. Keep
it minimal but exactly to the contract.

0. FIRST 10 MINUTES:
   - write scripts/setup_tools.ps1 (Windows) and update scripts/setup_tools.sh (Linux/macOS).
     Each downloads pinned releases of syft, osv-scanner and grype from GitHub into tools/bin/,
     checks SHA256 against the release checksums file, and writes versions to tools.lock;
   - run it, and confirm `tools/bin/syft version`, `tools/bin/osv-scanner --version` and
     `tools/bin/grype version`;
   - add guardian/v2/tools.py (you own it): find_tool(name) → path (tools/bin first, then
     PATH) or None, and tool_version(name);
   - commit and push immediately, so M2 and M3 can run the script.
   Also pick a small public Python repo with a pinned requirements.txt or poetry.lock for the
   team, add its owner to the allow-list, and post the URL to the team.

1. .gitignore: add workspaces/ and tools/bin/.
   guardian.toml: add
     [sources]
     allow = ["github.com/<demo owner>"]
     max_mb = 200
   Ask me for the demo owner.
   CLAUDE.md: show me the one-line scope change ("./target and workspaces/*/src, cloned
   only from [sources] allow with recorded consent") and apply it only after I say yes.

2. guardian/v2/workspace.py: the Workspace class exactly as in contract §4 (create, load, src,
   v1_run, stage_dir, write, read, set_status, audit). workspace.json is written atomically
   (write a temp file, then os.replace). Ids are a UTC timestamp plus 4 hex characters.

3. guardian/v2/runner.py:
   - the fixed registry of all 10 stages ("module:function", lazy import, "not built yet" when
     missing);
   - `needs` from contract §5;
   - run_stage(ws, stage, opts, force=False): upstream check, status running → ok/failed,
     timing, one-line error, then mark downstream stages stale;
   - run_until(ws, stage);
   - a per-workspace lock (one stage at a time).

4. guardian/api/app.py + routes_core.py: the endpoints in contract §6.
   - Stage runs go to a ThreadPoolExecutor.
   - The file endpoint serves files only under the workspace dir or its v1_run dir (resolve the
     path and check it is inside).
   - Static files are served from guardian/api/static.
   - `try: include routes_detect.router / routes_fix.router` (ImportError → skip).
   guardian/cli.py: add `ui` (uvicorn, 127.0.0.1:8080), `ws create|status`, `stage <id> --ws`.

5. Static files:
   - index.html: the left nav with the 10 stages in contract order, with status chips; loads
     app.js and all 10 pages/*.js files (a missing file just shows "not built yet");
   - a workspace picker at the top (latest by default);
   - app.js: the G object with every helper in contract §6, exact names and signatures:
     - G.header renders a Run / Re-run button that POSTs to the stage run endpoint, then polls
       GET /stages/{stage} every 1.5 s until the status is not running, then re-renders;
     - nav chips refresh every 3 s;
   - styles.css: the tokens and classes from the contract, light and dark. Make it look clean:
     - 8px spacing scale, 12px radius cards, subtle borders;
     - tiles in a responsive grid;
     - sticky table headers;
     - `.ai-box` with a dashed border, using --inferred, labelled "AI · inferred" via ::before.
   A page file that only calls G.header and G.json must look good, because M2 and M3 start
   from that.

6. tests/unit/test_v2_core.py:
   - workspace create from a local path;
   - zip-slip rejected;
   - a URL outside the allow-list rejected;
   - runner upstream check;
   - stale marking;
   - the file endpoint refuses `../`;
   - TestClient smoke test.
   Commit "[M1] v2 skeleton" and push. Tell me so I can tell the team.

PART B — STAGES 1–3 and their pages (T+30 to T+75).

7. stages_discover.run_ingest:
   - source kind git: check the URL against the allow-list (https only; no credentials in the
     URL; host/owner match), then `git -c core.hooksPath= -c core.autocrlf=false clone --depth
     50 --no-recurse-submodules <url> src`, check out the ref if given, and enforce max_mb;
   - kind zip: safe extraction;
   - kind path: copy, without node_modules or .git;
   - for zip and path: git init + commit, so v1 can `git archive` it.
   Result: sha, ref, size, and ecosystems detected, each with its manifest and lockfile paths:
   - npm: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml;
   - python: requirements*.txt, pyproject.toml, poetry.lock, Pipfile(.lock), uv.lock, setup.cfg;
   - go: go.mod/go.sum; maven: pom.xml; gradle: *.gradle(.kts), gradle.lockfile;
   - cargo: Cargo.toml/.lock; ruby: Gemfile(.lock); php: composer.json/.lock; dotnet: *.csproj,
     packages.lock.json;
   - plus whether each manifest is pinned (has a lockfile, or `==` pins), Dockerfiles and
     .github/workflows files;
   - deep_npm: true if a root package-lock.json exists.
   No manifests at all → a clear message. Never an error that blocks a non-npm repo.
   Audit the consent.

8. guardian/v2/bridge.py: scan(ws, offline=False):
   - temporarily set fastpath build.TARGET and guardian.runs.TARGET (plus fp.OUT handling, as
     guardian/validate.py lines 81–86 do) to str(ws.src);
   - call runs.scan(ref, ref, offline), so base = head = the snapshot;
   - restore the variables in `finally`;
   - set ws.v1_run;
   - protect it with a global lock (fastpath/out is shared).
   Also provide bridge.use_target(ws) exactly as in contract §4: a context manager that points
   every v1 TARGET at ws.src (guardian.runs.TARGET, fastpath build.TARGET; these are read by
   guardian/remediate.py:306, guardian/agents/runner.py:135 and guardian/agents/tools.py:119)
   and restores them in `finally`. M2 and M3 depend on it, so put bridge.py in the PART A
   skeleton commit (scan can be a stub until step 9).

9. run_sbom, for all ecosystems:
   a) Syft (required; if it is missing, fail with "run scripts/setup_tools"):
      - `syft dir:<src> -o cyclonedx-json=<stages/sbom/syft.cdx.json> -o
        syft-json=<stages/sbom/syft.json>`, excluding node_modules, .venv, venv, vendor, .git,
        with a 300 s timeout;
      - probe it once first and write the exact command, version and JSON key paths to
        docs/tool-notes/syft.md (artifacts[], artifactRelationships[] of type
        "dependency-of", locations, language, purl);
      - build components with the contract §0 schema: ecosystem (from purl type: npm, pypi,
        golang, maven, cargo, gem, composer, nuget…), locations, licences;
      - direct = it appears in a root manifest (parse the root manifest names per ecosystem:
        package.json deps, requirements*.txt lines, pyproject [project.dependencies] /
        [tool.poetry.dependencies], go.mod require, Cargo.toml [dependencies]); null if it can't
        be told;
      - unpinned requirement lines (no `==`) are recorded as components with version null and
        "unpinned": true.
   b) Deep npm layer: if bridge.has_npm_lock(ws), run bridge.scan(ws), copy sbom.head.cdx.json
      and cross-check with Syft by purl (counts, only_syft, only_v1, version mismatches). If it
      isn't npm, show "not applicable (no package-lock.json)".
   Result: components, totals per ecosystem, tools {syft: version, v1_npm: ran|not-applicable},
   crosscheck.
   pages/sbom.js:
   - G.header;
   - tiles (packages, ecosystems, direct, transitive/unknown, unpinned, licences);
   - an "Ecosystems" card with counts per ecosystem and the manifests they came from;
   - the tool cross-check card;
   - a searchable components table with an ecosystem column and filter;
   - download links (Syft CycloneDX, Syft JSON, v1 CycloneDX if npm);
   - G.sources.

10. run_graph, generic first:
    - edges from Syft artifactRelationships (dependency-of / contains between packages), root
      = the project, root → direct;
    - for npm with v1: merge in v1 graph.json edges and their lockfile evidence;
    - direct packages whose transitives Syft doesn't give (e.g. a plain requirements.txt):
      resolve them with the deps.dev API (contract §0). Pinned version → its :dependencies
      graph; unpinned → use deps.dev's default version and label it "version assumed".
      - mark those edges source_tool "deps.dev";
      - cache in .cache/depsdev/;
      - concurrency 8;
      - GUARDIAN_OFFLINE=1 → cache only, otherwise "not resolved".
      Whatever is still unresolved attaches to the root with edge kind "declared" and a "not
      resolved" chip. Never resolve by installing anything;
    - nodes with ecosystem, direct, dev, depth, fan_in;
    - edges with evidence (manifest/lockfile path and line where known, the source tool);
    - up to 3 shortest paths from the root per node;
    - stats: max depth, top-20 most depended-on, duplicate versions.
    pages/graph.js:
    - tabs All / Direct / Transitive / Statistics, plus an ecosystem selector (one graph per
      ecosystem by default);
    - a banner when transitives weren't resolved for an ecosystem;
    - vis-network graph; above 600 nodes, start with direct dependencies plus their counts and
      expand on click;
    - search box; dev/prod filter;
    - colour nodes red or amber if M2's vulns/signals results exist (read
      G.api(`/api/ws/${id}/stages/vulns`), ignore if not run);
    - node side panel: paths from the root (`app → a → b → c`), evidence, licence;
    - G.sources.

11. pages/start.js:
    - form: kind (git URL / local path / zip upload), value, ref, "Your name (consent)",
      checkbox "I am authorised to analyse this repository";
    - Create workspace, then the buttons "Run discovery (1–3)", "Run detection (1–7)" and
      "Run everything up to remedies (1–8)";
    - a live list of stage statuses;
    - a short "how Guardian works" box with the 10 stages and who decides (code / AI / human).
    Zip upload: add POST /api/ws/upload (multipart) in routes_core.py.

Acceptance (T+75, integration 1):
- `python -m guardian ui`.
- The Python test repo runs 1–3: the SBOM page lists pypi components from Syft; the graph shows
  direct packages, transitive packages where the lockfile gives them, and the "not resolved"
  banner otherwise.
- Create a workspace from a local path to a small npm repo with a package-lock.json (e.g. a
  copy of ./target), run 1–3. The SBOM page shows tiles, the cross-check (Syft "not run" if not
  installed, never 0) and the components table. The graph shows a transitive package's full
  path from the root with evidence. Every Source files link opens a real file.
- `python -m pytest -q` passes.
- Commit "[M1] stages 1-3 and pages", pull --rebase, push.

After T+75: help whoever is behind with integration bugs in your own files only; at T+100 do
the final end-to-end run on the demo repo and take screenshots for docs/screenshots/v2/.
```
