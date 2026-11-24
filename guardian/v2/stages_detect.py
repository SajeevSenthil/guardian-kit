"""Stages 4-7 (M2): vulns, signals, prioritise, investigate. Any ecosystem.

Tools detect (OSV-Scanner, Grype, v1's OSV querybatch for npm); code merges, scores and explains;
agents (v1 runner, npm deep layer) add INFERRED judgement only. Unknown is never zero: a tool that
did not run is "not-run" on every row, never "not reported".
"""

from __future__ import annotations

import collections
import json
import os
import re
import subprocess
from pathlib import Path

from .. import enrich, scoring
from ..config import load as load_cfg
from ..cvss import base_score
from . import bridge
from .stages_discover import norm_name, norm_purl, norm_version, purl_type
from .tools import KIT, find_tool, tool_version
from .workspace import Workspace

GRYPE_DB = KIT / ".cache" / "grype"
# files OSV-Scanner can parse (passed one by one with -L: directory walking fails on Windows builds)
OSV_PARSABLE = re.compile(r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|"
                          r"poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock|go\.mod|Cargo\.lock|Gemfile\.lock|composer\.lock|"
                          r"pom\.xml|gradle\.lockfile|packages\.lock\.json|mix\.lock|pubspec\.lock|conan\.lock)$")
SEV_ORDER = ["critical", "high", "medium", "low", "unknown"]
GHSA_BUCKET = {"critical": 0.95, "high": 0.8, "medium": 0.55, "low": 0.25}


def _run(cmd, cwd=None, timeout=600, env=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, env={**os.environ, **(env or {})})


def _offline() -> bool:
    return os.environ.get("GUARDIAN_OFFLINE") == "1"


def _sev_label(score: float | None, label: str | None) -> str:
    if score is not None:
        return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "unknown"
    lab = (label or "").strip().lower()
    return {"moderate": "medium", "negligible": "low"}.get(lab, lab if lab in SEV_ORDER else "unknown")


def _best_cvss(vectors: list[str]) -> tuple[float | None, str | None]:
    best = (None, None)
    for v in vectors or []:
        r = base_score(v) if v and v.startswith("CVSS:3") else None
        if r and (best[0] is None or r[0] > best[0]):
            best = (r[0], v)
    return best


def _primary(ids: set[str]) -> str:
    for p in ("GHSA-", "CVE-", "PYSEC-", "GO-", "RUSTSEC-"):
        c = sorted(i for i in ids if i.startswith(p))
        if c:
            return c[0]
    return sorted(ids)[0]


# ---------------------------------------------------------------- tool adapters (pure: dict in, records out)
def records_from_osv_scanner(d: dict) -> list[dict]:
    out = []
    for res in d.get("results") or []:
        src = (res.get("source") or {}).get("path", "")
        for p in res.get("packages") or []:
            pk = p.get("package") or {}
            groups = p.get("groups") or []
            for v in p.get("vulnerabilities") or []:
                ids = {v["id"], *(v.get("aliases") or [])}
                g = next((g for g in groups if v["id"] in (g.get("ids") or [])), {})
                vectors = [s.get("score") for s in v.get("severity") or [] if str(s.get("type", "")).startswith("CVSS_V3")]
                fixed = []
                for a in v.get("affected") or []:
                    if norm_name(_eco(pk.get("purl"), pk.get("ecosystem")), (a.get("package") or {}).get("name", "")) != \
                            norm_name(_eco(pk.get("purl"), pk.get("ecosystem")), pk.get("name", "")):
                        continue
                    for r in a.get("ranges") or []:
                        if r.get("type") in ("ECOSYSTEM", "SEMVER"):
                            fixed += [e["fixed"] for e in r.get("events") or [] if "fixed" in e]
                try:
                    gmax = float(g.get("max_severity")) if g.get("max_severity") else None
                except ValueError:
                    gmax = None
                out.append({"tool": "osv_scanner", "purl": pk.get("purl"), "name": pk.get("name"), "version": pk.get("version"),
                            "ecosystem": _eco(pk.get("purl"), pk.get("ecosystem")), "ids": ids,
                            "summary": v.get("summary") or (v.get("details") or "").strip().split("\n")[0][:240],
                            "vectors": vectors, "label": (v.get("database_specific") or {}).get("severity"),
                            "score_hint": gmax, "fixed": sorted(set(fixed)), "file": src,
                            "refs": [r.get("url") for r in v.get("references") or []][:5]})
    return out


def records_from_grype(d: dict) -> list[dict]:
    out = []
    for m in d.get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        ids = {v.get("id"), *[r.get("id") for r in m.get("relatedVulnerabilities") or []]} - {None}
        vectors = [c.get("vector") for c in v.get("cvss") or [] if str(c.get("vector", "")).startswith("CVSS:3")]
        vectors += [c.get("vector") for r in m.get("relatedVulnerabilities") or [] for c in r.get("cvss") or []
                    if str(c.get("vector", "")).startswith("CVSS:3")]
        epss = max((e.get("epss", 0) for e in v.get("epss") or []), default=None)
        out.append({"tool": "grype", "purl": a.get("purl"), "name": a.get("name"), "version": a.get("version"),
                    "ecosystem": _eco(a.get("purl"), a.get("type")), "ids": ids,
                    "summary": (v.get("description") or "").strip().split("\n")[0][:240], "vectors": vectors,
                    "label": v.get("severity"), "score_hint": None, "fixed": (v.get("fix") or {}).get("versions") or [],
                    "file": ((a.get("locations") or [{}])[0]).get("path"), "refs": (v.get("urls") or [])[:5],
                    "grype_epss": epss})
    return out


def records_from_v1(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        if f.get("type") != "known_vulnerability":
            continue
        out.append({"tool": "v1_osv", "purl": f["component"], "name": None, "version": f.get("installed_version"),
                    "ecosystem": purl_type(f["component"]), "ids": {f["advisory"], *(f.get("aliases") or [])},
                    "summary": re.sub(r"^\S+\s+", "", f.get("title", "")), "vectors": [f["cvss"]] if f.get("cvss") else [],
                    "label": f.get("severity"), "score_hint": None, "fixed": f.get("fixed") or [],
                    "file": "package-lock.json", "refs": [], "v1_id": f["id"],
                    "lock_line": next((e.get("line") for e in f.get("evidence", []) if e.get("line")), None)})
    return out


def _eco(purl: str | None, fallback: str | None) -> str:
    t = purl_type(purl or "")
    if t != "unknown":
        return t
    return {"pypi": "pypi", "npm": "npm", "go": "golang", "crates.io": "cargo", "maven": "maven", "rubygems": "gem",
            "packagist": "composer", "nuget": "nuget", "python": "pypi", "java-archive": "maven",
            "rust-crate": "cargo", "gem": "gem"}.get((fallback or "").lower(), (fallback or "unknown").lower())


def merge(records: list[dict], comps: list[dict], tools_ran: dict) -> list[dict]:
    """One row per (component, advisory). Advisory identity = union of alias sets (CVE/GHSA/PYSEC/...)."""
    by_purl = {c["id"]: c for c in comps}
    by_nv = {(c["ecosystem"], norm_name(c["ecosystem"], c["name"]), norm_version(c["ecosystem"], c["version"])): c
             for c in comps if c["version"]}

    def comp_of(r):
        if r.get("purl") and norm_purl(r["purl"]) in by_purl:
            return by_purl[norm_purl(r["purl"])]
        name = r.get("name") or re.sub(r"@.*$", "", (r.get("purl") or "").split("/", 1)[-1])
        return by_nv.get((r["ecosystem"], norm_name(r["ecosystem"], name), norm_version(r["ecosystem"], r.get("version"))))

    groups: dict[str, list[list]] = collections.defaultdict(list)  # component id -> [[ids set, [records]]]
    for r in records:
        c = comp_of(r)
        cid = c["id"] if c else (norm_purl(r["purl"]) if r.get("purl") else f"{r['ecosystem']}:{r.get('name')}@{r.get('version')}")
        r["component_id"], r["_comp"] = cid, c
        bucket = groups[cid]
        hit = [g for g in bucket if g[0] & r["ids"]]
        if hit:
            g0 = hit[0]
            for g in hit[1:]:
                g0[0] |= g[0]
                g0[1] += g[1]
                bucket.remove(g)
            g0[0] |= r["ids"]
            g0[1].append(r)
        else:
            bucket.append([set(r["ids"]), [r]])
    rows = []
    for cid, bucket in groups.items():
        for ids, recs in bucket:
            c = recs[0]["_comp"]
            vectors = [v for r in recs for v in r["vectors"]]
            score, vector = _best_cvss(vectors)
            hint = max((r["score_hint"] for r in recs if r["score_hint"] is not None), default=None)
            labels = [r["label"] for r in recs if r.get("label")]
            sev = _sev_label(score if score is not None else hint, labels[0] if labels else None)
            eco = (c or {}).get("ecosystem") or recs[0]["ecosystem"]
            by_tool = {r["tool"] for r in recs}
            rep = {}
            for t, st in tools_ran.items():
                ran_for_eco = st["status"] == "ran" and (eco in st.get("ecosystems", [eco]))
                rep[t] = True if t in by_tool else (False if ran_for_eco else ("not-applicable" if st["status"] == "not-applicable"
                                                                               or eco not in st.get("ecosystems", [eco]) else "not-run"))
            fixed = sorted({f for r in recs for f in r["fixed"]}, key=_vkey)
            rows.append({
                "id": None, "component_id": cid, "ecosystem": eco,
                "name": (c or {}).get("name") or recs[0].get("name") or cid, "version": (c or {}).get("version") or recs[0].get("version"),
                "purl": (c or {}).get("purl") or recs[0].get("purl"), "in_sbom": bool(c),
                "advisory": _primary(ids), "aliases": sorted(ids - {_primary(ids)}),
                "cves": sorted(i for i in ids if i.startswith("CVE-")),
                "summary": next((r["summary"] for r in recs if r["summary"]), ""),
                "severity": sev, "cvss_score": score if score is not None else hint, "cvss_vector": vector,
                "severity_source": "CVSS v3 vector" if score is not None else ("OSV group max CVSS" if hint is not None
                                                                              else ("database label" if labels else "unknown")),
                "fixed": fixed, "reported_by": rep,
                "disagreement": any(v is False for v in rep.values()),
                "direct": (c or {}).get("direct"), "dev": (c or {}).get("dev"),
                "files": sorted({r["file"] for r in recs if r.get("file")}),
                "references": sorted({u for r in recs for u in r["refs"] if u})[:6],
                "v1_ids": sorted({r["v1_id"] for r in recs if r.get("v1_id")}),
                "lock_line": next((r["lock_line"] for r in recs if r.get("lock_line")), None),
                "grype_epss": max((r["grype_epss"] for r in recs if r.get("grype_epss") is not None), default=None),
            })
    rows.sort(key=lambda r: (SEV_ORDER.index(r["severity"]), -(r["cvss_score"] or 0), r["name"]))
    for i, r in enumerate(rows, 1):
        r["id"] = f"V{i:04d}"
    return rows


def _vkey(v: str):
    return [int(x) if x.isdigit() else x for x in re.split(r"[.\-+]", v or "")]


# ---------------------------------------------------------------- stage 4: vulns
def _osv_targets(ing: dict) -> list[tuple[str, str]]:
    """(ecosystem, relative file) OSV-Scanner should read. Prefer lockfiles; fall back to parsable manifests."""
    out = []
    for eco, d in (ing.get("ecosystems") or {}).items():
        files = [f for f in d["lockfiles"] if OSV_PARSABLE.search(f)] or [f for f in d["manifests"] if OSV_PARSABLE.search(f)]
        out += [(eco, f) for f in files]
    return out


def run_osv_scanner(ws: Workspace, out_dir: Path) -> dict:
    exe = find_tool("osv-scanner")
    if not exe:
        return {"status": "not-run", "reason": "osv-scanner not installed (python scripts/setup_tools.py)"}
    targets = _osv_targets(ws.read("ingest") or {})
    if not targets:
        return {"status": "not-applicable", "reason": "no lockfile or manifest OSV-Scanner can read", "ecosystems": []}
    if _offline():
        return {"status": "not-run", "reason": "offline (GUARDIAN_OFFLINE=1): OSV-Scanner queries api.osv.dev"}
    cmd = [exe, "scan", "source", "--format", "json"]
    for _, f in targets:
        name = Path(f).name
        cmd += ["-L", (f"requirements.txt:{f}" if name.startswith("requirements") else f)]
    r = _run(cmd, cwd=ws.src, timeout=600)
    if r.returncode not in (0, 1) or not r.stdout.strip():
        return {"status": "failed", "reason": f"exit {r.returncode}: {(r.stderr or '').strip()[-300:]}",
                "ecosystems": sorted({e for e, _ in targets})}
    (out_dir / "osv-scanner.json").write_text(r.stdout, encoding="utf-8")
    shown = " ".join(["osv-scanner"] + cmd[1:])
    return {"status": "ran", "version": tool_version("osv-scanner"), "command": shown, "exit": r.returncode,
            "files": [f for _, f in targets], "ecosystems": sorted({e for e, _ in targets}),
            "raw": ws.rel(out_dir / "osv-scanner.json")}


def run_grype(ws: Workspace, out_dir: Path) -> dict:
    exe = find_tool("grype")
    sbom = ws.dir / "stages" / "sbom" / "syft.cdx.json"
    if not exe:
        return {"status": "not-run", "reason": "grype not installed (python scripts/setup_tools.py)"}
    if not sbom.exists():
        return {"status": "not-run", "reason": "no Syft SBOM (run stage 2)"}
    GRYPE_DB.mkdir(parents=True, exist_ok=True)
    env = {"GRYPE_DB_CACHE_DIR": str(GRYPE_DB), "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    if _offline():
        env["GRYPE_DB_AUTO_UPDATE"] = "false"
    r = _run([exe, f"sbom:{sbom}", "-o", "json", "-q"], timeout=900, env=env)
    if r.returncode not in (0, 1) or not r.stdout.strip():
        return {"status": "failed", "reason": f"exit {r.returncode}: {(r.stderr or '').strip()[-300:]}"}
    (out_dir / "grype.json").write_text(r.stdout, encoding="utf-8")
    db = (json.loads(r.stdout).get("descriptor") or {}).get("db") or {}
    sb = ws.read("sbom") or {}
    return {"status": "ran", "version": tool_version("grype"), "command": "grype sbom:stages/sbom/syft.cdx.json -o json",
            "db_built": db.get("built"), "ecosystems": sorted((sb.get("totals") or {}).get("ecosystems", {})),
            "raw": ws.rel(out_dir / "grype.json")}


def run_vulns(ws: Workspace, opts: dict) -> dict:
    out = ws.stage_dir("vulns")
    sb = ws.read("sbom") or {}
    comps = sb.get("components") or []
    tools, records = {}, []
    tools["osv_scanner"] = run_osv_scanner(ws, out)
    if tools["osv_scanner"]["status"] == "ran":
        records += records_from_osv_scanner(json.loads((out / "osv-scanner.json").read_text(encoding="utf-8")))
    tools["grype"] = run_grype(ws, out)
    if tools["grype"]["status"] == "ran":
        records += records_from_grype(json.loads((out / "grype.json").read_text(encoding="utf-8")))
    if ws.v1_run and (ws.v1_run / "findings.json").exists():
        fj = json.loads((ws.v1_run / "findings.json").read_text(encoding="utf-8"))
        records += records_from_v1(fj["findings"] if isinstance(fj, dict) else fj)
        osv = ((json.loads((ws.v1_run / "graph.json").read_text(encoding="utf-8")).get("meta") or {}).get("osv") or {})
        tools["v1_osv"] = {"status": "ran" if osv.get("status") == "evaluated" else "not-run", "version": "v1 fast path",
                           "command": "OSV querybatch on package-lock.json (v1)", "ecosystems": ["npm"],
                           "reason": None if osv.get("status") == "evaluated" else f"OSV {osv.get('status')}",
                           "raw": ws.rel(ws.v1_run / "findings.json")}
    else:
        tools["v1_osv"] = {"status": "not-applicable", "reason": "npm deep layer only (no package-lock.json)", "ecosystems": []}
    rows = merge(records, comps, tools)

    # exploitability enrichment (cached; offline -> "not evaluated")
    cves = sorted({c for r in rows for c in r["cves"]})
    epss, epss_status = enrich.epss(cves) if cves else ({}, {"status": "not needed"})
    kev, kev_status = enrich.kev()
    for r in rows:
        sc = [(epss[c]["epss"], c) for c in r["cves"] if c in epss]
        r["epss"] = {"score": max(sc)[0], "cve": max(sc)[1], "percentile": epss[max(sc)[1]].get("percentile")} if sc else None
        r["kev"] = None if kev is None else next(({"cve": c, "dateAdded": kev[c].get("dateAdded")} for c in r["cves"] if c in kev), False)

    # graph context (stage 3 may or may not have run; vulns only needs the SBOM)
    g = ws.read("graph")
    if g:
        names = {n["id"]: n["name"] for n in g["nodes"]}
        gn = {n["id"]: n for n in g["nodes"]}
        for r in rows:
            n = gn.get(r["component_id"])
            if n:
                r["depth"] = n.get("depth")
                r["introduced_via"] = [[names.get(x, x) for x in p] for p in (n.get("paths") or [])[:2]]
                if r["direct"] is None:
                    r["direct"] = n.get("direct")
    unpinned = [{"component_id": c["id"], "ecosystem": c["ecosystem"], "name": c["name"], "declared": c.get("declared"),
                 "file": (c.get("manifest") or {}).get("file") or (c["locations"] or [None])[0]}
                for c in comps if not c.get("version")]
    sev = collections.Counter(r["severity"] for r in rows)
    agree = collections.Counter(("all" if not r["disagreement"] else
                                 "one" if sum(v is True for v in r["reported_by"].values()) == 1 else "some") for r in rows)
    result = {"rows": rows, "tools": tools, "unpinned": unpinned,
              "enrichment": {"epss": epss_status, "kev": kev_status},
              "counts": {"rows": len(rows), "by_severity": {k: sev.get(k, 0) for k in SEV_ORDER},
                         "by_ecosystem": dict(collections.Counter(r["ecosystem"] for r in rows)),
                         "unique_advisories": len({r["advisory"] for r in rows}),
                         "affected_packages": len({r["component_id"] for r in rows}), "agreement": dict(agree),
                         "kev": sum(1 for r in rows if r["kev"]), "unpinned": len(unpinned)},
              "note": "Rows are merged across tools by alias (CVE/GHSA/PYSEC/...). 'not-run' means the tool did not "
                      "look at this ecosystem; it is never counted as 'not vulnerable'."}
    ws.write("vulns", result)
    ran = [k for k, v in tools.items() if v["status"] == "ran"]
    return {"advisories": len(rows), "critical": sev.get("critical", 0), "high": sev.get("high", 0),
            "packages": result["counts"]["affected_packages"], "tools_ran": ", ".join(ran) or "none",
            "kev": result["counts"]["kev"], "unpinned": len(unpinned)}


# ---------------------------------------------------------------- stage 5: signals
WHY = {
    "unpinned_version": "Without an exact version, every install can pull a different (possibly hijacked) release; "
                        "the scanners cannot match it against advisories either.",
    "non_registry_source": "Code fetched from a git URL, tarball URL or local path bypasses the registry's integrity "
                           "and audit trail.",
    "custom_index": "An extra or custom package index allows dependency confusion: a public package with your "
                    "internal name can win the resolution.",
    "no_lockfile": "Without a lockfile, transitive versions float: the build you test is not the build you ship.",
    "docker_latest": "A floating base image tag changes underneath you; pin a version and digest.",
    "docker_curl_pipe": "Piping a downloaded script into a shell runs unreviewed remote code during the build.",
    "ci_unpinned_action": "A tag can be moved to malicious code (tj-actions, 2025); pin third-party actions to a commit SHA.",
    "ci_write_all": "Every step (and every action) gets a token that can push code and releases.",
    "ci_curl_pipe": "Remote script executed in CI with the job's credentials.",
    "ci_pull_request_target": "pull_request_target runs with secrets; checking out the PR's code lets a fork run it.",
}


def _lines(p: Path):
    try:
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def repo_signals(src: Path, ing: dict) -> list[dict]:
    out = []

    def add(rule, title, file, line, excerpt, risk, category, grade="verified", component=None):
        out.append({"rule": rule, "title": title, "category": category, "risk": risk, "grade": grade,
                    "component": component or file, "component_id": None,
                    "evidence": [{"file": file, "line": line, "excerpt": excerpt.strip()[:200]}], "why": WHY[rule], "source": "v2-rules"})

    for f in ing.get("dockerfiles") or []:
        for i, ln in enumerate(_lines(src / f), 1):
            m = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", ln, re.I)
            if m and "@sha256:" not in m.group(1) and m.group(1).lower() != "scratch":
                img = m.group(1)
                tag = img.rsplit(":", 1)[1] if ":" in img.split("/")[-1] else None
                if tag in (None, "latest"):
                    add("docker_latest", f"base image {img} is floating ({'no tag' if not tag else ':latest'})", f, i, ln, "medium", "container")
            if re.search(r"(curl|wget)[^|\n]*\|\s*(ba|z)?sh\b", ln):
                add("docker_curl_pipe", "Dockerfile pipes a downloaded script into a shell", f, i, ln, "high", "container")
    for f in ing.get("workflows") or []:
        lines = _lines(src / f)
        text = "\n".join(lines)
        for i, ln in enumerate(lines, 1):
            m = re.search(r"uses:\s*([\w.\-]+/[\w.\-/]+)@([\w.\-/]+)", ln)
            if m and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)) and not m.group(1).startswith(("actions/", "github/")):
                add("ci_unpinned_action", f"third-party action {m.group(1)}@{m.group(2)} is not pinned to a commit", f, i, ln,
                    "medium", "ci", component=f"{m.group(1)}@{m.group(2)}")
            if re.search(r"permissions:\s*write-all", ln):
                add("ci_write_all", "workflow token has write-all permissions", f, i, ln, "high", "ci")
            if re.search(r"(curl|wget)[^|\n]*\|\s*(ba|z)?sh\b", ln):
                add("ci_curl_pipe", "workflow pipes a remote script into a shell", f, i, ln, "high", "ci")
        if "pull_request_target" in text and re.search(r"actions/checkout", text) and re.search(r"github\.event\.pull_request\.head", text):
            i = next(k for k, ln in enumerate(lines, 1) if "pull_request_target" in ln)
            add("ci_pull_request_target", "pull_request_target workflow checks out the pull request's code", f, i,
                lines[i - 1], "high", "ci")
    return out


def manifest_signals(src: Path, ing: dict, comps: list[dict]) -> list[dict]:
    out = []

    def add(rule, title, file, line, excerpt, risk, grade="verified", component=None, component_id=None):
        out.append({"rule": rule, "title": title, "category": "manifest", "risk": risk, "grade": grade,
                    "component": component or file, "component_id": component_id,
                    "evidence": [{"file": file, "line": line, "excerpt": (excerpt or "").strip()[:200]}],
                    "why": WHY[rule], "source": "v2-rules"})

    for c in comps:
        if not c.get("version") and c["ecosystem"] not in ("github", "github-action"):
            m = c.get("manifest") or {}
            add("unpinned_version", f"{c['name']} has no exact version ({c.get('declared') or 'any'})",
                m.get("file") or (c["locations"] or [""])[0], m.get("line"), f"{c['name']} {c.get('declared') or ''}",
                "low", component=c["name"], component_id=c["id"])
    for eco, d in (ing.get("ecosystems") or {}).items():
        for f in d["manifests"]:
            p = src / f
            lines = _lines(p)
            if Path(f).name.startswith("requirements") or Path(f).name in ("pip.conf", "pip.ini"):
                for i, ln in enumerate(lines, 1):
                    s = ln.strip()
                    if re.match(r"^(-i|--index-url|--extra-index-url)\b", s):
                        add("custom_index", "pip is told to use another package index", f, i, s, "medium")
                    elif re.match(r"^(-e\s+)?(git\+|hg\+|svn\+|https?://|file:)", s) or " @ " in s and "://" in s:
                        add("non_registry_source", "dependency installed from a URL or VCS, not the registry", f, i, s, "medium")
            if Path(f).name == "package.json":
                try:
                    j = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    j = {}
                for sec in ("dependencies", "devDependencies", "optionalDependencies"):
                    for n, v in (j.get(sec) or {}).items():
                        if re.match(r"^(git\+|git:|github:|https?://|file:|link:)|^[\w-]+/[\w.-]+(#.*)?$", str(v)):
                            ln = next((k for k, x in enumerate(lines, 1) if f'"{n}"' in x), None)
                            add("non_registry_source", f"{n} is installed from {v}", f, ln, f'"{n}": "{v}"', "medium", component=n)
        if d.get("pinned") in ("no lockfile", "partly or not pinned") and eco not in ("golang",):
            add("no_lockfile", f"{eco}: no lockfile ({d.get('pinned')})", (d["manifests"] or ["?"])[0], None,
                ", ".join(d["manifests"][:3]), "low", grade="verified", component=eco)
    for f in (".npmrc", "pip.conf", ".pypirc"):
        for i, ln in enumerate(_lines(src / f), 1):
            if re.match(r"^\s*(registry|index-url|extra-index-url)\s*=", ln):
                add("custom_index", f"{f} points at a custom registry", f, i, ln, "medium")
    return out


def run_signals(ws: Workspace, opts: dict) -> dict:
    ing, sb = ws.read("ingest") or {}, ws.read("sbom") or {}
    sigs = []
    v1_types = set()
    if ws.v1_run and (ws.v1_run / "findings.json").exists():
        fj = json.loads((ws.v1_run / "findings.json").read_text(encoding="utf-8"))
        for f in (fj["findings"] if isinstance(fj, dict) else fj):
            if f["type"] == "known_vulnerability":
                continue
            v1_types.add(f["type"])
            sigs.append({"rule": f["type"], "title": f.get("title"), "category": f.get("category"), "risk": f.get("risk"),
                         "grade": f.get("claim", "verified"), "component": f.get("component"),
                         "component_id": norm_purl(f["component"]) if str(f.get("component", "")).startswith("pkg:") else None,
                         "evidence": [{"file": (e.get("source") or "").split(" @")[0], "line": e.get("line"),
                                       "excerpt": e.get("excerpt")} for e in f.get("evidence", [])],
                         "why": f.get("rule"), "source": "v1", "v1_id": f["id"]})
    # generic repo rules: v1 already checks Dockerfiles and workflows for npm repos, so run ours only otherwise
    if not ws.v1_run:
        sigs += repo_signals(ws.src, ing)
    sigs += manifest_signals(ws.src, ing, sb.get("components") or [])
    for i, s in enumerate(sigs, 1):
        s["id"] = f"S{i:03d}"
    cats = collections.Counter(s["category"] for s in sigs)
    risk = collections.Counter(s["risk"] for s in sigs)
    result = {"signals": sigs, "rows": sigs, "counts": {"total": len(sigs), "by_category": dict(cats), "by_risk": dict(risk)},
              "sources": {"v1_npm_rules": "ran" if ws.v1_run else "not-applicable", "v2_repo_rules": "not-needed (v1 ran)" if ws.v1_run else "ran",
                          "v2_manifest_rules": "ran", "deps.dev_scorecard": "not-run (not built yet)"},
              "note": "Signals are risks without a CVE, found by fixed rules on files (verified facts) or heuristics "
                      "(labelled). A package describing itself as harmless is not evidence."}
    ws.write("signals", result)
    return {"signals": len(sigs), "high": risk.get("high", 0) + risk.get("critical", 0), "categories": len(cats)}


# ---------------------------------------------------------------- stage 6: prioritise
FACTOR_LABEL = {"severity": "severity", "exploitability": "exploitability", "reachability": "reachability",
                "exposure": "exposure", "fix_availability": "fix availability"}
SIGNAL_SEVERITY = {"docker_curl_pipe": 0.7, "ci_curl_pipe": 0.7, "ci_write_all": 0.7, "ci_pull_request_target": 0.8,
                   "ci_unpinned_action": 0.5, "docker_latest": 0.4, "custom_index": 0.6, "non_registry_source": 0.6,
                   "unpinned_version": 0.3, "no_lockfile": 0.35}


def _generic_vuln_factors(r: dict, epss, epss_status, kev, cfg) -> tuple[dict, list]:
    from ..prioritise import _exploit_vuln, _fix_factor
    if r["cvss_score"] is not None:
        sev = scoring.factor(round(r["cvss_score"] / 10, 2), "verified", f"CVSS {r['cvss_score']} ({r['severity_source']})")
    else:
        sev = scoring.factor(GHSA_BUCKET.get(r["severity"]), "verified", f"database severity {r['severity']}")
    ex, is_kev = _exploit_vuln(r["cves"], epss, epss_status, kev)
    reach = scoring.factor(None, "unknown", f"static reachability is implemented for npm only; {r['ecosystem']} not analysed")
    if r.get("dev") is True:
        expo = scoring.factor(0.3, "verified", "dev/test dependency (from the manifest)")
    elif r.get("dev") is False:
        expo = (scoring.factor(1.0, "heuristic", "production dependency of an internet-facing service (guardian.toml)")
                if cfg["context"].get("internet_facing") else
                scoring.factor(0.6, "heuristic", "production dependency, internal service (guardian.toml)"))
    else:
        expo = scoring.factor(None, "unknown", "cannot tell from the files whether it ships to production")
    fix = _fix_factor({"installed_version": r["version"] or "0", "fixed": r["fixed"]})
    rails = [("KEV_FLOOR", "floor", 90, "listed in CISA KEV and reachability unknown")] if is_kev else []
    return {"severity": sev, "exploitability": ex, "reachability": reach, "exposure": expo, "fix_availability": fix}, rails


def _generic_signal_factors(s: dict, cfg) -> dict:
    rule = s["rule"]
    sev = scoring.factor(SIGNAL_SEVERITY.get(rule, 0.3), "heuristic", f"rubric value for rule `{rule}`")
    hostile = rule in ("docker_curl_pipe", "ci_curl_pipe", "ci_pull_request_target", "custom_index")
    ex = scoring.factor(0.6 if hostile else 0.3, "heuristic", "pattern abused in real attacks" if hostile else "hygiene issue, no hostile signal")
    if s["category"] == "ci":
        reach = scoring.factor(1.0, "verified", "runs on every workflow trigger")
        expo = scoring.factor(1.0, "heuristic", "CI runner holds repository credentials")
    elif s["category"] == "container":
        reach = scoring.factor(1.0, "verified", "the image is the runtime of the deployed app")
        expo = scoring.factor(0.6, "heuristic", "deployed container")
    else:
        reach = scoring.factor(0.5, "heuristic", "affects what gets installed")
        expo = scoring.factor(0.6, "heuristic", "build and install environment")
    return {"severity": sev, "exploitability": ex, "reachability": reach, "exposure": expo,
            "fix_availability": scoring.factor(1.0, "verified", "pin, remove or restrict is available")}


def _factor_rows(p: dict, weights: dict) -> list[dict]:
    rows = []
    for k in scoring.FACTORS if hasattr(scoring, "FACTORS") else ("severity", "exploitability", "reachability", "exposure", "fix_availability"):
        f = p["factors"][k]
        rows.append({"factor": k, "label": FACTOR_LABEL[k], "weight": weights[k], "value": f["value"], "grade": f["grade"],
                     "evidence": f["evidence"], "contribution": p["contributions"][k]})
    return rows


def why_text(item: dict) -> str:
    fr = sorted(item["factor_rows"], key=lambda r: -r["contribution"])[:2]
    parts = [f"{r['label']} ({r['value'] if r['value'] is not None else 'unknown, prior used'}: {r['evidence']})" for r in fr]
    s = f"Scored {item['score']}/100 ({item['band']}) mainly because of " + " and ".join(parts) + "."
    for g in item["guardrails"]:
        s += f" Guardrail {g['name']} {g['effect']}: {g['reason']}."
    return s


def vs_next_text(a: dict, b: dict | None) -> str | None:
    if not b:
        return None
    if a["score"] == b["score"]:
        if a["confidence"] != b["confidence"]:
            return (f"Same score as #{b['rank']} {b['title']}; listed first because its evidence is stronger "
                    f"(confidence {a['confidence']} vs {b['confidence']}).")
        return f"Tied with #{b['rank']} {b['title']} (same score and confidence); order between them is alphabetical."
    ca = {r["factor"]: r["contribution"] for r in a["factor_rows"]}
    cb = {r["factor"]: r["contribution"] for r in b["factor_rows"]}
    k = max(ca, key=lambda x: ca[x] - cb[x])
    d = round(ca[k] - cb[k], 1)
    rail = next((g for g in a["guardrails"] if g["name"] not in {x["name"] for x in b["guardrails"]}), None)
    s = (f"Ranks above #{b['rank']} ({b['score']}) mainly because its {FACTOR_LABEL[k]} adds {d:+} points "
         f"({ca[k]} vs {cb[k]}).")
    if rail:
        s += f" It also has guardrail {rail['name']} ({rail['effect']})."
    return s


def initial_vs_final(item: dict) -> str:
    ini = item.get("initial_severity") or "unknown"
    if ini == "unknown":
        return f"No published severity; Guardian ranks it {item['band']}."
    order = ["low", "medium", "high", "critical"]
    fb = item["band"] if item["band"] in order else "low"
    if ini not in order or order.index(fb) == order.index(ini):
        return f"Published as {ini}; Guardian agrees ({item['band']})."
    low = min(item["factor_rows"][1:], key=lambda r: r["contribution"] / max(r["weight"], 1))
    if order.index(fb) < order.index(ini):
        return (f"Published as {ini}, ranked {item['band']} here: {low['label']} pulls it down "
                f"({low['value'] if low['value'] is not None else 'unknown'}: {low['evidence']}).")
    top = max(item["factor_rows"][1:], key=lambda r: r["contribution"] / max(r["weight"], 1))
    return f"Published as {ini}, ranked {item['band']} here: {top['label']} raises it ({top['evidence']})."


def run_prioritise(ws: Workspace, opts: dict) -> dict:
    cfg = load_cfg()
    weights = cfg["score"]["weights"]
    vul, sig = ws.read("vulns") or {"rows": []}, ws.read("signals") or {"signals": []}
    items, v1_meta = [], None
    covered_v1 = set()
    if ws.v1_run:
        from .. import prioritise as v1p
        with bridge.use_target(ws):
            pr = v1p.prioritise(ws.v1_run)
        v1_meta = {"file": ws.rel(ws.v1_run / "prioritised.json"), "funnel": pr["funnel"], "epss": pr["meta"]["epss"],
                   "kev": pr["meta"]["kev"], "reachability_scan": pr["meta"]["reachability_scan"]}
        byid = {f["id"]: f for f in pr["findings"]}
        row_by_v1 = {v: r for r in vul["rows"] for v in r.get("v1_ids", [])}
        sig_by_v1 = {s.get("v1_id"): s for s in sig["signals"] if s.get("v1_id")}
        for fid in pr["ranking"]:
            f = byid[fid]
            p = f["priority"]
            row = row_by_v1.get(fid)
            is_v = f["type"] == "known_vulnerability"
            if row:
                covered_v1.add(row["id"])
            items.append({"kind": "vuln" if is_v else "signal", "ref": (row or {}).get("id") or (sig_by_v1.get(fid) or {}).get("id"),
                          "v1_id": fid, "title": (f"{f.get('advisory')} in {(row or {}).get('name') or f['component']}" if is_v else f.get("title")),
                          "component": f["component"], "component_id": norm_purl(f["component"]) if f["component"].startswith("pkg:") else None,
                          "ecosystem": purl_type(f["component"]) if f["component"].startswith("pkg:") else "repo",
                          "advisory": f.get("advisory"), "initial_severity": _sev_label(None, f.get("severity") or f.get("risk")),
                          "summary": (row or {}).get("summary") or f.get("title"), "priority": p,
                          "reachability": (f.get("reachability") or {}).get("tier"), "source": "v1 (npm deep layer)",
                          "agents": f.get("agents")})
    epss = kev = None
    cves = sorted({c for r in vul["rows"] for c in r["cves"]})
    epss, epss_status = enrich.epss(cves) if cves else ({}, {"status": "not needed"})
    kev, kev_status = enrich.kev()
    for r in vul["rows"]:
        if r["id"] in covered_v1 or any(v is True for k, v in r["reported_by"].items() if k == "v1_osv"):
            continue
        factors, rails = _generic_vuln_factors(r, epss, epss_status, kev, cfg)
        p = scoring.score(factors, rails, cfg)
        items.append({"kind": "vuln", "ref": r["id"], "title": f"{r['advisory']} in {r['name']} {r['version'] or ''}".strip(),
                      "component": r["purl"] or r["component_id"], "component_id": r["component_id"], "ecosystem": r["ecosystem"],
                      "advisory": r["advisory"], "initial_severity": r["severity"], "summary": r["summary"], "priority": p,
                      "reachability": None, "source": "generic (tools + formula)"})
    for s in sig["signals"]:
        if s.get("source") == "v1":
            continue  # already ranked by v1
        p = scoring.score(_generic_signal_factors(s, cfg), [], cfg)
        items.append({"kind": "signal", "ref": s["id"], "title": s["title"], "component": s["component"],
                      "component_id": s.get("component_id"), "ecosystem": "repo", "advisory": None,
                      "initial_severity": None, "summary": s["why"], "priority": p, "reachability": None,
                      "source": "generic (rules + formula)"})
    for it in items:
        p = it.pop("priority")
        it.update({"score": p["score"], "band": p["band"], "range": p["range"], "confidence": p["confidence"],
                   "guardrails": p["guardrails"], "unknown_factors": p["unknown_factors"],
                   "factor_rows": _factor_rows(p, weights)})
    items.sort(key=lambda x: (-x["score"], -x["confidence"], x["title"] or ""))
    for i, it in enumerate(items, 1):
        it["rank"] = i
    for i, it in enumerate(items):
        it["why"] = why_text(it)
        it["vs_next"] = vs_next_text(it, items[i + 1] if i + 1 < len(items) else None)
        it["initial_vs_final"] = initial_vs_final(it)
    demoted = [{"rank": it["rank"], "title": it["title"], "initial_severity": it["initial_severity"], "score": it["score"],
                "band": it["band"], "reason": it["initial_vs_final"]}
               for it in items if it["initial_severity"] in ("critical", "high") and it["score"] < 65][:50]
    bands = collections.Counter(it["band"] for it in items)
    ini = collections.Counter(it["initial_severity"] for it in items)
    result = {"items": items, "rows": [{"component_id": it["component_id"], "id": it["title"], "band": it["band"]} for it in items if it["component_id"]],
              "demoted": demoted, "weights": weights, "bands": cfg["score"]["bands"], "priors": cfg["score"]["priors"],
              "counts": {"items": len(items), "by_band": dict(bands), "initial": dict(ini),
                         "need_attention": bands.get("critical", 0) + bands.get("high", 0)},
              "enrichment": {"epss": epss_status, "kev": kev_status}, "v1": v1_meta,
              "formula": "score = 30·severity + 25·exploitability + 20·reachability + 15·exposure + 10·fix availability; "
                         "unknown factors use a prior, lower confidence and widen the range; guardrails apply after."}
    ws.write("prioritise", result)
    return {"ranked": len(items), "critical": bands.get("critical", 0), "high": bands.get("high", 0),
            "demoted": len(demoted), "deep_npm": bool(ws.v1_run)}


# ---------------------------------------------------------------- stage 7: investigate
def run_investigate(ws: Workspace, opts: dict) -> dict:
    from ..env import gemini_keys
    from ..report import AGENT_INFO, agents_view
    mode = "offline" if _offline() or opts.get("mode") == "offline" else "live"
    if mode == "live" and not gemini_keys():
        mode = "offline"
    top = int(opts.get("top") or 3)
    pri = ws.read("prioritise") or {"items": []}
    out = {"mode": mode, "top": top, "agents": [], "items": [], "provider": "gemini", "keys_configured": len(gemini_keys())}
    if ws.v1_run and (ws.v1_run / "prioritised.json").exists():
        from ..agents.runner import analyse
        with bridge.use_target(ws):
            stats = analyse(ws.v1_run, mode=mode, top_n=top)
        pr = json.loads((ws.v1_run / "prioritised.json").read_text(encoding="utf-8"))
        view = agents_view(pr, {}, ws.v1_run)
        out.update({"analysis": stats, "agents": view["agents"], "flow": view["flow"], "models": view["models"],
                    "tokens": view["tokens"], "quotes_kept": view["quotes_kept"], "quotes_dropped": view["quotes_dropped"],
                    "investigations": ws.rel(ws.v1_run / "investigations.json") if (ws.v1_run / "investigations.json").exists() else None,
                    "v1_prioritised": ws.rel(ws.v1_run / "prioritised.json")})
        # re-scored items may differ after the agents: keep the prioritise page honest by flagging it stale
    else:
        out["agents"] = [{"key": k, "name": n, "when": w, "method": m, "output": o, "how_code_uses_it": a, "tools": [],
                          "runs": {"ok": 0, "skipped": min(top, len(pri["items"]))},
                          "outputs": [{"finding": it["ref"], "component": it["component"], "status": "skipped",
                                       "reason": f"agents for {it['ecosystem']} are not built yet (npm deep layer only)"}
                                      for it in pri["items"][:top]] if k in ("risk_analyst", "refuter") else []}
                         for k, n, w, m, o, a in AGENT_INFO]
        out["flow"] = ["Agents run on the npm deep layer today. For this repo every agent step is shown as skipped; "
                       "the scores above do not depend on any AI."]
    ok = sum(a["runs"]["ok"] for a in out["agents"])
    skipped = sum(a["runs"]["skipped"] for a in out["agents"])
    ws.write("investigate", out)
    return {"mode": mode, "agent_runs_ok": ok, "skipped": skipped, "top": top}
