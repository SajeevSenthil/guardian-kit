"""Stage 4 - Vulnerabilities: OSV-Scanner + Grype (+ v1 OSV for npm), merged per (package, advisory) by alias.

Page: guardian/api/static/pages/s04_vulns.js · Output: stages/vulns/ (result.json, osv-scanner.json, grype.json)
"""

from __future__ import annotations

import collections
import json
import re
from pathlib import Path

from ... import enrich
from ...cvss import base_score
from ..identity import norm_name, norm_purl, norm_version, purl_type, vkey
from ..proc import offline
from ..proc import run as _run
from ..tools import KIT, find_tool, tool_version
from ..workspace import Workspace

GRYPE_DB = KIT / ".cache" / "grype"


# files OSV-Scanner can parse (passed one by one with -L: directory walking fails on Windows builds)
OSV_PARSABLE = re.compile(r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|"
                          r"poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock|go\.mod|Cargo\.lock|Gemfile\.lock|composer\.lock|"
                          r"pom\.xml|gradle\.lockfile|packages\.lock\.json|mix\.lock|pubspec\.lock|conan\.lock)$")


SEV_ORDER = ["critical", "high", "medium", "low", "unknown"]


GHSA_BUCKET = {"critical": 0.95, "high": 0.8, "medium": 0.55, "low": 0.25}


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
            fixed = sorted({f for r in recs for f in r["fixed"]}, key=vkey)
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
    if offline():
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
    if offline():
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
