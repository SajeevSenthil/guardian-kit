"""Stage 3 - Dependency graph: edges from Syft, the v1 lockfile parser, manifests and deps.dev; BFS paths.

Page: guardian/api/static/pages/s03_graph.js · Output: stages/graph/result.json
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..identity import norm_name, norm_purl, norm_version
from ..tools import KIT
from ..workspace import Workspace
from .s01_ingest import _cfg_sources

DEPSDEV_SYSTEM = {"npm": "npm", "pypi": "pypi", "golang": "go", "maven": "maven", "cargo": "cargo", "nuget": "nuget"}


def _cache_dir() -> Path:
    d = KIT / ".cache" / "depsdev"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _depsdev(url: str) -> dict | None:
    p = _cache_dir() / (hashlib.sha256(url.encode()).hexdigest()[:24] + ".json")
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))["data"]
    if os.environ.get("GUARDIAN_OFFLINE") == "1":
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "guardian"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None
    import datetime as dt
    p.write_text(json.dumps({"fetched": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), "url": url,
                             "data": data}), encoding="utf-8")
    return data


def depsdev_resolve(eco: str, name: str, version: str | None) -> dict | None:
    system = DEPSDEV_SYSTEM.get(eco)
    if not system:
        return None
    qn = urllib.parse.quote(name.replace("/", ":") if eco == "maven" else name, safe="")
    assumed = False
    if not version:
        pkg = _depsdev(f"https://api.deps.dev/v3/systems/{system}/packages/{qn}")
        vs = [v for v in (pkg or {}).get("versions", []) if v.get("isDefault")]
        if not vs:
            return None
        version, assumed = vs[0]["versionKey"]["version"], True
    data = _depsdev(f"https://api.deps.dev/v3/systems/{system}/packages/{qn}/versions/"
                    f"{urllib.parse.quote(version, safe='')}:dependencies")
    if not data or not data.get("nodes"):
        return None
    return {"version": version, "assumed": assumed, "nodes": data["nodes"], "edges": data.get("edges", []),
            "error": data.get("error")}


def _paths(adj: dict, root: str, k: int = 3, cap: int = 200000):
    """BFS depth + up to k shortest paths per node (over the shortest-path parent DAG)."""
    depth, parents = {root: 0}, collections.defaultdict(list)
    q = collections.deque([root])
    while q:
        u = q.popleft()
        for v in adj.get(u, ()):
            if v not in depth:
                depth[v] = depth[u] + 1
                parents[v].append(u)
                q.append(v)
            elif depth[v] == depth[u] + 1 and len(parents[v]) < k:
                parents[v].append(u)
    paths = {root: [[root]]}
    budget = cap
    for v in sorted(depth, key=depth.get):
        if v == root:
            continue
        acc = []
        for p in parents[v]:
            for pp in paths.get(p, []):
                acc.append(pp + [v])
                budget -= 1
                if len(acc) >= k or budget <= 0:
                    break
            if len(acc) >= k:
                break
        paths[v] = acc
    return depth, paths


def run_graph(ws: Workspace, opts: dict) -> dict:
    sb = ws.read("sbom")
    if not sb:
        raise RuntimeError("run the sbom stage first")
    ing = ws.read("ingest") or {}
    root = "root"
    nodes = {root: {"id": root, "name": Path(str(ing.get("source", {}).get("value", "project"))).name.removesuffix(".git")
                    or "project", "version": (ing.get("sha") or "")[:12], "ecosystem": "project", "kind": "root",
                    "direct": None, "dev": None}}
    for c in sb["components"]:
        nodes[c["id"]] = {"id": c["id"], "name": c["name"], "version": c["version"], "ecosystem": c["ecosystem"],
                          "kind": "pkg", "direct": c["direct"], "dev": c["dev"], "unpinned": c["unpinned"],
                          "licenses": c["licenses"], "purl": c["purl"], "in_sbom": True}
    edges: dict[tuple, dict] = {}

    def add_edge(a, b, source, kind="dependency", evidence=None):
        if a == b or a not in nodes or b not in nodes:
            return
        e = edges.setdefault((a, b), {"from": a, "to": b, "kind": kind, "sources": [], "evidence": []})
        if source not in e["sources"]:
            e["sources"].append(source)
        if evidence and evidence not in e["evidence"]:
            e["evidence"].append(evidence)

    # 1. root -> direct (manifest evidence)
    for c in sb["components"]:
        if c["direct"]:
            m = c.get("manifest") or {}
            ev = {"file": m.get("file") or (c["locations"] or [None])[0], "line": m.get("line"),
                  "excerpt": (f"{c['name']} {m.get('spec') or ''}").strip()}
            add_edge(root, c["id"], "manifest", "dev" if c["dev"] else "direct", ev)
    # 2. Syft relationships
    rel_path = ws.dir / sb["files"]["relationships"]
    rels = json.loads(rel_path.read_text(encoding="utf-8")) if rel_path.exists() else []
    for r in rels:
        add_edge(r["from"], r["to"], "syft", evidence={"file": r.get("file"), "line": None,
                                                       "excerpt": "Syft dependency-of relationship"})
    # 3. v1 npm edges with lockfile line evidence
    v1_status = "not-applicable"
    if ws.v1_run and (ws.v1_run / "graph.json").exists():
        g = json.loads((ws.v1_run / "graph.json").read_text(encoding="utf-8"))
        lock2id = {n["id"]: norm_purl(n["purl"]) for n in g["nodes"] if n.get("purl")}
        lock2id[""] = root
        lines = {n["id"]: n.get("lockLine") for n in g["nodes"]}
        for a, b in g["edges"]:
            ia, ib = lock2id.get(a), lock2id.get(b)
            if ia and ib:
                add_edge(ia, ib, "v1-lockfile", evidence={"file": "package-lock.json", "line": lines.get(b),
                                                          "excerpt": f'"{b}" (required by {"the project" if not a else a})'})
        v1_status = "ran"
    # 4. deps.dev for ecosystems whose transitive dependencies the files do not give
    has_out = collections.Counter(nodes[a]["ecosystem"] for (a, b) in edges if a != root)
    depsdev = {"status": "not-needed", "resolved": 0, "failed": 0, "assumed_versions": 0, "ecosystems": []}
    todo = [c for c in sb["components"] if c["direct"] and not has_out.get(c["ecosystem"])
            and c["ecosystem"] in DEPSDEV_SYSTEM]
    limit = int(_cfg_sources().get("max_depsdev_lookups", 150))
    if todo and not opts.get("no_depsdev"):
        depsdev["status"] = "ran" if os.environ.get("GUARDIAN_OFFLINE") != "1" else "cache-only (offline)"
        depsdev["ecosystems"] = sorted({c["ecosystem"] for c in todo})
        with ThreadPoolExecutor(8) as ex:
            res = list(ex.map(lambda c: (c, depsdev_resolve(c["ecosystem"], c["name"], c["version"])), todo[:limit]))
        depsdev["skipped_over_limit"] = max(0, len(todo) - limit)
        for c, r in res:
            if not r:
                depsdev["failed"] += 1
                nodes[c["id"]]["resolution"] = "not resolved"
                continue
            depsdev["resolved"] += 1
            depsdev["assumed_versions"] += r["assumed"]
            if r["assumed"]:
                nodes[c["id"]]["assumed_version"] = r["version"]
            idx = []
            for n in r["nodes"]:
                vk = n["versionKey"]
                if n.get("relation") == "SELF":
                    idx.append(c["id"])
                    continue
                nid = f"{c['ecosystem']}:{norm_name(c['ecosystem'], vk['name'])}@{vk['version']}"
                match = next((k for k, v in nodes.items() if v.get("ecosystem") == c["ecosystem"]
                              and norm_name(c["ecosystem"], v.get("name", "")) == norm_name(c["ecosystem"], vk["name"])
                              and norm_version(c["ecosystem"], v.get("version")) == norm_version(c["ecosystem"], vk["version"])),
                             None)
                if not match:
                    nodes[nid] = {"id": nid, "name": vk["name"], "version": vk["version"], "ecosystem": c["ecosystem"],
                                  "kind": "pkg", "direct": False, "dev": c["dev"], "unpinned": False, "licenses": [],
                                  "purl": None, "in_sbom": False, "resolved_by": "deps.dev"}
                idx.append(match or nid)
            for e in r["edges"]:
                a, b = idx[e["fromNode"]], idx[e["toNode"]]
                add_edge(a, b, "deps.dev", evidence={"file": None, "line": None,
                                                     "excerpt": f"deps.dev: requires {e.get('requirement', '')}".strip()})
    # 4b. packages no other package depends on are declared by the project in the file they were found in
    #     (e.g. GitHub Actions in a workflow, an extraneous lockfile entry): attach them to the root, labelled.
    comp_by_id = {c["id"]: c for c in sb["components"]}
    has_parent = {b for (_, b) in edges}
    for nid, n in nodes.items():
        if n["kind"] == "pkg" and nid not in has_parent:
            loc = ((comp_by_id.get(nid) or {}).get("locations") or [None])[0]
            add_edge(root, nid, "declared-in-file", "declared",
                     {"file": loc, "line": None, "excerpt": "listed in this file; no other package depends on it"})
            if n["direct"] is None:
                n["direct"] = True
    # 5. paths, depth, fan-in
    adj = collections.defaultdict(list)
    for (a, b) in edges:
        adj[a].append(b)
    depth, paths = _paths(adj, root)
    fan_in = collections.Counter(b for (_, b) in edges)
    for nid, n in nodes.items():
        n["depth"] = depth.get(nid)
        n["fan_in"] = fan_in.get(nid, 0)
        n["paths"] = paths.get(nid, [])
        n["cluster"] = n["paths"][0][1] if n["paths"] and len(n["paths"][0]) > 1 else nid
        if n["kind"] == "pkg" and n["direct"] is None and n["depth"] == 1:
            n["direct"] = True
        if n["kind"] == "pkg" and n["depth"] and n["depth"] > 1 and n["direct"] is None:
            n["direct"] = False
    unreachable = [nid for nid in nodes if nid not in depth]
    names = collections.defaultdict(set)
    for n in nodes.values():
        if n["kind"] == "pkg" and n["version"]:
            names[(n["ecosystem"], n["name"])].add(n["version"])
    eco_info = {}
    for eco in sorted({n["ecosystem"] for n in nodes.values() if n["kind"] == "pkg"}):
        srcs = collections.Counter(s for (a, b), e in edges.items() if nodes[b]["ecosystem"] == eco for s in e["sources"])
        eco_info[eco] = {"nodes": sum(1 for n in nodes.values() if n["ecosystem"] == eco),
                         "edge_sources": dict(srcs),
                         "transitives_resolved": bool(srcs.get("syft") or srcs.get("v1-lockfile") or srcs.get("deps.dev"))
                         or eco not in DEPSDEV_SYSTEM,  # actions, images...: nothing transitive to resolve
                         "not_resolved": sum(1 for n in nodes.values() if n["ecosystem"] == eco
                                             and n.get("resolution") == "not resolved")}
    stats = {"nodes": len(nodes) - 1, "edges": len(edges),
             "direct": sum(1 for n in nodes.values() if n["kind"] == "pkg" and n["direct"]),
             "transitive": sum(1 for n in nodes.values() if n["kind"] == "pkg" and n["direct"] is False),
             "max_depth": max(depth.values()) if depth else 0,
             "not_connected": len([u for u in unreachable if u != root]),
             "top_depended_on": [{"id": k, "name": nodes[k]["name"], "version": nodes[k]["version"], "fan_in": v}
                                 for k, v in fan_in.most_common(20) if k != root],
             "duplicate_versions": sorted([{"ecosystem": e, "name": n, "versions": sorted(v)}
                                           for (e, n), v in names.items() if len(v) > 1],
                                          key=lambda x: -len(x["versions"]))[:50],
             "cycles": "not computed"}
    result = {"root": root, "nodes": list(nodes.values()), "edges": list(edges.values()), "stats": stats,
              "ecosystems": eco_info, "sources": {"syft": len(rels), "v1_npm": v1_status, "deps.dev": depsdev},
              "note": "Edges come from tools: Syft relationships, the v1 package-lock parser (with line evidence) "
                      "and the deps.dev resolver (labelled; a real install can differ). Nothing was installed."}
    ws.write("graph", result)
    return {"nodes": stats["nodes"], "edges": stats["edges"], "direct": stats["direct"],
            "transitive": stats["transitive"], "max_depth": stats["max_depth"],
            "depsdev": depsdev["status"], "v1_npm": v1_status}
