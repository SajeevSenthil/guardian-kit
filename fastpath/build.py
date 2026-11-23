#!/usr/bin/env python3
"""Guardian fast path: one-shot evidence graph for ./target (stdlib only).

    python fastpath/build.py [--base guardian-baseline] [--head tampered] [--offline]

Reads ./target only through `git archive` (never modifies it), extracts both refs into a
temp dir, and writes fastpath/out/{findings.json, sbom.base.cdx.json, sbom.head.cdx.json,
sbom.diff.json, guardian.html}. Never executes code from scanned packages.
"""

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
TARGET = os.path.join(KIT, "target")
OUT = os.path.join(HERE, "out")
CACHE = os.path.join(HERE, ".cache", "osv")
REGISTRY = "https://registry.npmjs.org/"
OSV = "https://api.osv.dev/v1"

_spec = importlib.util.spec_from_file_location("lsd", os.path.join(KIT, "scripts", "lockfile_sbom_diff.py"))
lsd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lsd)


# ---------------------------------------------------------------- helpers
def git(*args):
    return subprocess.run(["git", "-C", TARGET, *args], capture_output=True, check=True).stdout


def extract(ref, dest):
    data = git("archive", ref)
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(dest, filter="data")
    return dest


def read(root, rel):
    p = os.path.join(root, rel)
    return open(p, encoding="utf-8", errors="replace").read() if os.path.exists(p) else None


def line_of(text, needle):
    for i, ln in enumerate(text.splitlines(), 1):
        if needle in ln:
            return i, ln.strip()
    return None, None


def introduced_by(base, head, path, text=None):
    """Oldest commit in base..head touching path (and adding `text`, if given)."""
    args = ["log", "--reverse", "--format=%h%x09%s"]
    if text:
        args += ["-S", text]
    args += ["%s..%s" % (base, head), "--", path]
    out = git(*args).decode("utf-8", "replace").strip().splitlines()
    if not out and text:
        return introduced_by(base, head, path)
    if not out:
        return None
    sha, subj = out[0].split("\t", 1)
    return {"sha": sha, "subject": subj}


def name_of(path):
    return path.split("node_modules/")[-1]


# ---------------------------------------------------------------- step 1: inventory
def inventory(root):
    lock = json.load(open(os.path.join(root, "package-lock.json"), encoding="utf-8"))
    lock_text = read(root, "package-lock.json")
    pk = lock["packages"]
    rootpkg = pk[""]
    prod_direct = set(rootpkg.get("dependencies", {}))
    dev_direct = set(rootpkg.get("devDependencies", {}))
    nodes, edges = {}, []
    nodes[""] = {"id": "", "name": lock.get("name", "app"), "version": lock.get("version", ""),
                 "kind": "app", "label": "%s (app)" % lock.get("name", "app")}
    for path, e in pk.items():
        if not path or e.get("link"):
            continue
        n = name_of(path)
        resolved = e.get("resolved", "")
        ln, _ = line_of(lock_text, '"%s": {' % path)
        nodes[path] = {
            "id": path, "name": n, "version": e.get("version", ""), "kind": "pkg",
            "dev": bool(e.get("dev")), "optional": bool(e.get("optional")),
            "direct": path == "node_modules/" + n and n in (prod_direct | dev_direct),
            "resolved": resolved, "registry": resolved.startswith(REGISTRY),
            "install": bool(e.get("hasInstallScript")), "integrity": e.get("integrity", ""),
            "lockLine": ln,
            "purl": "pkg:npm/%s@%s" % (n.replace("@", "%40", 1), e.get("version", "")),
        }
    for path, e in pk.items():
        if e.get("link") or path not in nodes:
            continue
        names = dict(e.get("dependencies", {}))
        names.update(e.get("optionalDependencies", {}))
        if not path:
            names.update(e.get("devDependencies", {}))
        for d in names:
            t = lsd._resolve(pk, path, d)
            if t and t in nodes:
                edges.append([path, t])
    # shortest dependency path from the root (BFS)
    adj = {}
    for a, b in edges:
        adj.setdefault(a, []).append(b)
    prev, q = {"": None}, deque([""])
    while q:
        cur = q.popleft()
        for nx in adj.get(cur, []):
            if nx not in prev:
                prev[nx] = cur
                q.append(nx)
    for nid, n in nodes.items():
        p, c = [], nid
        if nid not in prev:
            n["path"] = None
            continue
        while c is not None:
            p.append(c)
            c = prev[c]
        n["path"] = list(reversed(p))
    return {"lock": lock, "lock_text": lock_text, "nodes": nodes, "edges": edges,
            "decl": {**rootpkg.get("dependencies", {}), **rootpkg.get("devDependencies", {})}}


# ---------------------------------------------------------------- step 2: vulnerabilities (OSV)
def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def _get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def _cached(key, fn):
    os.makedirs(CACHE, exist_ok=True)
    p = os.path.join(CACHE, hashlib.sha256(key.encode()).hexdigest()[:24] + ".json")
    if os.path.exists(p):
        return json.load(open(p, encoding="utf-8"))
    if os.environ.get("GUARDIAN_OFFLINE") == "1":
        raise OSError("offline and not cached")
    data = fn()
    json.dump({"fetched": dt.datetime.now(dt.timezone.utc).isoformat(), "key": key, "data": data},
              open(p, "w", encoding="utf-8"))
    return {"fetched": "now", "key": key, "data": data}


def osv_scan(nodes):
    """Returns (status, {node_id: [vuln]}, details). status: evaluated | not evaluated."""
    pkgs = sorted({(n["name"], n["version"]) for n in nodes.values() if n["kind"] == "pkg" and n["registry"]})
    hits = {}
    try:
        for i in range(0, len(pkgs), 500):
            chunk = pkgs[i:i + 500]
            body = {"queries": [{"package": {"name": a, "ecosystem": "npm"}, "version": v} for a, v in chunk]}
            res = _cached("querybatch:" + json.dumps(body, sort_keys=True), lambda b=body: _post(OSV + "/querybatch", b))
            for (a, v), r in zip(chunk, res["data"]["results"]):
                if r.get("next_page_token"):
                    raise RuntimeError("paged OSV result for %s@%s not handled" % (a, v))
                hits[(a, v)] = [x["id"] for x in r.get("vulns", [])]
        ids = sorted({i for v in hits.values() for i in v})
        with cf.ThreadPoolExecutor(12) as ex:
            det = dict(zip(ids, ex.map(lambda i: _cached("vuln:" + i, lambda: _get(OSV + "/vulns/" + i)), ids)))
    except (OSError, urllib.error.URLError, RuntimeError, ValueError, KeyError) as e:
        return {"status": "not evaluated", "reason": "%s: %s" % (type(e).__name__, e)}, {}
    out = {}
    for nid, n in nodes.items():
        if n["kind"] != "pkg":
            continue
        if not n["registry"]:
            n["vulnStatus"] = "not evaluated (non-registry origin: OSV cannot match it)"
            continue
        n["vulnStatus"] = "evaluated"
        for vid in hits.get((n["name"], n["version"]), []):
            d = det[vid]["data"]
            sev = (d.get("database_specific") or {}).get("severity") or "UNKNOWN"
            sev = {"MODERATE": "MEDIUM"}.get(sev.upper(), sev.upper())
            fixed = []
            for a in d.get("affected", []):
                if a.get("package", {}).get("name") != n["name"]:
                    continue
                for r in a.get("ranges", []):
                    fixed += [ev["fixed"] for ev in r.get("events", []) if "fixed" in ev]
            cvss = [s.get("score") for s in d.get("severity", [])]
            out.setdefault(nid, []).append({
                "id": vid, "aliases": d.get("aliases", []), "summary": d.get("summary", ""),
                "severity": sev, "cvss": cvss[0] if cvss else None, "fixed": sorted(set(fixed)),
                "fetched": det[vid]["fetched"],
            })
    return {"status": "evaluated", "packages_queried": len(pkgs), "advisories": len(ids)}, out


def osv_action(name):
    """Advisories OSV knows for a GitHub Action (package-level query; version not matched)."""
    try:
        body = {"package": {"name": name, "ecosystem": "GitHub Actions"}}
        r = _cached("query:" + json.dumps(body, sort_keys=True), lambda: _post(OSV + "/query", body))
        return [{"id": v["id"], "aliases": v.get("aliases", []), "summary": v.get("summary", "")}
                for v in r["data"].get("vulns", [])]
    except (OSError, urllib.error.URLError, ValueError) as e:
        return None


# ---------------------------------------------------------------- step 3: suspicious changes
def osa(a, b, cap=3):
    """Optimal-string-alignment edit distance (transposition = 1)."""
    if abs(len(a) - len(b)) >= cap:
        return cap
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            c = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


SECRET_ENV = re.compile(r"process\.env|os\.environ", re.I)
SECRET_WORDS = re.compile(r"TOKEN|SECRET|PASSWORD|API_?KEY|\bKEY\b", re.I)
URL = re.compile(r"https?://[^\s'\"`)]+")
NET = re.compile(r"require\(['\"](https?|net|dns|child_process)['\"]\)|from ['\"](node:)?(https?|net|child_process)['\"]|fetch\(|exec\(|spawn\(")
TMP = re.compile(r"tmpdir\(\)|/tmp/|TEMP")
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")


def inspect_tarball(root, resolved):
    """Static read of a local file: tarball. Returns dict with scripts, files, signals."""
    if not resolved.startswith("file:"):
        return None
    rel = resolved[5:]
    p = os.path.join(root, rel)
    if not os.path.exists(p):
        return {"tarball": rel, "missing": True}
    info = {"tarball": rel, "size": os.path.getsize(p), "files": {}, "scripts": {}, "signals": []}
    with tarfile.open(p) as t:
        members = {m.name: m for m in t.getmembers() if m.isfile()}
        for name, m in members.items():
            info["files"][name] = m.size
        pj = members.get("package/package.json")
        if pj:
            ptext = t.extractfile(pj).read().decode("utf-8", "replace")
            meta = json.loads(ptext)
            for h in INSTALL_HOOKS:
                if h in meta.get("scripts", {}):
                    cmd = meta["scripts"][h]
                    ln, ex = line_of(ptext, '"%s"' % h)
                    info["scripts"][h] = {"cmd": cmd, "evidence": {"source": "%s!package/package.json" % rel, "line": ln, "excerpt": ex}}
                    for tok in cmd.split():
                        f = "package/" + tok.lstrip("./")
                        if f in members:
                            src = t.extractfile(members[f]).read().decode("utf-8", "replace")
                            for rx, label in ((SECRET_ENV, "reads environment variables"),
                                              (URL, "contains a hard-coded URL"),
                                              (NET, "uses network / process APIs"),
                                              (TMP, "writes to the temp directory")):
                                for i, l in enumerate(src.splitlines(), 1):
                                    if rx.search(l) and (rx is not SECRET_ENV or True):
                                        extra = ""
                                        if rx is SECRET_ENV and SECRET_WORDS.search(src):
                                            extra = " (matches secret-like names)"
                                        info["signals"].append({"signal": label + extra, "evidence": {
                                            "source": "%s!%s" % (rel, f), "line": i, "excerpt": l.strip()[:200]}})
                                        break
        for name, m in members.items():
            if m.size > 20000 and name.endswith((".js", ".mjs", ".cjs")):
                head = t.extractfile(m).read(300).decode("utf-8", "replace")
                lines = t.extractfile(m).read().count(b"\n")
                info["signals"].append({"signal": "large code file (%d bytes, %d newlines)" % (m.size, lines),
                                        "evidence": {"source": "%s!%s" % (rel, name), "line": 1, "excerpt": head[:120] + "…"}})
    return info


def workflow_files(root):
    d = os.path.join(root, ".github", "workflows")
    return sorted(".github/workflows/" + f for f in os.listdir(d) if f.endswith((".yml", ".yaml"))) if os.path.isdir(d) else []


# ---------------------------------------------------------------- findings
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_RISK = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
LOWER = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}


class Findings:
    def __init__(self):
        self.items = []

    def add(self, **f):
        f["id"] = "F%03d" % (len(self.items) + 1)
        self.items.append(f)
        return f


def build(base, head, offline):
    if offline:
        os.environ["GUARDIAN_OFFLINE"] = "1"
    os.makedirs(OUT, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="guardian-fast-")
    rb, rh = extract(base, os.path.join(tmp, "base")), extract(head, os.path.join(tmp, "head"))

    # 1. inventory + SBOM
    sb, sh = lsd.sbom(rb), lsd.sbom(rh)
    sdiff = lsd.diff(sb, sh)
    for fn, d in (("sbom.base.cdx.json", sb), ("sbom.head.cdx.json", sh), ("sbom.diff.json", sdiff)):
        json.dump(d, open(os.path.join(OUT, fn), "w", encoding="utf-8"), indent=1)
    B, H = inventory(rb), inventory(rh)
    nodes, edges = H["nodes"], H["edges"]
    base_by_path = B["nodes"]
    base_names = {n["name"]: n for n in base_by_path.values() if n["kind"] == "pkg"}
    for nid, n in nodes.items():
        if n["kind"] != "pkg":
            continue
        b = base_by_path.get(nid)
        n["isNew"] = b is None
        n["changed"] = bool(b) and (b["version"], b["integrity"], b["resolved"]) != (n["version"], n["integrity"], n["resolved"])
        n["baseVersion"] = b["version"] if b else None
        n["findings"] = []
    nodes[""]["findings"] = []
    nodes[""]["path"] = [""]
    removed = [{"id": k, "name": v["name"], "version": v["version"]} for k, v in base_by_path.items()
               if v["kind"] == "pkg" and k not in nodes]

    F = Findings()

    def attach(nid, f):
        nodes[nid]["findings"].append(f["id"])
        f["nodeId"] = nid
        f["path"] = [nodes[p]["name"] + ("@" + nodes[p]["version"] if nodes[p]["kind"] == "pkg" else "") for p in (nodes[nid].get("path") or [nid])]

    def lock_ev(nid):
        n = nodes[nid]
        return {"source": "package-lock.json @ %s" % head, "line": n["lockLine"],
                "excerpt": '"%s": { "version": "%s", "resolved": "%s"%s }' % (
                    nid, n["version"], n["resolved"], ', "hasInstallScript": true' if n["install"] else "")}

    # 2. vulnerabilities
    osv_meta, vulns = osv_scan(nodes)
    for nid, vs in vulns.items():
        n = nodes[nid]
        n["vulns"] = vs
        for v in vs:
            risk = SEV_RISK.get(v["severity"])
            rule = "OSV database_specific.severity = %s" % v["severity"]
            if risk is None:
                risk, rule = "medium", "OSV severity missing -> medium (unknown is not low)"
            if n["dev"]:
                risk, rule = LOWER[risk], rule + "; dev-only dependency -> one level lower"
            f = F.add(category="vulnerability", type="known_vulnerability", component=n["purl"], risk=risk, rule=rule,
                      title="%s %s" % (v["id"], v["summary"][:90]), new_in_head=n["isNew"] or n["changed"],
                      claim="VERIFIED", fixed=v["fixed"], advisory=v["id"], aliases=v["aliases"], severity=v["severity"],
                      evidence=[{"source": "api.osv.dev/v1/vulns/%s (fetched %s)" % (v["id"], v["fetched"][:19]),
                                 "line": None, "excerpt": "severity=%s; aliases=%s; fixed=%s; cvss=%s" % (
                                     v["severity"], ",".join(v["aliases"][:3]) or "-", ",".join(v["fixed"]) or "none", v["cvss"] or "-")},
                                lock_ev(nid)])
            attach(nid, f)

    # 3. suspicious changes: packages
    popular = [l.strip() for l in open(os.path.join(KIT, "guardian", "data", "popular_npm_names.txt"), encoding="utf-8")
               if l.strip() and not l.startswith("#")]
    all_names = sorted({n["name"] for n in nodes.values() if n["kind"] == "pkg"})
    commit_for_pkg = {}
    for nid, n in nodes.items():
        if n["kind"] != "pkg" or not (n["isNew"] or n["changed"]):
            continue
        ln_pj, ex_pj = line_of(read(rh, "package.json") or "", '"%s"' % n["name"]) if n["direct"] else (None, None)
        c = introduced_by(base, head, "package-lock.json", n["integrity"] or n["resolved"] or '"%s"' % nid)
        commit_for_pkg[nid] = c
        common = dict(component=n["purl"], new_in_head=True, commit=c, claim="VERIFIED")
        what = "new package" if n["isNew"] else "changed %s -> %s" % (n["baseVersion"], n["version"])
        ev = [lock_ev(nid)]
        if ex_pj:
            ev.append({"source": "package.json @ %s" % head, "line": ln_pj, "excerpt": ex_pj})
        attach(nid, F.add(category="change", type="new_dependency" if n["isNew"] else "changed_dependency",
                          risk="low", rule="new or changed since %s -> low (informational)" % base,
                          title="%s%s" % (what, ", direct" if n["direct"] else ""), evidence=ev, **common))
        # typosquat
        if len(n["name"]) >= 4:
            near = []
            for other in set(all_names) | set(popular):
                if other == n["name"]:
                    continue
                dist = osa(n["name"], other)
                if dist <= (1 if len(n["name"]) < 6 else 2):
                    near.append((dist, other, "dependency" if other in all_names else "popular-npm list"))
            if near:
                near.sort()
                d, other, src = near[0]
                attach(nid, F.add(category="change", type="typosquat", risk="high",
                                  rule="new name within edit distance %d of '%s' (%s) -> high" % (d, other, src),
                                  title="look-alike name: '%s' resembles '%s' (edit distance %d)" % (n["name"], other, d),
                                  evidence=ev + [{"source": "computed: edit distance against %s" % ("guardian/data/popular_npm_names.txt" if src != "dependency" else "dependency names in package-lock.json @ %s" % head),
                                                  "line": None, "kind": "computed",
                                                  "excerpt": "%s  vs  %s  (distance %d, %s)" % (n["name"], other, d, src)}], **common))
        # origin
        if not n["registry"]:
            attach(nid, F.add(category="change", type="non_registry_origin", risk="medium",
                              rule="resolved is not %s -> medium" % REGISTRY,
                              title="resolved from %s" % (n["resolved"] or "(no resolved field)"), evidence=[lock_ev(nid)], **common))
        # install script
        if n["install"]:
            info = inspect_tarball(rh, n["resolved"])
            binfo = None
            bnode = base_names.get(n["name"])
            if bnode:
                binfo = inspect_tarball(rb, bnode["resolved"])
            if info is None:
                attach(nid, F.add(category="change", type="unsafe_install_script", risk="medium",
                                  rule="hasInstallScript, content not inspected (registry tarball not downloaded) -> medium; unknown is not clean",
                                  title="install script (content not inspected)", evidence=[lock_ev(nid)], **common))
            else:
                sig = info.get("signals", [])
                hooks = ", ".join("%s: %s" % (h, s["cmd"]) for h, s in info.get("scripts", {}).items())
                newhook = binfo is not None and not binfo.get("scripts")
                risk = "critical" if len({s["signal"] for s in sig}) >= 2 else "high"
                rule = "%s install hook(s) with %d static risk signal(s) -> %s" % (len(info.get("scripts", {})), len({s['signal'] for s in sig}), risk)
                ev = [s["evidence"] for s in info.get("scripts", {}).values()] + [s["evidence"] for s in sig]
                title = "install hook %s" % hooks
                if newhook:
                    title += " — added in this version (previous %s had none)" % bnode["version"]
                attach(nid, F.add(category="change", type="unsafe_install_script", risk=risk, rule=rule, title=title,
                                  signals=[s["signal"] for s in sig], evidence=ev, **common))
                if binfo and not binfo.get("missing"):
                    growth = info["size"] / max(binfo["size"], 1)
                    newfiles = sorted(set(info["files"]) - set(binfo["files"]))
                    if growth >= 2 or newhook:
                        attach(nid, F.add(category="change", type="suspicious_update", risk="high",
                                          rule="update adds install hook and/or tarball grows >= 2x -> high",
                                          title="%s -> %s: tarball %d -> %d bytes (x%.1f), new files: %s" % (
                                              bnode["version"], n["version"], binfo["size"], info["size"], growth, ", ".join(newfiles) or "none"),
                                          evidence=[{"source": "%s @ %s" % (binfo["tarball"], base), "line": None, "excerpt": "%d bytes; files: %s" % (binfo["size"], ", ".join(sorted(binfo["files"])))},
                                                    {"source": "%s @ %s" % (info["tarball"], head), "line": None, "excerpt": "%d bytes; files: %s" % (info["size"], ", ".join(sorted(info["files"])))},
                                                    {"source": "computed: size ratio and file-set difference", "line": None, "kind": "computed",
                                                     "excerpt": "x%.1f size; new files: %s; install hook added: %s" % (growth, ", ".join(newfiles) or "none", "yes" if newhook else "no")}],
                                          **common))

    # unused new import (new require() of a new direct dependency whose binding is never used)
    for nid, n in nodes.items():
        if n["kind"] == "pkg" and n["isNew"] and n["direct"]:
            for rel in ("app.js", "routes/index.js"):
                txt = read(rh, rel) or ""
                m = re.search(r"(?:var|const|let)\s+(\w+)\s*=\s*require\(['\"]%s['\"]\)" % re.escape(n["name"]), txt)
                if m:
                    uses = len(re.findall(r"\b%s\b" % m.group(1), txt)) - 1
                    ln, ex = line_of(txt, m.group(0))
                    attach(nid, F.add(category="change", type="unexpected_dependency", risk="medium" if uses == 0 else "low",
                                      rule="new require() whose binding is used %d time(s) -> %s" % (uses, "medium" if uses == 0 else "low"),
                                      title="new require() in %s; binding '%s' used %d time(s)" % (rel, m.group(1), uses),
                                      component=n["purl"], new_in_head=True, claim="VERIFIED",
                                      commit=introduced_by(base, head, rel, m.group(0)),
                                      evidence=[{"source": "%s @ %s" % (rel, head), "line": ln, "excerpt": ex}]))

    # 3b. Dockerfile + workflows as file nodes
    def file_node(rel):
        nid = "file:" + rel
        nodes[nid] = {"id": nid, "name": rel, "version": "", "kind": "file", "path": ["", nid], "findings": [],
                      "isNew": read(rb, rel) is None, "changed": read(rb, rel) != read(rh, rel)}
        edges.append(["", nid])
        return nid

    pending = []  # file-based findings, merged by (file, type, new_in_head) below

    def pend(nid, f):
        pending.append((nid, f))

    for rel in ("Dockerfile",):
        txt_h, txt_b = read(rh, rel), read(rb, rel) or ""
        if txt_h is None:
            continue
        nid = file_node(rel)
        base_froms = re.findall(r"^\s*FROM\s+(\S+)", txt_b, re.M | re.I)
        for i, l in enumerate(txt_h.splitlines(), 1):
            m = re.match(r"\s*FROM\s+(\S+)", l, re.I)
            if m:
                img = m.group(1)
                changed = img not in base_froms
                if "@sha256:" in img:
                    continue
                tag = img.split(":", 1)[1] if ":" in img else "latest"
                floating = not re.fullmatch(r"\d+\.\d+\.\d+.*", tag)
                risk = "high" if changed and floating else ("medium" if floating else "low")
                pend(nid, dict(category="change" if changed else "config", type="untrusted_image", component="Dockerfile FROM " + img,
                                  risk=risk, rule="base image without digest%s%s -> %s" % (", floating tag" if floating else "", ", changed since " + base if changed else "", risk),
                                  title="FROM %s (no digest%s)%s" % (img, ", floating tag" if floating else "", "; was " + ", ".join(base_froms) if changed else ""),
                                  new_in_head=changed, claim="VERIFIED",
                                  commit=introduced_by(base, head, rel, l.strip()) if changed else None,
                                  evidence=[{"source": "%s @ %s" % (rel, head), "line": i, "excerpt": l.strip()}] +
                                           ([{"source": "%s @ %s" % (rel, base), "line": line_of(txt_b, base_froms[0])[0], "excerpt": "FROM " + base_froms[0]}] if changed and base_froms else [])))
            if re.search(r"\bnpm (update|install)\b", l) and "npm ci" not in l:
                pend(nid, dict(category="config", type="lockfile_drift", component=rel, risk="low",
                                  rule="image installs with npm update/install, not from the lockfile -> low",
                                  title="image does not install from the lockfile", new_in_head=l.strip() not in txt_b, claim="VERIFIED",
                                  evidence=[{"source": "%s @ %s" % (rel, head), "line": i, "excerpt": l.strip()}]))

    for rel in workflow_files(rh):
        txt_h, txt_b = read(rh, rel), read(rb, rel) or ""
        nid = file_node(rel)
        for i, l in enumerate(txt_h.splitlines(), 1):
            s = l.strip()
            new = s not in txt_b
            com = dict(new_in_head=new, claim="VERIFIED", commit=introduced_by(base, head, rel, s) if new else None,
                       evidence=[{"source": "%s @ %s" % (rel, head), "line": i, "excerpt": s}])
            cat = "change" if new else "config"
            m = re.search(r"uses:\s*([^\s@]+)@(\S+)", s)
            if m and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
                act, ref = m.group(1), m.group(2)
                first = act.split("/")[0] in ("actions", "github")
                risk = "low" if first else ("high" if new else "medium")
                adv = None if first else osv_action(act)
                f = dict(category=cat, type="unpinned_ci_component", component="%s@%s" % (act, ref), risk=risk,
                          rule="action pinned to mutable ref '%s', not a commit SHA; %s%s -> %s" % (ref, "first-party" if first else "third-party", ", new" if new else "", risk),
                          title="uses %s@%s (mutable ref)" % (act, ref), **com)
                if adv:
                    f["evidence"].append({"source": "api.osv.dev/v1/query (GitHub Actions, %s)" % act, "line": None,
                                          "excerpt": "; ".join("%s %s %s" % (a["id"], ",".join(a["aliases"][:2]), a["summary"][:70]) for a in adv[:3])})
                    f["title"] += " — OSV lists %d advisory(ies) for this action (version match not evaluated)" % len(adv)
                elif adv is None and not first:
                    f["evidence"].append({"source": "api.osv.dev", "line": None, "excerpt": "advisory lookup not evaluated (network/cache miss)"})
                pend(nid, f)
            if re.search(r"permissions:\s*write-all", s):
                pend(nid, dict(category=cat, type="unsafe_ci_pattern", component=rel, risk="high",
                                  rule="permissions: write-all -> high", title="workflow token has write-all permissions", **com))
            if re.search(r"(curl|wget)\b.*\|\s*(ba|z)?sh\b", s):
                pend(nid, dict(category=cat, type="unsafe_ci_pattern", component=rel, risk="high",
                                  rule="remote script piped to a shell -> high", title="downloads and pipes a remote script into a shell", **com))

    # merge duplicate file findings: same file + same type (+ same new/preexisting status)
    groups = {}
    for nid, f in pending:
        groups.setdefault((nid, f["type"], f["new_in_head"]), []).append(f)
    for (nid, typ, _new), fs in groups.items():
        fs.sort(key=lambda f: RISK_ORDER[f["risk"]])
        top = fs[0]
        rel = nodes[nid]["name"]
        merged = dict(top)
        merged["component"] = rel if (rel.startswith(".github/") or len(fs) > 1) else top["component"]
        if len(fs) > 1:
            titles = list(dict.fromkeys(f["title"] for f in fs))
            merged["title"] = "; ".join(titles)
            merged["rule"] = top["rule"] + " (highest of %d merged occurrences)" % len(fs)
            merged["evidence"] = [e for f in fs for e in f["evidence"]]
            merged["merged"] = len(fs)
            merged["commit"] = next((f["commit"] for f in fs if f.get("commit")), None)
        attach(nid, F.add(**merged))

    # claim labels: "verified" = statement read directly from a file or OSV;
    # "computed" = derived by code (edit distance, size ratio, usage count)
    COMPUTED = {"typosquat", "suspicious_update", "unexpected_dependency"}
    for f in F.items:
        f["claim"] = "computed" if f["type"] in COMPUTED else "verified"
        for e in f["evidence"]:
            e.setdefault("kind", "verified")

    findings = sorted(F.items, key=lambda f: (RISK_ORDER[f["risk"]], f["category"] != "change", f["id"]))
    pk = [n for n in nodes.values() if n["kind"] == "pkg"]
    # vulnerability counts: one per unique (package@version, advisory); the highest risk across its
    # install paths wins (a package can be prod on one path and dev-only on another)
    pairs = {}
    for f in F.items:
        if f["type"] == "known_vulnerability":
            k = (f["component"], f["advisory"])
            if k not in pairs or RISK_ORDER[f["risk"]] < RISK_ORDER[pairs[k]]:
                pairs[k] = f["risk"]
    sev = {}
    for r in pairs.values():
        sev[r] = sev.get(r, 0) + 1
    uniq = {n["purl"] for n in pk}
    uniq_direct = {n["purl"] for n in pk if n["direct"]}
    sus = [f for f in F.items if f["type"] not in ("known_vulnerability", "new_dependency", "changed_dependency")]
    counts = {
        "packages": len(uniq), "install_paths": len(pk), "direct": len(uniq_direct), "transitive": len(uniq - uniq_direct),
        "suspicious_new": sum(f["new_in_head"] for f in sus), "suspicious_present": sum(not f["new_in_head"] for f in sus),
        "components": len(pk),
        "prod": sum(not n["dev"] for n in pk), "dev": sum(n["dev"] for n in pk),
        "new": sum(n["isNew"] for n in pk), "changed": sum(n["changed"] for n in pk), "removed": len(removed),
        "vulnerable_components": len(vulns) if osv_meta["status"] == "evaluated" else None,
        "vulnerable_packages": len({k[0] for k in pairs}) if osv_meta["status"] == "evaluated" else None,
        "vuln_pairs": len(pairs) if osv_meta["status"] == "evaluated" else None,
        "vuln_findings_by_install_path": sum(1 for f in F.items if f["type"] == "known_vulnerability"),
        "vulns_by_risk": sev if osv_meta["status"] == "evaluated" else None,
        "suspicious_changes": sum(1 for f in F.items if f["category"] == "change" and f["type"] not in ("new_dependency", "changed_dependency")),
    }
    commits = [dict(zip(("sha", "subject"), l.split("\t", 1))) for l in
               git("log", "--reverse", "--format=%h%x09%s", "%s..%s" % (base, head)).decode().strip().splitlines()]
    doc = {
        "meta": {"target": "./target", "base": base, "head": head, "base_sha": git("rev-parse", "--short", base).decode().strip(),
                 "head_sha": git("rev-parse", "--short", head).decode().strip(),
                 "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                 "osv": osv_meta, "generator": "fastpath/build.py (deterministic, no LLM)"},
        "counts": counts, "commits": commits, "removed": removed, "findings": findings,
        "nodes": list(nodes.values()), "edges": edges,
    }
    json.dump({k: doc[k] for k in ("meta", "counts", "commits", "removed", "findings")},
              open(os.path.join(OUT, "findings.json"), "w", encoding="utf-8"), indent=1)
    tpl = open(os.path.join(HERE, "template.html"), encoding="utf-8").read()
    vis = open(os.path.join(OUT, "vis-network.min.js"), encoding="utf-8").read()
    html = tpl.replace("/*__DATA__*/null", json.dumps(doc).replace("</", "<\\/")).replace("<!--__VIS__-->", "<script>" + vis + "</script>")
    open(os.path.join(OUT, "guardian.html"), "w", encoding="utf-8").write(html)
    print("packages=%(packages)d install_paths=%(install_paths)d direct=%(direct)d transitive=%(transitive)d "
          "suspicious_new=%(suspicious_new)d suspicious_present=%(suspicious_present)d" % counts,
          "vulns=%s" % counts["vulns_by_risk"], "osv=%s" % osv_meta["status"], "findings=%d" % len(findings))
    return doc


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="guardian-baseline")
    ap.add_argument("--head", default="tampered")
    ap.add_argument("--offline", action="store_true")
    a = ap.parse_args()
    build(a.base, a.head, a.offline)
