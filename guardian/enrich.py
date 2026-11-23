"""EPSS (FIRST.org) and CISA KEV enrichment, cached under .cache/enrich/ with the fetch time.

Request shapes verified on 2026-11-23 (docs/tool-notes/epss-kev.md). Offline with no cache, or on
any network error, values are None (= unknown). None is never treated as 0 or False.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
CACHE = KIT / ".cache" / "enrich"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = {"User-Agent": "guardian-hackathon/0.1"}


def _offline() -> bool:
    return os.environ.get("GUARDIAN_OFFLINE") == "1"


def _cached(key: str, fetch):
    CACHE.mkdir(parents=True, exist_ok=True)
    p = CACHE / (hashlib.sha256(key.encode()).hexdigest()[:24] + ".json")
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    if _offline():
        raise OSError("offline and not cached")
    rec = {"fetched": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), "key": key, "data": fetch()}
    p.write_text(json.dumps(rec), encoding="utf-8")
    return rec


def _get(url: str):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return json.load(r)


def epss(cves: list[str]) -> tuple[dict, dict]:
    """{cve: {"epss": float, "percentile": float, "date": str, "fetched": str}}, status."""
    out, errors = {}, []
    cves = sorted({c for c in cves if c.startswith("CVE-")})
    for i in range(0, len(cves), 100):
        chunk = cves[i:i + 100]
        try:
            rec = _cached("epss:" + ",".join(chunk), lambda c=chunk: _get(EPSS_URL + ",".join(c)))
        except (OSError, urllib.error.URLError, ValueError) as e:
            errors.append(f"{type(e).__name__}: {e}")
            continue
        for row in rec["data"].get("data", []):
            out[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]),
                               "date": row.get("date"), "fetched": rec["fetched"]}
    status = {"source": "api.first.org EPSS", "requested": len(cves), "scored": len(out),
              "status": "evaluated" if not errors else ("partial" if out else "not evaluated"), "errors": errors}
    return out, status


def kev() -> tuple[dict | None, dict]:
    """({cve: entry} or None when unknown, status)."""
    try:
        rec = _cached("kev:catalog", lambda: _get(KEV_URL))
    except (OSError, urllib.error.URLError, ValueError) as e:
        return None, {"source": "CISA KEV", "status": "not evaluated", "error": f"{type(e).__name__}: {e}"}
    d = rec["data"]
    return ({v["cveID"]: {"dateAdded": v.get("dateAdded"), "name": v.get("vulnerabilityName")}
             for v in d["vulnerabilities"]},
            {"source": "CISA KEV", "status": "evaluated", "catalogVersion": d.get("catalogVersion"),
             "count": d.get("count"), "fetched": rec["fetched"]})
