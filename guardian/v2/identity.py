"""Package identity helpers shared by all stages: names, versions and purls normalised the same way everywhere."""

from __future__ import annotations

import re
import urllib.parse


def norm_name(eco: str, name: str) -> str:
    n = (name or "").strip().lower()
    return re.sub(r"[-_.]+", "-", n) if eco == "pypi" else n


def norm_version(eco: str, v: str | None) -> str | None:
    """Compare-only normalisation: PEP 440 treats 3.20 and 3.20.0 as the same release."""
    if not v:
        return v
    v = v.strip().lower().removeprefix("v") if eco != "golang" else v.strip()
    if eco == "pypi":
        v = re.sub(r"(\.0+)+$", "", v)
    return v


def purl_type(purl: str) -> str:
    m = re.match(r"pkg:([^/]+)/", purl or "")
    return m.group(1) if m else "unknown"


def norm_purl(purl: str) -> str:
    p = urllib.parse.unquote((purl or "").split("?")[0].split("#")[0]).lower()
    if p.startswith("pkg:pypi/"):
        body, _, ver = p[9:].partition("@")
        p = "pkg:pypi/" + re.sub(r"[-_.]+", "-", body) + ("@" + ver if ver else "")
    return p


EXACT = re.compile(r"^v?\d+(\.\d+)*([.\-+][0-9A-Za-z.\-+]+)?$")


def vkey(v: str):
    """Sortable version key; numeric parts compare as numbers, text parts (beta, rc) sort before them."""
    return [(1, int(x), "") if x.isdigit() else (0, 0, x) for x in re.split(r"[.\-+]", (v or "").lstrip("v"))]
