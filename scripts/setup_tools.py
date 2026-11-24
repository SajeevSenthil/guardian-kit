"""Download pinned SBOM / vulnerability tools into tools/bin and verify their SHA256 (stdlib only).

    python scripts/setup_tools.py            # syft, osv-scanner, grype for this OS/arch
    python scripts/setup_tools.py --force    # re-download

Versions are pinned here and written to tools.lock. Each download is checked against the
release's checksums file; a mismatch aborts and nothing is installed for that tool.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
BIN = KIT / "tools" / "bin"

SYFT, GRYPE, OSV = "1.57.2", "0.122.1", "2.7.1"


def _plat() -> tuple[str, str]:
    osname = {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux")
    m = platform.machine().lower()
    arch = "arm64" if m in ("arm64", "aarch64") else "amd64"
    return osname, arch


def _spec(name: str) -> dict:
    osn, arch = _plat()
    ext = ".exe" if osn == "windows" else ""
    if name in ("syft", "grype"):
        ver = SYFT if name == "syft" else GRYPE
        arc = "zip" if osn == "windows" else "tar.gz"
        base = f"https://github.com/anchore/{name}/releases/download/v{ver}/"
        asset = f"{name}_{ver}_{osn}_{arch}.{arc}"
        return {"version": ver, "url": base + asset, "asset": asset,
                "sums": base + f"{name}_{ver}_checksums.txt", "member": name + ext, "out": name + ext}
    base = f"https://github.com/google/osv-scanner/releases/download/v{OSV}/"
    asset = f"osv-scanner_{osn}_{arch}{ext}"
    return {"version": OSV, "url": base + asset, "asset": asset, "sums": base + "osv-scanner_SHA256SUMS",
            "member": None, "out": "osv-scanner" + ext}


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "guardian-setup"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def install(name: str, force: bool = False) -> str:
    s = _spec(name)
    out = BIN / s["out"]
    if out.exists() and not force:
        return f"ok       {name} {s['version']} (already installed)"
    sums = _get(s["sums"]).decode()
    want = next((ln.split()[0] for ln in sums.splitlines() if ln.strip().endswith(s["asset"])), None)
    if not want:
        return f"FAILED   {name}: {s['asset']} not listed in the checksums file"
    data = _get(s["url"])
    got = hashlib.sha256(data).hexdigest()
    if got != want:
        return f"FAILED   {name}: SHA256 mismatch (want {want[:12]}, got {got[:12]})"
    BIN.mkdir(parents=True, exist_ok=True)
    if s["member"] is None:
        out.write_bytes(data)
    elif s["asset"].endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            out.write_bytes(z.read(s["member"]))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
            out.write_bytes(t.extractfile(s["member"]).read())
    out.chmod(out.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return f"ok       {name} {s['version']} sha256 {got[:12]} verified"


def main() -> int:
    force = "--force" in sys.argv
    rc = 0
    lines = []
    for t in ("syft", "osv-scanner", "grype"):
        try:
            msg = install(t, force)
        except Exception as e:  # network, disk
            msg = f"FAILED   {t}: {type(e).__name__}: {e}"
        print(msg)
        rc |= msg.startswith("FAILED")
        lines.append(f"{t} {_spec(t)['version']} {'installed' if msg.startswith('ok') else 'missing'}")
    if os.environ.get("GUARDIAN_SKIP_GRYPE_DB") != "1" and (BIN / _spec("grype")["out"]).exists():
        print("updating the grype vulnerability database (one-off, ~200 MB)...")
        subprocess.run([str(BIN / _spec("grype")["out"]), "db", "update"], check=False)
    (KIT / "tools.lock").write_text("# written by scripts/setup_tools.py\n" + "\n".join(lines) + "\n", encoding="utf-8")
    return rc


if __name__ == "__main__":
    sys.exit(main())
