#!/usr/bin/env python3
"""Add or bump a local `file:` tarball dependency in package.json + package-lock.json.

Network-free and deterministic: used by make_demo_target.sh to seed harmless demo
packages without ever touching a registry.

usage: _lock_edit.py <name> <version> <tarball-relative-path> [--install-script]
"""

import base64
import hashlib
import json
import sys


def main() -> None:
    name, version, tar = sys.argv[1:4]
    has_script = "--install-script" in sys.argv[4:]
    digest = hashlib.sha512(open(tar, "rb").read()).digest()
    integrity = "sha512-" + base64.b64encode(digest).decode()
    spec = "file:" + tar

    pkg = json.load(open("package.json"))
    pkg["dependencies"][name] = spec
    pkg["dependencies"] = dict(sorted(pkg["dependencies"].items()))
    with open("package.json", "w") as f:
        json.dump(pkg, f, indent=2)
        f.write("\n")

    lock = json.load(open("package-lock.json"))
    lock["packages"][""]["dependencies"][name] = spec
    lock["packages"][""]["dependencies"] = dict(sorted(lock["packages"][""]["dependencies"].items()))
    entry = {"version": version, "resolved": spec, "integrity": integrity, "license": "MIT"}
    if has_script:
        entry["hasInstallScript"] = True
    lock["packages"]["node_modules/" + name] = entry
    if "dependencies" in lock:  # lockfile v2 keeps a legacy mirror section
        lock["dependencies"][name] = {"version": spec, "integrity": integrity}
    with open("package-lock.json", "w") as f:
        json.dump(lock, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
