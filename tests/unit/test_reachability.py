from pathlib import Path

from guardian import reachability as r

APP = {
    "app.js": "var x = require('alpha');\nvar fn = require('beta').run;\nconst { gamma1 } = require('gamma');\n"
              "var p = require('path');\nvar local = require('./lib');\napp.engine('delta', x);\n",
    "routes/index.js": "var _ = require('alpha');\nexports.h = function (req, res) {\n"
                       "  _.merge(obj, req.body.data);\n  _.chunk(list);\n  fn();\n};\n",
    "tests/a.spec.js": "require('epsilon');\n",
    "public/js/app.js": "require('zeta');\n",
    "package.json": '{"scripts": {"build": "tool-x -r alpha > out.js"}}',
}


def make(tmp_path: Path) -> Path:
    for rel, text in APP.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return tmp_path


def test_package_of():
    assert r.package_of("lodash/fp") == "lodash"
    assert r.package_of("@scope/pkg/sub") == "@scope/pkg"
    assert r.package_of("./x") is None and r.package_of("fs") is None and r.package_of("node:fs") is None


def test_scan_excludes_tests_and_public(tmp_path):
    s = r.scan(make(tmp_path), {"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "tool-x"})
    assert set(s["files"]) == {"app.js", "routes/index.js"}
    assert {"alpha", "beta", "gamma"} <= set(s["imports"])
    assert "epsilon" not in s["imports"] and "zeta" not in s["imports"] and "path" not in s["imports"]
    assert "merge" in s["imports"]["alpha"]["members"] and "run" in s["imports"]["beta"]["members"]


def test_tiers(tmp_path):
    s = r.scan(make(tmp_path), {"alpha", "delta", "tool-x", "omega"})
    alpha = {"name": "alpha", "direct": True, "path": ["", "node_modules/alpha"]}
    nodes = {"": {}, "node_modules/alpha": alpha}
    assert r.tier_for_vulnerability(alpha, nodes, "Prototype pollution in merge.", s)["tier"] == "R3"
    assert r.tier_for_vulnerability(alpha, nodes, "Issue in chunk handling.", s)["tier"] == "R2"
    assert r.tier_for_vulnerability(alpha, nodes, "Issue in defaultsDeep.", s)["tier"] == "R1"
    assert r.package_tier("delta", s)["tier"] == "unknown"      # named as a string, not imported
    assert r.package_tier("tool-x", s)["tier"] == "R1"          # invoked by an npm script
    assert r.package_tier("omega", s)["tier"] == "R0"


def test_transitive_capped_at_r1(tmp_path):
    s = r.scan(make(tmp_path), set())
    parent = {"name": "alpha", "version": "1", "direct": True, "path": ["", "node_modules/alpha"]}
    child = {"name": "kid", "direct": False, "path": ["", "node_modules/alpha", "node_modules/kid"]}
    nodes = {"": {}, "node_modules/alpha": parent, "node_modules/kid": child}
    t = r.tier_for_vulnerability(child, nodes, "merge merge merge", s)
    assert t["tier"] == "R1" and "capped at R1" in t["note"]
