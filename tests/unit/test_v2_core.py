"""v2 core (M1): workspace, allow-list, zip safety, runner dependencies and stale marking, file endpoint, API."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from guardian.v2 import runner
from guardian.v2 import stages_discover as sd
from guardian.v2.workspace import Workspace


@pytest.fixture()
def wsroot(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_WORKSPACES_DIR", str(tmp_path / "ws"))
    # tests use a restrictive allow-list regardless of guardian.toml
    monkeypatch.setattr(sd, "_cfg_sources", lambda: {"allow": ["github.com/SajeevSenthil"], "max_mb": 200})
    return tmp_path


def _repo(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    (d / "requirements.txt").write_text("flask==2.0.1\nrequests>=2\n# comment\n", encoding="utf-8")
    (d / "package.json").write_text(json.dumps({"name": "demo", "version": "1.0.0", "dependencies": {"lodash": "^4"},
                                                "devDependencies": {"mocha": "^10"}}), encoding="utf-8")
    (d / "Dockerfile").write_text("FROM python:latest\n", encoding="utf-8")
    return d


def test_create_requires_consent(wsroot):
    with pytest.raises(ValueError, match="consent"):
        Workspace.create("path", str(wsroot), None, "", consent=True)
    with pytest.raises(ValueError, match="consent"):
        Workspace.create("path", str(wsroot), None, "me", consent=False)


def test_wildcard_allows_any_https_repo_but_keeps_safety_checks(monkeypatch):
    monkeypatch.setattr(sd, "_cfg_sources", lambda: {"allow": ["*"]})
    assert sd.check_git_url("https://github.com/anyone/anything")[1] == "anyone/anything"
    with pytest.raises(ValueError, match="credentials"):
        sd.check_git_url("https://u:p@github.com/anyone/x")
    with pytest.raises(ValueError, match="https"):
        sd.check_git_url("http://github.com/anyone/x")


def test_allow_list_refuses_unknown_owner_and_credentials(wsroot):
    with pytest.raises(ValueError, match="not in guardian.toml"):
        Workspace.create("git", "https://github.com/someone-else/repo", None, "me")
    with pytest.raises(ValueError, match="credentials"):
        sd.check_git_url("https://user:tok@github.com/SajeevSenthil/x")
    with pytest.raises(ValueError, match="https"):
        sd.check_git_url("file:///etc/passwd")
    with pytest.raises(ValueError, match="https"):
        sd.check_git_url("git@github.com:SajeevSenthil/x.git")
    assert sd.check_git_url("https://github.com/SajeevSenthil/guardian-kit.git")[1] == "sajeevsenthil/guardian-kit"


def test_zip_slip_and_symlink_rejected(tmp_path):
    for name in ("../evil.txt", "/abs.txt", "a/../../evil.txt"):
        zp = tmp_path / "z.zip"
        with zipfile.ZipFile(zp, "w") as z:
            z.writestr(name, "x")
        dest = tmp_path / ("out" + str(abs(hash(name))))
        dest.mkdir()
        with pytest.raises(ValueError, match="unsafe"):
            sd._safe_unzip(zp, dest, 10)
    zp = tmp_path / "s.zip"
    with zipfile.ZipFile(zp, "w") as z:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "/etc/passwd")
    with pytest.raises(ValueError, match="symlink"):
        sd._safe_unzip(zp, tmp_path / "o2", 10)


def test_ingest_from_path_detects_ecosystems(wsroot):
    ws = Workspace.create("path", str(_repo(wsroot)), None, "tester")
    st = runner.run_stage(ws, "ingest")
    assert st["status"] == "ok", st
    r = ws.read("ingest")
    assert set(r["ecosystems"]) == {"npm", "pypi"}
    assert r["ecosystems"]["pypi"]["pinned"] == "partly or not pinned"
    assert r["dockerfiles"] == ["Dockerfile"] and r["deep_npm"] is False
    assert (ws.src / ".git").exists()  # snapshot committed so v1 can git-archive it
    events = [json.loads(x) for x in (ws.dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events[0]["action"] == "consent" and events[0]["actor"] == "tester"


def test_direct_deps_parsing(wsroot):
    d = _repo(wsroot)
    found = sd.detect(d)
    dd = sd.direct_deps(d, found)
    assert dd[("pypi", "flask")]["line"] == 1 and dd[("pypi", "requests")]["spec"] == ">=2"
    assert dd[("npm", "lodash")]["dev"] is False and dd[("npm", "mocha")]["dev"] is True


def test_runner_upstream_check_and_stale(wsroot, monkeypatch):
    ws = Workspace.create("path", str(_repo(wsroot)), None, "tester")
    with pytest.raises(runner.StageError, match="run ingest first"):
        runner.run_stage(ws, "sbom")
    calls = {"n": 0}

    def fake_sbom(w, opts):
        calls["n"] += 1
        w.write("sbom", {"n": calls["n"]})
        return {"n": calls["n"]}

    def fake_graph(w, opts):
        w.write("graph", {"ok": True})
        return {}

    real = runner.resolve
    monkeypatch.setattr(runner, "resolve", lambda s: {"sbom": fake_sbom, "graph": fake_graph}.get(s) or real(s))
    assert runner.run_stage(ws, "ingest")["status"] == "ok"
    assert runner.run_stage(ws, "sbom")["status"] == "ok"
    assert runner.run_stage(ws, "graph")["status"] == "ok"
    assert runner.run_stage(ws, "sbom")["status"] == "ok"  # output changed -> graph is stale
    assert ws.status("graph")["status"] == "stale"


def test_not_built_stage_is_reported(wsroot, monkeypatch):
    monkeypatch.setitem(runner.REGISTRY, "vulns", "guardian.v2.no_such_module:run_vulns")
    with pytest.raises(runner.NotBuilt):
        runner.resolve("vulns")


def test_awaiting_approval_is_kept(wsroot, monkeypatch):
    ws = Workspace.create("path", str(_repo(wsroot)), None, "tester")

    def fake(w, opts):
        w.write("ingest", {})
        w.set_status("ingest", "awaiting_approval", summary={"plans": 2})
        return {"plans": 2}

    monkeypatch.setattr(runner, "resolve", lambda s: fake)
    assert runner.run_stage(ws, "ingest")["status"] == "awaiting_approval"


def test_file_endpoint_refuses_traversal(wsroot):
    ws = Workspace.create("path", str(_repo(wsroot)), None, "tester")
    (ws.dir / "stages").mkdir()
    (ws.dir / "stages" / "x.json").write_text("{}", encoding="utf-8")
    assert ws.safe_path("stages/x.json").name == "x.json"
    for bad in ("../../etc/passwd", "..\\..\\guardian.toml", "/etc/passwd", "stages/../../x"):
        with pytest.raises(FileNotFoundError):
            ws.safe_path(bad)


def test_api_smoke(wsroot):
    from fastapi.testclient import TestClient

    from guardian.api.app import create_app
    c = TestClient(create_app())
    assert [s["id"] for s in c.get("/api/meta").json()["stages"]] == runner.ORDER
    r = c.post("/api/ws", json={"kind": "git", "value": "https://github.com/evil/x", "consent_by": "me", "consent": True})
    assert r.status_code == 400 and "allow" in r.json()["detail"]
    r = c.post("/api/ws", json={"kind": "path", "value": str(_repo(wsroot)), "consent_by": "me", "consent": True})
    wid = r.json()["id"]
    assert c.get(f"/api/ws/{wid}").json()["stages"]["ingest"]["status"] == "not_run"
    assert c.get(f"/api/ws/{wid}/file", params={"path": "../../guardian.toml"}).status_code == 404
    assert c.post(f"/api/ws/{wid}/stages/sbom/run").status_code == 400  # needs ingest
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../x", "1")
    r = c.post("/api/ws/upload", files={"file": ("r.zip", buf.getvalue())}, data={"consent_by": "me", "consent": "true"})
    assert r.status_code == 200
    assert "index.html" not in c.get("/").text or "Supply Chain Guardian" in c.get("/").text
