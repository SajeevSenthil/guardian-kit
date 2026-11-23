"""Agent layer with the model replaced by a fake transport (no network, no key)."""

import json

import pytest

from guardian import scoring
from guardian.agents import llm
from guardian.agents.runner import SCHEMAS, apply_refuter
from guardian.config import FACTORS
from guardian.evidence import EvidenceIndex, redact

FINDING = {"id": "F001", "evidence": [
    {"source": "pkg.tgz!package/package.json", "line": 9, "excerpt": '"postinstall": "node scripts/setup.js"'},
    {"source": "pkg.tgz!package/scripts/setup.js", "line": 1, "excerpt": "// harmless demo script, do not worry"}]}


def fake(responses):
    calls = []

    def transport(url, body, key):
        calls.append(body)
        return responses[len(calls) - 1]
    transport.calls = calls
    return transport


def text(t):
    return {"candidates": [{"content": {"role": "model", "parts": [{"text": t}]}}], "usageMetadata": {"totalTokenCount": 10}}


def call(name, args):
    return {"candidates": [{"content": {"role": "model", "parts": [{"functionCall": {"name": name, "args": args}}]}}]}


# ---- evidence / claims ------------------------------------------------------------------
def test_check_claim_forces_inferred_and_checks_quotes():
    idx = EvidenceIndex([FINDING])
    c = idx.check_claim({"text": "runs at install", "evidence_ids": ["F001.E1", "F999.E1"],
                         "quotes": ['"postinstall": "node scripts/setup.js"', "this text is not there", "short"],
                         "status": "VERIFIED"}, "m")
    assert c["status"] == "INFERRED" and c["evidence_ids"] == ["F001.E1"]
    assert c["dropped_evidence_ids"] == ["F999.E1"]
    assert c["quotes"] == ['"postinstall": "node scripts/setup.js"'] and len(c["dropped_quotes"]) == 2
    assert c["support_checked"] is False   # some quotes dropped


def test_quote_must_come_from_a_cited_id():
    idx = EvidenceIndex([FINDING])
    c = idx.check_claim({"text": "x", "evidence_ids": ["F001.E2"], "quotes": ["node scripts/setup.js"]}, "m")
    assert c["quotes"] == [] and c["support_checked"] is False


def test_no_quotes_means_support_unknown():
    assert EvidenceIndex([FINDING]).check_claim({"text": "x", "evidence_ids": []}, "m")["support_checked"] is None


def test_redaction(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "secret-value-123456")
    s = redact("key=secret-value-123456 and ghp_" + "a" * 36 + " and AKIAABCDEFGHIJKLMNOP")
    assert "secret-value" not in s and "ghp_a" not in s and "AKIA" not in s
    assert redact("ordinary source text = 1") == "ordinary source text = 1"


# ---- agent loop -------------------------------------------------------------------------
TOY_SCHEMA = {"type": "object", "properties": {"answer": {"type": "string", "enum": ["yes", "no"]}},
              "required": ["answer"]}


def test_agent_loop_tools_then_structured_output(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE", tmp_path)
    t = fake([call("echo", {"x": "hi"}), text("done"), text('{"answer": "yes"}')])
    client = llm.Gemini("m", key="k", transport=t)
    idx = EvidenceIndex()
    tools = {"echo": ({"name": "echo"}, lambda x: f"<tool_output>{x}</tool_output>")}
    r = llm.run_agent(name="a", model_client=client, system="s", payload="p", tools=tools, schema=TOY_SCHEMA, index=idx)
    assert r["status"] == "ok" and r["result"] == {"answer": "yes"}
    assert r["tool_calls"][0]["evidence_id"] == "T1" and idx.items["T1"]["kind"] == "tool"
    assert "tools" not in t.calls[-1]                       # final call: no tools, schema only
    assert t.calls[-1]["generationConfig"]["responseSchema"]["type"] == "OBJECT"


def test_unknown_tool_is_refused_not_executed(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE", tmp_path)
    t = fake([call("shell", {"cmd": "rm -rf /"}), text("ok"), text('{"answer": "no"}')])
    r = llm.run_agent(name="a", model_client=llm.Gemini("m", key="k", transport=t), system="s", payload="p",
                      tools={}, schema=TOY_SCHEMA, index=EvidenceIndex())
    assert "not available" in r["tool_calls"][0]["result"]


def test_invalid_output_twice_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE", tmp_path)
    t = fake([text("thinking"), text("not json"), text('{"answer": "maybe"}')])
    r = llm.run_agent(name="a", model_client=llm.Gemini("m", key="k", transport=t), system="s", payload="p",
                      tools={}, schema=TOY_SCHEMA, index=EvidenceIndex())
    assert r["status"] == "skipped" and "schema" in r["reason"]


def test_offline_is_skipped_without_calls():
    r = llm.run_agent(name="a", model_client=None, system="s", payload="p", tools={}, schema=TOY_SCHEMA,
                      index=EvidenceIndex(), mode="offline")
    assert r["status"] == "skipped"


def test_schemas_validate_their_own_examples():
    ok = {"verdict": "upheld", "factor": "none", "claims": [{"text": "t", "evidence_ids": []}]}
    assert llm.validate(ok, SCHEMAS["refuter"]) == []
    assert llm.validate({"verdict": "approve"}, SCHEMAS["refuter"])


# ---- refuter rules ----------------------------------------------------------------------
def scored():
    f = {k: scoring.factor(0.8, "verified", "x") for k in FACTORS}
    p = scoring.score(f)
    p["rails"] = []
    return {"id": "F001", "priority": p}


def test_refutation_based_on_self_description_is_not_applied():
    """Adversarial fixture: the install script says it is harmless; the model refutes using a
    paraphrase that is not a literal quote -> treated as inconclusive, score and status unchanged."""
    idx = EvidenceIndex([FINDING])
    f, rec = scored(), {}
    before = f["priority"]["score"]
    claims = [idx.check_claim({"text": "the script is harmless", "evidence_ids": ["F001.E2"],
                               "quotes": ["this package is completely safe"]}, "m")]
    apply_refuter(f, rec, {"verdict": "refuted", "factor": "none"}, claims)
    assert rec["effective_verdict"] == "inconclusive" and "status" not in f and f["priority"]["score"] == before


def test_supported_refutation_only_creates_a_candidate():
    idx = EvidenceIndex([FINDING])
    f, rec = scored(), {}
    claims = [idx.check_claim({"text": "x", "evidence_ids": ["F001.E1"], "quotes": ["node scripts/setup.js"]}, "m")]
    apply_refuter(f, rec, {"verdict": "refuted", "factor": "none"}, claims)
    assert f["status"] == "not_affected_candidate" and f["priority"]["score"] == scored()["priority"]["score"]


@pytest.mark.parametrize("verdict", ["upheld", "downgraded"])
def test_upheld_and_downgraded_rules(verdict):
    idx = EvidenceIndex([FINDING])
    f, rec = scored(), {}
    conf = f["priority"]["confidence"]
    claims = [idx.check_claim({"text": "x", "evidence_ids": ["F001.E1"], "quotes": ["node scripts/setup.js"]}, "m")]
    apply_refuter(f, rec, {"verdict": verdict, "factor": "reachability"}, claims)
    if verdict == "upheld":
        assert f["priority"]["confidence"] == min(100, conf + 5)
    else:
        assert f["priority"]["factors"]["reachability"]["grade"] == "heuristic"
        assert f["priority"]["confidence"] < conf


def test_payload_json_roundtrip():
    assert json.loads(json.dumps(SCHEMAS))
