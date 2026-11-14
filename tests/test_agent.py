import json
import os

import httpx
import pytest

from cryptagent.agent import CryptAgent
from cryptagent.brain import BrainResult, OllamaBrain
from cryptagent.config import LLMConfig, PolicyError, load_policy
from cryptagent.crypto import count_recipient_stanzas, decrypt_file
from cryptagent.scanner import scan
from cryptagent.watcher import process_path


def test_scan_classifies(env):
    recs = {r.path.name: r for r in scan(env["policy"])}
    assert recs["cr_irm_martin.txt"].level == "high"
    assert recs["notes_service.txt"].level == "none"
    assert recs["fuite.csv"].level == "high"


def test_run_encrypts_and_restores_with_escrow_key(env):
    agent = CryptAgent(env["policy"], use_llm=False)
    plan = agent.plan()
    assert len(plan.by_action("encrypt")) == 1  # la racine 'public' est en mode monitor
    stats = agent.execute(plan)
    assert stats["encrypted"] == 1 and stats["errors"] == 0

    files = sorted(p.name for p in env["patients"].iterdir())
    assert "cr_irm_martin.txt" not in files  # clair effacé
    enc = [p for p in env["patients"].iterdir() if p.suffix == ".age"]
    assert len(enc) == 1 and enc[0].name.startswith("f_")  # nom pseudonymisé
    assert b"Martin" not in enc[0].read_bytes()
    assert count_recipient_stanzas(enc[0]) == 2

    out = decrypt_file(enc[0], env["tmp"] / "restored", [env["escrow_key"]])
    assert out.name == "cr_irm_martin.txt"
    assert "Jeanne Martin" in out.read_text(encoding="utf-8")


def test_public_root_untouched_but_flagged(env):
    agent = CryptAgent(env["policy"], use_llm=False)
    plan = agent.plan()
    review = [a for a in plan.by_action("review")]
    assert any(a.record.path.name == "fuite.csv" for a in review)
    agent.execute(plan)
    assert (env["public"] / "fuite.csv").exists()


def test_second_run_is_idempotent(env):
    agent = CryptAgent(env["policy"], use_llm=False)
    agent.execute(agent.plan())
    plan2 = agent.plan()
    assert plan2.by_action("encrypt") == []


def test_compliance_check(env):
    agent = CryptAgent(env["policy"], use_llm=False)
    assert agent.compliance_check()["compliant"] is False
    agent.execute(agent.plan())
    assert agent.compliance_check()["compliant"] is True


def test_symlink_not_followed(env, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("IPP : 99999999 Diagnostic", encoding="utf-8")
    os.symlink(outside, env["patients"] / "lien.txt")
    agent = CryptAgent(env["policy"], use_llm=False)
    agent.execute(agent.plan())
    assert outside.read_text(encoding="utf-8").startswith("IPP")


def test_audit_tamper_detected(env):
    agent = CryptAgent(env["policy"], use_llm=False)
    agent.execute(agent.plan())
    assert agent.audit.verify().ok
    log = agent.audit.path
    lines = log.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["data"]["encrypted"] = 999
    lines[1] = json.dumps(entry)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    status = agent.audit.verify()
    assert not status.ok and "ligne 2" in status.error


def test_audit_never_contains_paths(env):
    agent = CryptAgent(env["policy"], use_llm=False)
    agent.execute(agent.plan())
    raw = agent.audit.path.read_text(encoding="utf-8")
    assert "martin" not in raw.lower() and str(env["patients"]) not in raw


class LaxBrain:
    """Simule un LLM qui voudrait ignorer un fichier sensible."""

    name = "fake-llm"

    def plan(self, items):
        return BrainResult({it["id"]: ("skip", "ok") for it in items}, "tout va bien", self.name)

    def report(self, stats):
        return "rapport"


def test_llm_cannot_downgrade_policy_floor(env):
    agent = CryptAgent(env["policy"], brain=LaxBrain())
    plan = agent.plan()
    enc = plan.by_action("encrypt")
    assert len(enc) == 1 and enc[0].source == "policy-override"
    assert plan.overrides >= 1


def test_ollama_brain_receives_only_pseudonymized_metadata(env):
    captured = {}

    def handler(request: httpx.Request):
        if request.url.path == "/api/chat":
            body = json.loads(request.content)
            captured["body"] = body
            inv = json.loads(body["messages"][1]["content"])["inventaire"]
            decisions = [{"id": it["id"], "action": "encrypt", "reason": "test"} for it in inv]
            return httpx.Response(200, json={"message": {"content": json.dumps({"analysis": "risque élevé", "decisions": decisions})}})
        return httpx.Response(200, json={"models": [{"name": "qwen2.5:3b"}]})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://ollama")
    brain = OllamaBrain(LLMConfig(model="qwen2.5:3b"), client=client)
    assert brain.available()[0]
    agent = CryptAgent(env["policy"], brain=brain)
    plan = agent.plan()
    sent = json.dumps(captured["body"], ensure_ascii=False)
    assert "martin" not in sent.lower() and "cr_irm" not in sent and str(env["tmp"]) not in sent
    assert captured["body"]["format"]["required"] == ["analysis", "decisions"]
    assert plan.analysis == "risque élevé"
    # LLM a demandé "encrypt" sur la racine monitor : le garde-fou l'en empêche
    assert all(a.record.root == env["patients"] for a in plan.by_action("encrypt"))


def test_ollama_down_falls_back_to_rules(env):
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)), base_url="http://ollama")
    brain = OllamaBrain(LLMConfig(), client=client)
    assert brain.available()[0] is False
    agent = CryptAgent(env["policy"], brain=brain)
    plan = agent.plan()
    assert plan.llm_errors and len(plan.by_action("encrypt")) == 1


def test_watch_reflex_encrypts_new_file(env):
    agent = CryptAgent(env["policy"], use_llm=False)
    new = env["patients"] / "nouveau_cr.txt"
    new.write_text("IPP : 55555555\nDiagnostic : fracture", encoding="utf-8")
    res = process_path(agent, env["patients"], new)
    assert res and res["ok"] and not new.exists()


def test_policy_rejects_private_key(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("roots: [{path: .}]\nrecipients: [{name: x, public_key: AGE-SECRET-KEY-1ABC}]\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(p)
