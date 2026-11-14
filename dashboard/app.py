"""Console de pilotage Streamlit de l'agent de cryptage AP-HB.

Lancement : streamlit run dashboard/app.py --server.address 127.0.0.1 -- --policy policy.yaml
La console n'affiche que des jetons pseudonymes, jamais de nom de fichier.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptagent.agent import CryptAgent  # noqa: E402
from cryptagent.config import load_policy  # noqa: E402
from cryptagent.scanner import root_mode, scan  # noqa: E402


def _policy_path() -> str:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default="policy.yaml")
    args, _ = ap.parse_known_args()
    return args.policy


st.set_page_config(page_title="AP-HB · Agent de cryptage", page_icon="🔐", layout="wide")
policy = load_policy(_policy_path())


@st.cache_resource
def get_agent(use_llm: bool) -> CryptAgent:
    return CryptAgent(policy, use_llm=use_llm)


with st.sidebar:
    st.header("Paramètres")
    use_llm = st.toggle("Cerveau LLM (Ollama local)", value=policy.llm.enabled)
    agent = get_agent(use_llm)
    st.caption(f"Moteur actif : `{agent.brain.name}`")
    if agent.brain_note:
        st.warning(agent.brain_note)
    st.caption("Destinataires : " + ", ".join(r.name for r in policy.recipients))
    for r in policy.roots:
        st.caption(f"`{agent.pseudo.dir_token(r.path)}` · {r.mode}")

st.title("🔐 Agent de cryptage des données de santé")

# --- État de conformité (lecture seule) -------------------------------------
records = scan(policy)
chain = agent.audit.verify()
exposed = [r for r in records if not r.encrypted and policy.must_encrypt(r.level) and root_mode(policy, r.root) == "encrypt"]
flagged = [r for r in records if not r.encrypted and policy.must_encrypt(r.level) and root_mode(policy, r.root) == "monitor"]
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Fichiers inventoriés", len(records))
c2.metric("Chiffrés", sum(r.encrypted for r in records))
c3.metric("Sensibles en clair", len(exposed), delta=None if not exposed else "non conforme", delta_color="inverse")
c4.metric("Zones surveillées à traiter", len(flagged))
c5.metric("Journal d'audit", "intègre" if chain.ok else "ALTÉRÉ", f"{chain.entries} entrées")
if chain.ok and not exposed:
    st.success("Conforme : aucune donnée sensible en clair dans les zones protégées.")
else:
    st.error(chain.error or f"{len(exposed)} fichier(s) sensible(s) en clair.")

levels = Counter("chiffré" if r.encrypted else r.level for r in records)
st.bar_chart(pd.DataFrame({"fichiers": levels}).reindex(["chiffré", "high", "medium", "low", "none"]).fillna(0))

# --- Planification -----------------------------------------------------------
st.subheader("Planification")
if st.button("Proposer un plan (dry-run)", type="secondary"):
    st.session_state["plan"] = agent.plan()

plan = st.session_state.get("plan")
if plan:
    st.info(f"**{plan.engine}** — {plan.analysis}")
    st.dataframe(
        pd.DataFrame(
            [
                {"jeton": a.token, "niveau": a.record.level, "action": a.action, "origine": a.source, "raison": a.reason}
                for a in plan.actions
            ]
        ),
        width="stretch",
        hide_index=True,
    )
    n = len(plan.by_action("encrypt"))
    confirm = st.checkbox(f"Je valide le chiffrement de {n} fichier(s) et l'effacement du clair")
    if st.button("Exécuter le plan", type="primary", disabled=not confirm or n == 0):
        agent.audit.append("plan_approved", approver="dashboard")
        stats = agent.execute(plan)
        report = agent.write_report(stats, plan.analysis)
        st.session_state.pop("plan")
        st.success(f"{stats['encrypted']} fichier(s) chiffré(s), {stats['errors']} erreur(s). Rapport : {report.name}")
        st.rerun()

# --- Journal et rapports -----------------------------------------------------
st.subheader("Journal d'audit")
entries = agent.audit.entries()
if entries:
    df = pd.DataFrame([{"seq": e["seq"], "date": e["ts"], "événement": e["event"], "détails": e["data"]} for e in entries])
    df["jour"] = pd.to_datetime(df["date"]).dt.date
    st.bar_chart(df.groupby(["jour", "événement"]).size().unstack(fill_value=0))
    st.dataframe(df.drop(columns="jour").tail(50).iloc[::-1], width="stretch", hide_index=True)

reports = sorted((policy.state_dir / "reports").glob("*.md"))
if reports:
    st.subheader("Dernier rapport")
    st.markdown(reports[-1].read_text(encoding="utf-8"))
