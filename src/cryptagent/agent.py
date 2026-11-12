"""Boucle agentique : percevoir → planifier → valider (garde-fous) → agir → vérifier → rendre compte."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .audit import AuditLog
from .brain import OllamaBrain, RuleBrain
from .config import Policy
from .crypto import CryptoError, encrypt_file
from .scanner import FileRecord, root_mode, scan
from .secrets_store import Pseudonymizer, ensure_state_dir, load_or_create_master


def _size_bucket(size: int) -> int:
    """Taille arrondie (kB, puissance de 2) : réduit le risque de ré-identification par la taille."""
    kb = max(1, size // 1024)
    return 1 << (kb.bit_length() - 1)


@dataclass
class PlannedAction:
    record: FileRecord
    token: str
    action: str
    reason: str
    source: str  # llm | rules | policy-override


@dataclass
class Plan:
    actions: list[PlannedAction]
    analysis: str
    engine: str
    overrides: int = 0
    llm_errors: list[str] = field(default_factory=list)

    def by_action(self, action: str) -> list[PlannedAction]:
        return [a for a in self.actions if a.action == action]


class CryptAgent:
    def __init__(self, policy: Policy, use_llm: bool | None = None, brain=None):
        self.policy = policy
        ensure_state_dir(policy.state_dir)
        master = load_or_create_master(policy.state_dir)
        self.pseudo = Pseudonymizer(master)
        self.audit = AuditLog(policy.state_dir / "audit.jsonl", master)
        self.rules = RuleBrain(policy.must_encrypt)
        self.brain = brain
        self.brain_note = ""
        if self.brain is None:
            want_llm = policy.llm.enabled if use_llm is None else use_llm
            self.brain = self.rules
            if want_llm:
                candidate = OllamaBrain(policy.llm)
                ok, why = candidate.available()
                if ok:
                    self.brain = candidate
                else:
                    self.brain_note = f"LLM indisponible, repli sur les règles : {why}"

    # --- Perception ----------------------------------------------------------
    def perceive(self) -> tuple[list[FileRecord], list[dict]]:
        records = scan(self.policy)
        items = []
        for r in records:
            items.append(
                {
                    "id": self.pseudo.token(r.path),
                    "dir": self.pseudo.dir_token(r.path.parent),
                    "ext": r.ext or "(aucune)",
                    "size_kb": _size_bucket(r.size),
                    "level": r.level,
                    "signals": sorted(r.detectors),
                    "root_mode": root_mode(self.policy, r.root),
                    "already_encrypted": r.encrypted,
                }
            )
        return records, items

    # --- Planification + garde-fous -----------------------------------------
    def plan(self) -> Plan:
        records, items = self.perceive()
        proposal = self.brain.plan(items)
        floor = self.rules.plan(items)
        actions, overrides = [], 0

        for rec, it in zip(records, items):
            tok = it["id"]
            floor_action, floor_reason = floor.decisions[tok]
            if tok in proposal.decisions and self.brain is not self.rules:
                action, reason = proposal.decisions[tok]
                source = "llm"
            else:
                action, reason, source = floor_action, floor_reason, "rules"

            # Garde-fou 1 : le LLM peut durcir, jamais assouplir le plancher de la politique.
            if floor_action == "encrypt" and action != "encrypt":
                action, reason, source = "encrypt", f"plancher politique ({floor_reason})", "policy-override"
                overrides += 1
            # Garde-fou 2 : jamais d'action sur un fichier déjà chiffré ou une racine en surveillance.
            if (it["already_encrypted"] or it["root_mode"] == "monitor") and action == "encrypt":
                action, reason, source = floor_action, floor_reason, "policy-override"
                overrides += 1
            actions.append(PlannedAction(rec, tok, action, reason, source))

        plan = Plan(actions, proposal.analysis or floor.analysis, self.brain.name, overrides, proposal.errors)
        self.audit.append(
            "plan",
            engine=plan.engine,
            inventoried=len(actions),
            encrypt=len(plan.by_action("encrypt")),
            review=len(plan.by_action("review")),
            overrides=overrides,
            llm_errors=len(plan.llm_errors),
            note=self.brain_note,
        )
        return plan

    # --- Action --------------------------------------------------------------
    def target_for(self, rec: FileRecord, token: str) -> Path:
        return rec.path.with_name(token + self.policy.suffix)

    def encrypt_one(self, rec: FileRecord, token: str, trigger: str) -> dict:
        target = self.target_for(rec, token)
        try:
            res = encrypt_file(
                rec.path,
                target,
                [r.public_key for r in self.policy.recipients],
                remove_plaintext=self.policy.remove_plaintext,
                shred_passes=self.policy.shred_passes,
            )
        except (CryptoError, OSError) as exc:
            self.audit.append("encrypt_failed", id=token, trigger=trigger, error=f"{exc.__class__.__name__}: {exc}"[:200])
            return {"id": token, "ok": False, "error": str(exc)}
        entry = self.audit.append(
            "encrypted",
            id=token,
            trigger=trigger,
            level=rec.level,
            recipients=[r.name for r in self.policy.recipients],
            size=res.plaintext_size,
            fingerprint=self.pseudo.content_fingerprint(res.content_sha256),
            plaintext_removed=res.plaintext_removed,
        )
        return {"id": token, "ok": True, "seq": entry["seq"], "plaintext_removed": res.plaintext_removed}

    def execute(self, plan: Plan) -> dict:
        results = [self.encrypt_one(a.record, a.token, trigger=a.source) for a in plan.by_action("encrypt")]
        for a in plan.by_action("review"):
            self.audit.append("review_requested", id=a.token, level=a.record.level, reason=a.reason)
        stats = {
            "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "engine": plan.engine,
            "inventoried": len(plan.actions),
            "encrypted": sum(1 for r in results if r["ok"]),
            "errors": sum(1 for r in results if not r["ok"]),
            "already_encrypted": sum(1 for a in plan.actions if a.record.encrypted),
            "review": len(plan.by_action("review")),
            "overrides": plan.overrides,
        }
        stats["audit_ok"] = self.audit.verify().ok
        return stats

    # --- Vérification de conformité -----------------------------------------
    def compliance_check(self) -> dict:
        records = scan(self.policy)
        exposed = [
            self.pseudo.token(r.path)
            for r in records
            if not r.encrypted and self.policy.must_encrypt(r.level) and root_mode(self.policy, r.root) == "encrypt"
        ]
        flagged = [
            self.pseudo.token(r.path)
            for r in records
            if not r.encrypted and self.policy.must_encrypt(r.level) and root_mode(self.policy, r.root) == "monitor"
        ]
        chain = self.audit.verify()
        result = {
            "files": len(records),
            "encrypted": sum(1 for r in records if r.encrypted),
            "sensitive_plaintext": len(exposed),
            "sensitive_plaintext_ids": exposed[:50],
            "sensitive_in_monitored_roots": len(flagged),
            "audit_ok": chain.ok,
            "audit_entries": chain.entries,
            "audit_error": chain.error,
            "compliant": chain.ok and not exposed,
        }
        self.audit.append(
            "compliance_check",
            compliant=result["compliant"],
            sensitive_plaintext=len(exposed),
            audit_ok=chain.ok,
        )
        return result

    # --- Compte rendu ----------------------------------------------------------
    def write_report(self, stats: dict, analysis: str = "") -> Path:
        body = self.brain.report(stats)
        reports = self.policy.state_dir / "reports"
        reports.mkdir(exist_ok=True)
        path = reports / f"report-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.md"
        header = f"# Rapport agent de cryptage AP-HB\n\nMoteur : `{stats.get('engine')}`  \nDate : {stats.get('date')}\n\n"
        if analysis:
            header += f"**Analyse du lot** : {analysis}\n\n"
        path.write_text(header + body + "\n", encoding="utf-8")
        self.audit.append("report", file=path.name)
        return path
