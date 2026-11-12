"""Interface en ligne de commande : `cryptagent <commande>`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import PolicyError, load_policy

LEVEL_ICON = {"none": "·", "low": "○", "medium": "◐", "high": "●"}


def _agent(args, use_llm=None):
    from .agent import CryptAgent

    agent = CryptAgent(load_policy(args.policy), use_llm=use_llm)
    if agent.brain_note:
        print(f"⚠ {agent.brain_note}", file=sys.stderr)
    return agent


def _print_plan(plan, show_paths: bool) -> None:
    print(f"\nMoteur : {plan.engine}")
    if plan.analysis:
        print(f"Analyse : {plan.analysis}\n")
    for a in plan.actions:
        label = a.record.rel if show_paths else a.token
        print(f"  {LEVEL_ICON[a.record.level]} {a.action:<8} {label:<48} [{a.source}] {a.reason}")
    print(
        f"\n→ {len(plan.by_action('encrypt'))} à chiffrer, {len(plan.by_action('review'))} à revoir, "
        f"{len(plan.by_action('skip'))} ignorés, {plan.overrides} décision(s) LLM corrigée(s) par la politique."
    )
    for e in plan.llm_errors:
        print(f"  ⚠ LLM {e} (repli sur les règles pour ce lot)")


def cmd_keygen(args):
    from .crypto import write_identity

    path, public = write_identity(Path(args.out), args.name)
    print(f"Clé privée : {path}  (À DÉPLACER HORS DE L'HÔTE : coffre, clé USB chiffrée, HSM)")
    print(f"Clé publique (à copier dans policy.yaml) : {public}")


def cmd_scan(args):
    from .scanner import scan

    policy = load_policy(args.policy)
    recs = scan(policy)
    for r in recs:
        state = "chiffré" if r.encrypted else r.level
        print(f"  {LEVEL_ICON.get(r.level, '·')} {state:<8} {r.rel:<48} {'; '.join(r.reasons)}")
    print(f"\n{len(recs)} fichier(s), {sum(policy.must_encrypt(r.level) and not r.encrypted for r in recs)} sensible(s) en clair.")


def cmd_plan(args):
    agent = _agent(args, use_llm=False if args.no_llm else None)
    _print_plan(agent.plan(), args.show_paths)
    print("\n(dry-run : aucune modification. Lancez `cryptagent run` pour exécuter.)")


def cmd_run(args):
    agent = _agent(args, use_llm=False if args.no_llm else None)
    plan = agent.plan()
    _print_plan(plan, args.show_paths)
    if not plan.by_action("encrypt") and not plan.by_action("review"):
        print("Rien à faire.")
    if plan.by_action("encrypt") and not args.yes:
        if not sys.stdin.isatty():
            print("Confirmation requise : relancez avec --yes.", file=sys.stderr)
            return 2
        answer = input("\nValider l'exécution (chiffrement + effacement du clair) ? [oui/non] ").strip().lower()
        if answer not in ("o", "oui", "y", "yes"):
            agent.audit.append("plan_rejected_by_human", encrypt=len(plan.by_action("encrypt")))
            print("Annulé.")
            return 1
    agent.audit.append("plan_approved", approver="cli" if not args.yes else "cli --yes")
    stats = agent.execute(plan)
    report = agent.write_report(stats, plan.analysis)
    print(f"\n{stats['encrypted']} chiffré(s), {stats['errors']} erreur(s). Rapport : {report}")
    return 0 if stats["errors"] == 0 else 1


def cmd_watch(args):
    from .watcher import watch

    agent = _agent(args, use_llm=False)
    print("Surveillance active (Ctrl+C pour arrêter)…")
    try:
        watch(agent, settle_s=args.settle)
    except KeyboardInterrupt:
        print("\nArrêt.")


def cmd_verify(args):
    agent = _agent(args, use_llm=False)
    res = agent.compliance_check()
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(f"Fichiers : {res['files']} | chiffrés : {res['encrypted']} | sensibles en clair : {res['sensitive_plaintext']}")
        if res["sensitive_in_monitored_roots"]:
            print(f"⚠ {res['sensitive_in_monitored_roots']} fichier(s) sensible(s) dans des zones en surveillance : à traiter")
        print(f"Journal d'audit : {'intègre' if res['audit_ok'] else 'ALTÉRÉ — ' + str(res['audit_error'])} ({res['audit_entries']} entrées)")
        print("CONFORME" if res["compliant"] else "NON CONFORME")
    return 0 if res["compliant"] else 1


def cmd_audit(args):
    agent = _agent(args, use_llm=False)
    status = agent.audit.verify()
    for e in agent.audit.entries()[-args.tail :]:
        print(f"{e['seq']:>5} {e['ts']} {e['event']:<20} {json.dumps(e['data'], ensure_ascii=False)}")
    print(f"\nChaîne : {'OK' if status.ok else 'ALTÉRÉE — ' + str(status.error)} | {status.entries} entrées | dernier sceau {status.last_hash[:16]}…")
    return 0 if status.ok else 1


def cmd_lookup(args):
    agent = _agent(args, use_llm=False)
    for p in args.paths:
        print(f"{agent.pseudo.token(Path(p))}  {p}")


def cmd_decrypt(args):
    from .crypto import decrypt_file

    ids = [Path(i) for i in args.identity]
    for f in args.files:
        out = decrypt_file(Path(f), Path(args.out), ids)
        print(f"{f} → {out}")


def cmd_doctor(args):
    from .brain import OllamaBrain

    policy = load_policy(args.policy)
    ok = True
    print(f"Politique : {args.policy} ✓")
    for r in policy.roots:
        exists = r.path.is_dir()
        ok &= exists
        print(f"Racine {r.path} [{r.mode}] {'✓' if exists else '✗ introuvable'}")
    print(f"Destinataires : {', '.join(r.name for r in policy.recipients)} ✓")
    if len(policy.recipients) < 2:
        print("  ⚠ Un seul destinataire : ajoutez une clé de séquestre hors ligne.")
    for r in policy.roots:
        if not r.path.is_dir():
            continue
        for p in r.path.rglob("*"):
            if p.is_file() and not p.is_symlink() and p.stat().st_size < 4096:
                try:
                    if "AGE-SECRET-KEY-" in p.read_text("utf-8", "ignore"):
                        ok = False
                        print(f"  ✗ CLÉ PRIVÉE présente sur l'hôte : {p}")
                except OSError:
                    pass
    if policy.llm.enabled:
        avail, why = OllamaBrain(policy.llm).available()
        print(f"LLM {policy.llm.model} @ {policy.llm.base_url} : {'✓' if avail else '⚠ ' + why + ' (repli règles)'}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cryptagent", description="Agent IA de chiffrement des données de santé (AP-HB)")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-p", "--policy", default="policy.yaml", help="fichier de politique (défaut : policy.yaml)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="générer une paire de clés age")
    s.add_argument("--out", default="keys")
    s.add_argument("--name", default="aphb-primary")
    s.set_defaults(fn=cmd_keygen)

    sub.add_parser("scan", help="inventaire et classification (lecture seule)").set_defaults(fn=cmd_scan)

    for name, fn, helptext in (("plan", cmd_plan, "proposer un plan (dry-run)"), ("run", cmd_run, "planifier puis exécuter")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("--no-llm", action="store_true", help="forcer le moteur de règles")
        s.add_argument("--show-paths", action="store_true", help="afficher les chemins locaux (terminal uniquement)")
        if name == "run":
            s.add_argument("-y", "--yes", action="store_true", help="valider sans confirmation interactive")
        s.set_defaults(fn=fn)

    s = sub.add_parser("watch", help="chiffrer automatiquement les nouveaux fichiers")
    s.add_argument("--settle", type=float, default=2.0, help="secondes de stabilité avant chiffrement")
    s.set_defaults(fn=cmd_watch)

    s = sub.add_parser("verify", help="contrôle de conformité (code retour 1 si non conforme)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("audit", help="afficher et vérifier le journal d'audit")
    s.add_argument("--tail", type=int, default=20)
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("lookup", help="retrouver le jeton d'un chemin")
    s.add_argument("paths", nargs="+")
    s.set_defaults(fn=cmd_lookup)

    s = sub.add_parser("decrypt", help="déchiffrer (HORS de l'hôte protégé)")
    s.add_argument("files", nargs="+")
    s.add_argument("-i", "--identity", action="append", required=True, help="fichier de clé privée age")
    s.add_argument("-o", "--out", default="restored")
    s.set_defaults(fn=cmd_decrypt)

    sub.add_parser("doctor", help="diagnostic de l'installation").set_defaults(fn=cmd_doctor)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args) or 0)
    except PolicyError as exc:
        print(f"Erreur de politique : {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
