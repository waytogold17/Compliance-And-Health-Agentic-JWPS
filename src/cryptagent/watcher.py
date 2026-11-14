"""Mode surveillance : chiffrement « réflexe » des nouveaux fichiers, sans attendre le LLM.

Le chemin réflexe n'utilise que les règles déterministes (latence faible, aucune dépendance réseau).
Le LLM intervient dans les passages planifiés (`cryptagent run`), pas ici.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .agent import CryptAgent
from .scanner import TMP_SUFFIX, classify


class _Collector(FileSystemEventHandler):
    def __init__(self):
        self.pending: dict[Path, tuple[int, float]] = {}
        self.lock = threading.Lock()

    def _add(self, path: str):
        p = Path(path)
        if p.name.endswith(TMP_SUFFIX) or p.name.startswith("~$"):
            return
        with self.lock:
            self.pending[p] = (-1, time.monotonic())

    def on_created(self, event):
        if not event.is_directory:
            self._add(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._add(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._add(event.dest_path)


def process_path(agent: CryptAgent, root: Path, path: Path) -> dict | None:
    """Classe un fichier et le chiffre si le plancher de la politique l'exige."""
    if path.is_symlink() or not path.is_file():
        return None
    rec = classify(path, root, agent.policy)
    if rec.encrypted or not agent.policy.must_encrypt(rec.level):
        return None
    return agent.encrypt_one(rec, agent.pseudo.token(path), trigger="watch")


def watch(agent: CryptAgent, settle_s: float = 2.0, stop: threading.Event | None = None, on_event=print) -> None:
    roots = [r.path for r in agent.policy.roots if r.mode == "encrypt" and r.path.is_dir()]
    if not roots:
        raise SystemExit("Aucune racine en mode 'encrypt' à surveiller.")
    collector = _Collector()
    observer = Observer()
    for r in roots:
        observer.schedule(collector, str(r), recursive=True)
    observer.start()
    agent.audit.append("watch_started", roots=len(roots))
    stop = stop or threading.Event()
    try:
        while not stop.is_set():
            time.sleep(0.5)
            now = time.monotonic()
            ready = []
            with collector.lock:
                for p, (last_size, since) in list(collector.pending.items()):
                    try:
                        size = p.stat().st_size
                    except OSError:
                        collector.pending.pop(p, None)
                        continue
                    if size != last_size:
                        collector.pending[p] = (size, now)
                    elif now - since >= settle_s:  # fichier stable : écriture terminée
                        ready.append(p)
                        collector.pending.pop(p, None)
            for p in ready:
                root = next((r for r in roots if p.is_relative_to(r)), None)
                if root is None:
                    continue
                res = process_path(agent, root, p)
                if res:
                    on_event(f"[watch] {res['id']} chiffré" if res["ok"] else f"[watch] échec {res['id']} : {res['error']}")
    finally:
        observer.stop()
        observer.join()
        agent.audit.append("watch_stopped")
