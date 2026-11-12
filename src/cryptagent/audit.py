"""Journal d'audit append-only, chaîné et scellé par HMAC (inviolabilité détectable).

Chaque entrée contient le hash de la précédente : supprimer, modifier ou réordonner une ligne
casse la chaîne. Le scellement HMAC empêche un attaquant sans le secret de recalculer la chaîne.
Le journal ne contient jamais de chemin en clair, seulement des jetons pseudonymes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .secrets_store import subkey

GENESIS = "0" * 64


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


@dataclass
class ChainStatus:
    ok: bool
    entries: int
    last_hash: str
    error: str | None = None


class AuditLog:
    def __init__(self, path: Path, master: bytes):
        self.path = path
        self._k = subkey(master, "audit-seal-v1")

    def _last(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        with self.path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            buf = b""
            while pos > 0 and buf.count(b"\n") < 2:
                step = min(4096, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
        last = json.loads(buf.strip().splitlines()[-1])
        return int(last["seq"]), last["hash"]

    def append(self, event: str, **data) -> dict:
        seq, prev = self._last()
        entry = {
            "seq": seq + 1,
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            "data": data,
            "prev": prev,
        }
        entry["hash"] = hmac.new(self._k, prev.encode() + _canonical(entry), hashlib.sha256).hexdigest()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as fh:
            fh.write(_canonical(entry) + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def verify(self) -> ChainStatus:
        prev, n = GENESIS, 0
        if not self.path.exists():
            return ChainStatus(True, 0, GENESIS)
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return ChainStatus(False, n, prev, f"ligne {lineno} illisible")
                claimed = entry.pop("hash", "")
                if entry.get("prev") != prev:
                    return ChainStatus(False, n, prev, f"rupture de chaîne à la ligne {lineno}")
                if entry.get("seq") != n + 1:
                    return ChainStatus(False, n, prev, f"séquence incohérente à la ligne {lineno}")
                expected = hmac.new(self._k, prev.encode() + _canonical(entry), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, claimed):
                    return ChainStatus(False, n, prev, f"sceau invalide à la ligne {lineno}")
                prev, n = claimed, n + 1
        return ChainStatus(True, n, prev)
