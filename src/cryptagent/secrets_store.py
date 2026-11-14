"""Secret local de l'agent (pseudonymisation + scellement du journal).

Ce secret NE permet PAS de déchiffrer les fichiers : le déchiffrement exige la clé privée age,
qui ne doit jamais se trouver sur l'hôte protégé.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

KEY_FILE = "agent.key"


def ensure_state_dir(state_dir: Path) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(state_dir, 0o700)
    except OSError:
        pass
    return state_dir


def load_or_create_master(state_dir: Path) -> bytes:
    ensure_state_dir(state_dir)
    kf = state_dir / KEY_FILE
    if kf.exists():
        data = kf.read_bytes()
        if len(data) != 32:
            raise RuntimeError(f"Secret agent corrompu : {kf}")
        return data
    data = secrets.token_bytes(32)
    fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return data


def subkey(master: bytes, label: str) -> bytes:
    return hmac.new(master, label.encode(), hashlib.sha256).digest()


class Pseudonymizer:
    """Jetons stables et non réversibles pour les chemins (HMAC-SHA256)."""

    def __init__(self, master: bytes):
        self._k = subkey(master, "pseudonymize-v1")

    def token(self, path: Path) -> str:
        digest = hmac.new(self._k, str(Path(path).resolve()).encode(), hashlib.sha256).hexdigest()
        return "f_" + digest[:16]

    def dir_token(self, path: Path) -> str:
        digest = hmac.new(self._k, ("dir:" + str(Path(path).resolve())).encode(), hashlib.sha256).hexdigest()
        return "d_" + digest[:10]

    def content_fingerprint(self, data_hash: bytes) -> str:
        """Empreinte keyed du contenu : empêche les attaques par confirmation sur un simple SHA-256."""
        return hmac.new(self._k, data_hash, hashlib.sha256).hexdigest()[:32]
