"""Chiffrement des fichiers avec age (X25519 + ChaCha20-Poly1305), sans crypto « maison ».

Choix de conception :
- L'hôte ne détient que des CLÉS PUBLIQUES : il peut chiffrer mais jamais déchiffrer.
- Plusieurs destinataires (clé d'exploitation + clé de séquestre hors ligne).
- Le nom du fichier d'origine est placé DANS le flux chiffré : le nom visible devient un jeton.
- Écriture atomique (fichier temporaire + fsync + rename), puis effacement du clair.
"""

from __future__ import annotations

import hashlib
import io
import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path

import pyrage

from .scanner import AGE_MAGIC, TMP_SUFFIX

FRAME_MAGIC = b"CAG1"  # en-tête interne (dans la partie chiffrée) portant le nom d'origine
CHUNK = 1 << 20


class CryptoError(RuntimeError):
    pass


# --- Clés --------------------------------------------------------------------

def generate_identity() -> tuple[str, str]:
    """Retourne (clé_privée, clé_publique)."""
    ident = pyrage.x25519.Identity.generate()
    return str(ident), str(ident.to_public())


def write_identity(out_dir: Path, name: str) -> tuple[Path, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    secret, public = generate_identity()
    path = out_dir / f"{name}.key"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(f"# public key: {public}\n{secret}\n")
    (out_dir / f"{name}.pub").write_text(public + "\n", encoding="ascii")
    return path, public


def load_identities(paths: list[Path]):
    idents = []
    for p in paths:
        for line in Path(p).read_text(encoding="ascii").splitlines():
            line = line.strip()
            if line.startswith("AGE-SECRET-KEY-"):
                idents.append(pyrage.x25519.Identity.from_str(line))
    if not idents:
        raise CryptoError("Aucune clé privée age trouvée.")
    return idents


def parse_recipients(public_keys: list[str]):
    try:
        return [pyrage.x25519.Recipient.from_str(k) for k in public_keys]
    except Exception as exc:  # pyrage lève des types variés selon la version
        raise CryptoError(f"Clé publique invalide : {exc}") from exc


# --- Flux --------------------------------------------------------------------

class _ChainReader(io.RawIOBase):
    """Concatène un préfixe en mémoire et un fichier, en streaming."""

    def __init__(self, prefix: bytes, fh, sha):
        self._prefix = prefix
        self._fh = fh
        self._sha = sha

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        n = len(b)
        if self._prefix:
            chunk, self._prefix = self._prefix[:n], self._prefix[n:]
        else:
            chunk = self._fh.read(n)
            self._sha.update(chunk)
        b[: len(chunk)] = chunk
        return len(chunk)


def _frame_header(original_name: str) -> bytes:
    raw = original_name.encode("utf-8")
    return FRAME_MAGIC + struct.pack(">H", len(raw)) + raw


def count_recipient_stanzas(path: Path) -> int:
    """Lit l'en-tête age et compte les destinataires X25519 (vérification sans clé privée)."""
    with path.open("rb") as fh:
        if fh.read(len(AGE_MAGIC)) != AGE_MAGIC:
            raise CryptoError("En-tête age absent")
        count = 0
        for _ in range(4096):
            line = fh.readline(4096)
            if not line:
                raise CryptoError("En-tête age tronqué")
            if line.startswith(b"-> X25519 "):
                count += 1
            elif line.startswith(b"--- "):
                return count
    raise CryptoError("En-tête age invalide")


@dataclass
class EncryptResult:
    source: Path
    target: Path
    plaintext_size: int
    ciphertext_size: int
    content_sha256: bytes
    plaintext_removed: bool


def _shred(path: Path, passes: int) -> None:
    """Écrase puis supprime. Sur SSD / CoW, ne remplace pas le chiffrement intégral du disque."""
    size = path.stat().st_size
    with path.open("r+b", buffering=0) as fh:
        for _ in range(max(0, passes)):
            fh.seek(0)
            left = size
            while left > 0:
                n = min(CHUNK, left)
                fh.write(secrets.token_bytes(n))
                left -= n
            os.fsync(fh.fileno())
        fh.truncate(0)
        os.fsync(fh.fileno())
    # renommage aléatoire : le nom d'origine (souvent nominatif) disparaît de l'entrée de répertoire
    anon = path.with_name("." + secrets.token_hex(8) + TMP_SUFFIX)
    os.replace(path, anon)
    anon.unlink()


def encrypt_file(
    src: Path,
    target: Path,
    recipients_public: list[str],
    remove_plaintext: bool = True,
    shred_passes: int = 1,
) -> EncryptResult:
    src = Path(src)
    target = Path(target)
    if target.exists():
        raise CryptoError(f"La cible existe déjà : {target.name}")
    recipients = parse_recipients(recipients_public)
    tmp = target.with_name("." + secrets.token_hex(8) + TMP_SUFFIX)
    sha = hashlib.sha256()
    size = src.stat().st_size

    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with open(src, "rb") as fin, os.fdopen(fd, "wb") as fout:
            reader = io.BufferedReader(_ChainReader(_frame_header(src.name), fin, sha), CHUNK)
            pyrage.encrypt_io(reader, fout, recipients)
            fout.flush()
            os.fsync(fout.fileno())

        # Vérification post-chiffrement : format valide et tous les destinataires présents.
        stanzas = count_recipient_stanzas(tmp)
        if stanzas != len(recipients):
            raise CryptoError(f"{stanzas} destinataires dans l'en-tête, {len(recipients)} attendus")
        if src.stat().st_size != size:
            raise CryptoError("Le fichier source a changé pendant le chiffrement")
        os.replace(tmp, target)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise

    removed = False
    if remove_plaintext:
        _shred(src, shred_passes)
        removed = not src.exists()
    return EncryptResult(src, target, size, target.stat().st_size, sha.digest(), removed)


def decrypt_file(src: Path, out_dir: Path, identity_files: list[Path]) -> Path:
    """Déchiffrement : à exécuter HORS de l'hôte protégé, sur un poste détenant la clé privée."""
    idents = load_identities(identity_files)
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = out_dir / ("." + secrets.token_hex(8) + TMP_SUFFIX)
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            pyrage.decrypt_io(fin, fout, idents)
        with open(tmp, "rb") as fh:
            head = fh.read(6)
            if head[:4] == FRAME_MAGIC:
                (n,) = struct.unpack(">H", head[4:6])
                name = fh.read(n).decode("utf-8")
                offset = 6 + n
            else:
                name, offset = Path(src).name.removesuffix(".age"), 0
        name = Path(name).name  # anti path-traversal sur le nom restauré
        final = out_dir / name
        if final.exists():
            raise CryptoError(f"Le fichier restauré existe déjà : {final}")
        with open(tmp, "rb") as fin, open(final, "wb") as fout:
            fin.seek(offset)
            while chunk := fin.read(CHUNK):
                fout.write(chunk)
        return final
    finally:
        if tmp.exists():
            tmp.unlink()
