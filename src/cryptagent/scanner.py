"""Inventaire et classification des fichiers d'un répertoire autorisé."""

from __future__ import annotations

import fnmatch
import os
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .config import LEVELS, Policy
from .detectors import detect, score

AGE_MAGIC = b"age-encryption.org/v1\n"
TMP_SUFFIX = ".cryptagent-tmp"
_ZIP_XML_EXT = {".docx", ".xlsx", ".pptx", ".odt", ".ods"}
_BINARY_HIGH_EXT = {".dcm", ".hl7"}  # imagerie DICOM / messages HL7 : toujours nominatifs
_OPAQUE_EXT = {".pdf", ".jpg", ".jpeg", ".png", ".tif", ".tiff", ".zip", ".7z", ".doc", ".xls"}


@dataclass
class FileRecord:
    path: Path
    root: Path
    size: int
    ext: str
    level: str = "none"
    reasons: list[str] = field(default_factory=list)
    detectors: dict[str, int] = field(default_factory=dict)
    encrypted: bool = False

    @property
    def rel(self) -> str:
        return self.path.relative_to(self.root).as_posix()


def is_age_file(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(len(AGE_MAGIC)) == AGE_MAGIC
    except OSError:
        return False


def _read_text(path: Path, ext: str, limit: int) -> str:
    """Lecture locale bornée. Les formats Office (zip XML) sont dézippés en mémoire."""
    if ext in _ZIP_XML_EXT:
        try:
            out, budget = [], limit
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.filename.endswith(".xml") and budget > 0:
                        with zf.open(info) as fh:
                            chunk = fh.read(budget)
                        budget -= len(chunk)
                        out.append(re.sub(rb"<[^>]+>", b" ", chunk).decode("utf-8", "ignore"))
            return " ".join(out)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            return ""
    try:
        with path.open("rb") as fh:
            data = fh.read(limit)
    except OSError:
        return ""
    return data.decode("utf-8", "ignore")


def _max_level(a: str, b: str) -> str:
    return a if LEVELS.index(a) >= LEVELS.index(b) else b


def classify(path: Path, root: Path, policy: Policy) -> FileRecord:
    st = path.stat()
    ext = path.suffix.lower()
    rec = FileRecord(path=path, root=root, size=st.st_size, ext=ext)

    if path.name.endswith(policy.suffix) or is_age_file(path):
        rec.encrypted = True
        rec.reasons.append("déjà chiffré (format age)")
        return rec

    if ext in _BINARY_HIGH_EXT:
        rec.level = "high"
        rec.reasons.append(f"format médical nominatif ({ext})")
    for pat in policy.sensitive_name_patterns:
        if re.search(pat, path.name):
            rec.level = _max_level(rec.level, "medium")
            rec.reasons.append("nom de fichier évocateur")
            break

    text = _read_text(path, ext, policy.content_scan_max_bytes)
    if ext in policy.sensitive_extensions:
        if ext in _OPAQUE_EXT or not text.strip():
            # contenu non analysable localement (PDF, image…) : chiffrement par précaution
            rec.level = _max_level(rec.level, "medium")
            rec.reasons.append(f"format {ext} non analysable, précaution")
        # format texte : c'est le contenu analysé ci-dessous qui décide

    hits: Counter = detect(text)
    if hits:
        rec.detectors = dict(hits)
        content_level = score(hits)
        rec.level = _max_level(rec.level, content_level)
        rec.reasons.append(f"contenu : {', '.join(sorted(hits))} → {content_level}")
    return rec


def _excluded(rel: str, policy: Policy) -> bool:
    return any(fnmatch.fnmatch(rel, pat) for pat in policy.exclude_patterns)


def iter_files(policy: Policy):
    """Parcourt les racines autorisées sans suivre les liens symboliques."""
    state = policy.state_dir.resolve()
    for root in policy.roots:
        base = root.path
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            d = Path(dirpath)
            dirnames[:] = [n for n in dirnames if not (d / n).is_symlink() and (d / n).resolve() != state]
            for name in filenames:
                p = d / name
                if p.is_symlink() or not p.is_file():
                    continue
                if name.endswith(TMP_SUFFIX) or name.startswith("~$"):
                    continue
                rel = p.relative_to(base).as_posix()
                if _excluded(rel, policy):
                    continue
                yield root, p


def scan(policy: Policy) -> list[FileRecord]:
    return [classify(p, root.path, policy) for root, p in iter_files(policy)]


def root_mode(policy: Policy, root_path: Path) -> str:
    for r in policy.roots:
        if r.path == root_path:
            return r.mode
    return "monitor"
