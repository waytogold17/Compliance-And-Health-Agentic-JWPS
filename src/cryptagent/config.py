"""Chargement et validation de la politique (policy.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

LEVELS = ["none", "low", "medium", "high"]


class PolicyError(ValueError):
    pass


@dataclass
class Root:
    path: Path
    mode: str = "encrypt"  # encrypt | monitor


@dataclass
class Recipient:
    name: str
    public_key: str


@dataclass
class LLMConfig:
    enabled: bool = True
    base_url: str = "http://localhost:11434"
    model: str = "qwen2.5:3b"
    timeout_s: float = 120.0


@dataclass
class Policy:
    roots: list[Root]
    recipients: list[Recipient]
    state_dir: Path
    min_level_to_encrypt: str = "medium"
    sensitive_extensions: list[str] = field(default_factory=list)
    sensitive_name_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    content_scan_max_bytes: int = 1_048_576
    suffix: str = ".age"
    remove_plaintext: bool = True
    shred_passes: int = 1
    llm: LLMConfig = field(default_factory=LLMConfig)

    def level_rank(self, level: str) -> int:
        return LEVELS.index(level)

    def must_encrypt(self, level: str) -> bool:
        return self.level_rank(level) >= self.level_rank(self.min_level_to_encrypt)


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise PolicyError(msg)


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    _require(path.is_file(), f"Politique introuvable : {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    base = path.resolve().parent

    def resolve(p: str) -> Path:
        q = Path(p).expanduser()
        return (q if q.is_absolute() else base / q).resolve()

    roots_raw = raw.get("roots") or []
    _require(bool(roots_raw), "La politique doit déclarer au moins un répertoire dans 'roots'.")
    roots = []
    for r in roots_raw:
        mode = r.get("mode", "encrypt")
        _require(mode in ("encrypt", "monitor"), f"Mode inconnu pour {r.get('path')} : {mode}")
        roots.append(Root(path=resolve(r["path"]), mode=mode))

    recips = [Recipient(name=x["name"], public_key=str(x["public_key"]).strip()) for x in raw.get("recipients") or []]
    _require(bool(recips), "Au moins un destinataire (clé publique age) est requis dans 'recipients'.")
    for rc in recips:
        _require(rc.public_key.startswith("age1"), f"Clé publique age invalide pour {rc.name}")
        _require(not rc.public_key.upper().startswith("AGE-SECRET-KEY"), "Une clé PRIVÉE a été placée dans la politique.")

    cls = raw.get("classification") or {}
    enc = raw.get("encryption") or {}
    llm = raw.get("llm") or {}
    agent = raw.get("agent") or {}

    min_level = cls.get("min_level_to_encrypt", "medium")
    _require(min_level in LEVELS[1:], f"min_level_to_encrypt invalide : {min_level}")

    return Policy(
        roots=roots,
        recipients=recips,
        state_dir=resolve(agent.get("state_dir", ".cryptagent")),
        min_level_to_encrypt=min_level,
        sensitive_extensions=[e.lower() for e in cls.get("sensitive_extensions", [])],
        sensitive_name_patterns=list(cls.get("sensitive_name_patterns", [])),
        exclude_patterns=list(cls.get("exclude_patterns", [])),
        content_scan_max_bytes=int(cls.get("content_scan_max_bytes", 1_048_576)),
        suffix=enc.get("suffix", ".age"),
        remove_plaintext=bool(enc.get("remove_plaintext", True)),
        shred_passes=int(enc.get("shred_passes", 1)),
        llm=LLMConfig(
            enabled=bool(llm.get("enabled", True)),
            base_url=str(llm.get("base_url", "http://localhost:11434")).rstrip("/"),
            model=str(llm.get("model", "qwen2.5:3b")),
            timeout_s=float(llm.get("timeout_s", 120)),
        ),
    )
