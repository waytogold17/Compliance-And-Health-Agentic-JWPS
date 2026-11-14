"""Détecteurs locaux de données personnelles de santé (aucun appel réseau).

Les identifiants nationaux sont validés par leur clé de contrôle pour limiter les faux positifs.
Les détecteurs renvoient des NOMS et des COMPTES, jamais les valeurs trouvées.
"""

from __future__ import annotations

import re
from collections import Counter

# --- Identifiants nationaux --------------------------------------------------

_NIR_RE = re.compile(
    r"(?<![\dA-Z])([12])\s?(\d{2})\s?(\d{2})\s?(\d{2}|2[AB])\s?(\d{3})\s?(\d{3})\s?(\d{2})(?![\dA-Z])"
)
_CN_ID_RE = re.compile(r"(?<!\d)(\d{17}[\dXx])(?!\d)")
_US_SSN_RE = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")

_CN_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_CN_CHECK = "10X98765432"


def nir_is_valid(groups: tuple[str, ...]) -> bool:
    """Valide un NIR (n° de sécurité sociale FR) : clé = 97 - (n mod 97), Corse 2A/2B gérée."""
    sex, yy, mm, dept, commune, order, key = groups
    if dept == "2A":
        dept_num = "19"
    elif dept == "2B":
        dept_num = "18"
    else:
        dept_num = dept
    body = int(f"{sex}{yy}{mm}{dept_num}{commune}{order}")
    return 97 - (body % 97) == int(key)


def cn_id_is_valid(value: str) -> bool:
    """Valide un numéro de carte d'identité de résident chinois (GB 11643, 18 caractères)."""
    s = sum(int(d) * w for d, w in zip(value[:17], _CN_WEIGHTS))
    return _CN_CHECK[s % 11] == value[17].upper()


# --- Données personnelles et médicales --------------------------------------

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PHONE_FR_RE = re.compile(r"(?<!\d)(?:\+33\s?|0)[1-9](?:[ .-]?\d{2}){4}(?!\d)")
_DOB_RE = re.compile(
    r"(?i)(n[ée]e?\s+le|date\s+de\s+naissance|ddn|dob|date\s+of\s+birth|出生日期)\s*[:\-]?\s*\d{1,4}[/.\-年]\d{1,2}[/.\-月]\d{1,4}"
)
_IPP_RE = re.compile(r"(?i)\b(IPP|MRN|n°\s*patient|patient\s*id)\s*[:#]?\s*[A-Z0-9]{5,}")
# En-tête d'export tabulaire (CSV/TSV) portant une colonne d'identifiant patient
_TABLE_HEADER_RE = re.compile(r"(?i)^(?=[^\n]*[,;\t])[^\n]*\b(ipp|nir|ssn|mrn|patient_?id|num[ée]ro_?s[ée]cu)\b")
_MEDICAL_RE = re.compile(
    r"(?i)\b(diagnostic|diagnosis|pathologie|ant[ée]c[ée]dents?|ordonnance|posologie|prescription|"
    r"traitement|treatment|hospitalisation|compte[- ]rendu|IRM|MRI|scanner|biopsie|chimioth[ée]rapie|"
    r"VIH|HIV|CIM-?10|ICD-?10|allergie|allergy|groupe\s+sanguin|诊断|病历|处方)\b"
)

IDENTIFIER_DETECTORS = ("nir_fr", "id_cn", "ssn_us")
PERSONAL_DETECTORS = ("email", "phone_fr", "date_of_birth", "patient_id")


def detect(text: str) -> Counter:
    """Retourne un compteur {nom_detecteur: occurrences}."""
    hits: Counter = Counter()
    for m in _NIR_RE.finditer(text):
        if nir_is_valid(m.groups()):
            hits["nir_fr"] += 1
    for m in _CN_ID_RE.finditer(text):
        if cn_id_is_valid(m.group(1)):
            hits["id_cn"] += 1
    hits["ssn_us"] += len(_US_SSN_RE.findall(text))
    hits["email"] += len(_EMAIL_RE.findall(text))
    hits["phone_fr"] += len(_PHONE_FR_RE.findall(text))
    hits["date_of_birth"] += len(_DOB_RE.findall(text))
    hits["patient_id"] += len(_IPP_RE.findall(text))
    first_line = text.lstrip("\ufeff").split("\n", 1)[0]
    if _TABLE_HEADER_RE.search(first_line):
        hits["patient_id"] += 1
    hits["medical_term"] += len(_MEDICAL_RE.findall(text))
    return +hits  # supprime les zéros


def score(hits: Counter) -> str:
    """Convertit les détections en niveau de sensibilité : none | low | medium | high."""
    has_identifier = any(hits.get(d) for d in IDENTIFIER_DETECTORS)
    personal = sum(1 for d in PERSONAL_DETECTORS if hits.get(d))
    medical = hits.get("medical_term", 0)

    if has_identifier or hits.get("patient_id"):
        return "high"
    if medical and personal:
        return "high"  # donnée de santé rattachée à une personne (art. 9 RGPD)
    if medical >= 2 or personal >= 2:
        return "medium"
    if medical or personal:
        return "low"
    return "none"
