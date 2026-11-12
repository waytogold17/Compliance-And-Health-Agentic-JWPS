from pathlib import Path

import pytest
import yaml

from cryptagent.config import load_policy
from cryptagent.crypto import write_identity

PHI = (
    "COMPTE-RENDU IRM\nPatient : Jeanne Martin\nIPP : 12345678\n"
    "Né(e) le 03/04/1961\nNIR : 2 61 04 75 112 345 {key}\nDiagnostic : RAS. Traitement poursuivi.\n"
)


def nir_key(body: str) -> str:
    return f"{97 - int(body) % 97:02d}"


@pytest.fixture
def env(tmp_path: Path):
    """Arborescence de test + 2 paires de clés (exploitation + séquestre), clés privées HORS des racines."""
    data = tmp_path / "data"
    patients = data / "patients"
    public = data / "public"
    patients.mkdir(parents=True)
    public.mkdir(parents=True)
    keys = tmp_path / "offline_keys"
    k1, pub1 = write_identity(keys, "primary")
    k2, pub2 = write_identity(keys, "escrow")

    (patients / "cr_irm_martin.txt").write_text(PHI.format(key=nir_key("2610475112345")), encoding="utf-8")
    (patients / "notes_service.txt").write_text("Réunion d'équipe jeudi.\n", encoding="utf-8")
    (public / "fuite.csv").write_text("IPP,nom\n87654321,Paul Durand\n", encoding="utf-8")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "agent": {"state_dir": str(tmp_path / "state")},
                "roots": [{"path": str(patients), "mode": "encrypt"}, {"path": str(public), "mode": "monitor"}],
                "recipients": [{"name": "primary", "public_key": pub1}, {"name": "escrow", "public_key": pub2}],
                "classification": {"min_level_to_encrypt": "medium", "sensitive_extensions": [".csv"]},
                "llm": {"enabled": False},
            }
        ),
        encoding="utf-8",
    )
    return {
        "tmp": tmp_path,
        "patients": patients,
        "public": public,
        "policy_path": policy_path,
        "policy": load_policy(policy_path),
        "primary_key": k1,
        "escrow_key": k2,
    }
