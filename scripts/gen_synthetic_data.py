"""Génère un jeu de données de santé 100 % SYNTHÉTIQUE pour la démo (patients FR, CN, US).

Usage : python scripts/gen_synthetic_data.py --out demo_data --patients 12
Aucune donnée réelle ne doit jamais être utilisée hors de l'environnement certifié HDS.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path

from faker import Faker

CN_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
CN_CHECK = "10X98765432"
PATHOLOGIES = ["diabète de type 2", "hypertension artérielle", "asthme", "fracture du radius", "pneumopathie"]
EXAMENS = ["IRM cérébrale", "scanner thoracique", "radio du poignet", "bilan sanguin", "échographie"]


def fake_nir(rng: random.Random, sex: int, birth_year: int, birth_month: int) -> str:
    dept, commune, order = rng.randint(1, 95), rng.randint(1, 990), rng.randint(1, 999)
    body = f"{sex}{birth_year % 100:02d}{birth_month:02d}{dept:02d}{commune:03d}{order:03d}"
    key = 97 - (int(body) % 97)
    return f"{body[0]} {body[1:3]} {body[3:5]} {body[5:7]} {body[7:10]} {body[10:13]} {key:02d}"


def fake_cn_id(rng: random.Random, birth: str) -> str:
    body = f"{rng.randint(110000, 659000)}{birth}{rng.randint(0, 999):03d}"
    return body + CN_CHECK[sum(int(d) * w for d, w in zip(body, CN_WEIGHTS)) % 11]


def fake_ssn(rng: random.Random) -> str:
    return f"{rng.randint(100, 665):03d}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="demo_data")
    ap.add_argument("--patients", type=int, default=12)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    Faker.seed(args.seed)
    fakers = {"FR": Faker("fr_FR"), "CN": Faker("zh_CN"), "US": Faker("en_US")}
    out = Path(args.out)
    dossiers = out / "dossiers_patients"
    factu = out / "exports_facturation"
    public = out / "partage_public"
    for d in (dossiers, factu, public):
        d.mkdir(parents=True, exist_ok=True)

    billing = []
    for i in range(args.patients):
        origin = ["FR", "FR", "CN", "US"][i % 4]
        f = fakers[origin]
        dob = f.date_of_birth(minimum_age=18, maximum_age=90)
        sex = rng.choice([1, 2])
        name = f.name()
        ident = {
            "FR": fake_nir(rng, sex, dob.year, dob.month),
            "CN": fake_cn_id(rng, dob.strftime("%Y%m%d")),
            "US": fake_ssn(rng),
        }[origin]
        ipp = f"{rng.randint(10_000_000, 99_999_999)}"
        patho, exam = rng.choice(PATHOLOGIES), rng.choice(EXAMENS)
        pdir = dossiers / f"patient_{ipp}"
        pdir.mkdir(exist_ok=True)

        (pdir / f"compte_rendu_{exam.split()[0].lower()}.txt").write_text(
            f"COMPTE-RENDU — {exam}\nPatient : {name}\nIPP : {ipp}\nNé(e) le {dob.strftime('%d/%m/%Y')}\n"
            f"Identifiant national ({origin}) : {ident}\nTél : {fakers['FR'].phone_number()}\n\n"
            f"Antécédents : {patho}.\nDiagnostic : examen sans anomalie aiguë. Traitement poursuivi.\n",
            encoding="utf-8",
        )
        (pdir / "ordonnance.json").write_text(
            json.dumps(
                {"patient": name, "ipp": ipp, "prescription": [{"molecule": "paracétamol", "posologie": "1 g x3/j"}]},
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        billing.append([ipp, name, origin, f"{rng.randint(80, 4500)}.00", f.email()])

    with (factu / "facturation_internationale.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["IPP", "nom", "origine", "montant_eur", "email"])
        w.writerows(billing)

    # Fichiers non sensibles : l'agent doit les laisser tranquilles.
    (dossiers / "LISEZMOI_service.txt").write_text("Horaires du secrétariat : 8h-18h.\n", encoding="utf-8")
    (public / "menu_cantine.txt").write_text("Lundi : lasagnes. Mardi : poisson.\n", encoding="utf-8")
    (public / "export_oublie_patients.csv").write_text(
        "IPP,nom,diagnostic\n" + f"{billing[0][0]},{billing[0][1]},{PATHOLOGIES[0]}\n", encoding="utf-8"
    )
    print(f"{args.patients} patients synthétiques générés dans {out.resolve()}")


if __name__ == "__main__":
    main()
