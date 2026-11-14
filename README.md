# AP-HB Crypt Agent

Agent IA qui **chiffre automatiquement les répertoires de données de santé** de l'AP-HB, pour que même en cas d'intrusion ou de rançongiciel, **aucune donnée ne sorte de l'établissement sous forme lisible**.

- **Chiffrement** : [age](https://age-encryption.org) (X25519 + ChaCha20-Poly1305) via `pyrage`. Aucune crypto maison.
- **Cerveau** : LLM **local** via [Ollama](https://ollama.com) (`qwen2.5:3b` par défaut). Aucune donnée ne part vers un fournisseur cloud.
- **Garde-fous** : le LLM ne voit que des métadonnées pseudonymisées, il ne peut que durcir la politique, et chaque action destructive exige une validation humaine.
- **Traçabilité** : journal d'audit chaîné et scellé par HMAC, rapports d'exécution, contrôle de conformité scriptable.

> ⚠️ Projet pédagogique (atelier EPITA « Conformité et cyber-résilience »). Le dépôt ne contient et ne doit contenir **que des données synthétiques**. Un déploiement réel sur des données de santé exige un hébergement certifié HDS et une validation RSSI/DPO.

---

## Pourquoi ce design

| Exigence | Réponse technique |
|---|---|
| Une exfiltration ne doit rien révéler | Les fichiers sont chiffrés au repos, et le **nom** d'origine est chiffré avec le contenu (le nom visible devient `f_<jeton>.age`). |
| Un serveur compromis ne doit pas pouvoir déchiffrer | L'hôte ne détient **que des clés publiques**. La clé privée reste hors ligne. |
| Pas de perte de données si une clé est perdue | Chiffrement multi-destinataires : clé d'exploitation + **clé de séquestre** (coffre RSSI/DPO). |
| Données de santé jamais envoyées à un tiers | LLM local (Ollama). Il reçoit seulement jeton, extension, taille arrondie, niveau et noms de détecteurs. |
| Un LLM peut se tromper | **Plancher déterministe** : le LLM peut demander plus de chiffrement, jamais moins. Repli automatique sur les règles si Ollama est indisponible. |
| Auditabilité (RGPD art. 5.2, 30, 32) | Journal append-only chaîné + HMAC, sans aucun chemin en clair. Commande `verify` avec code retour pour cron/SIEM. |

Détails : [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · Menaces et limites : [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

## Architecture en une image

```
          ┌──────────────── hôte protégé (serveur / poste) ───────────────┐
 fichiers │  PERCEPTION        PLANIFICATION            ACTION             │
 ───────► │  scan + détecteurs → Ollama (métadonnées  → age encrypt        │
          │  locaux (NIR, ID CN,  pseudonymisées)       (clés publiques)   │
          │  SSN, IPP, termes      + plancher politique → vérif en-tête     │
          │  médicaux…)            + validation humaine → effacement clair  │
          │                                              → journal scellé  │
          │  watch : chiffrement réflexe des nouveaux fichiers (règles)    │
          └────────────────────────────────────────────────────────────────┘
 clé privée de séquestre ── hors ligne ──► `cryptagent decrypt` sur un poste isolé
```

## Démarrage rapide (5 min)

```bash
git clone https://github.com/waytogold17/Compliance-And-Health-Agentic-JWPS.git && cd Compliance-And-Health-Agentic-JWPS
python -m venv .venv && source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -e ".[dashboard,dev]"

# 1. Données synthétiques (patients FR / CN / US)
python scripts/gen_synthetic_data.py --out demo_data --patients 12

# 2. Clés : à générer puis DÉPLACER hors de l'hôte
cryptagent keygen --out ~/cles_hors_ligne --name aphb-exploitation
cryptagent keygen --out ~/cles_hors_ligne --name aphb-sequestre

# 3. Politique : copier puis coller les deux clés PUBLIQUES (age1…)
cp policy.example.yaml policy.yaml

# 4. LLM local (facultatif : sans lui, l'agent passe en mode règles)
ollama serve &            # https://ollama.com/download
ollama pull qwen2.5:3b

# 5. Diagnostic, plan, exécution
cryptagent doctor
cryptagent plan --show-paths     # dry-run
cryptagent run                   # demande confirmation
cryptagent verify                # CONFORME / NON CONFORME (code retour 0/1)
cryptagent audit                 # journal + vérification de la chaîne
```

Restauration (sur un poste isolé qui détient la clé privée) :

```bash
cryptagent decrypt demo_data/dossiers_patients/*/f_*.age -i ~/cles_hors_ligne/aphb-sequestre.key -o restored/
```

Console web :

```bash
streamlit run dashboard/app.py --server.address 127.0.0.1 -- --policy policy.yaml
```

## Commandes

| Commande | Rôle |
|---|---|
| `keygen` | Génère une paire de clés age (privée en `0600`) |
| `scan` | Inventaire et classification, en lecture seule |
| `plan` | Plan proposé par le LLM et corrigé par la politique (dry-run) |
| `run [-y]` | Planifie, demande validation, chiffre, vérifie, rédige le rapport |
| `watch` | Chiffre en continu les nouveaux fichiers (chemin réflexe, sans LLM) |
| `verify [--json]` | Contrôle de conformité : sensibles en clair + intégrité du journal |
| `audit` | Affiche le journal et vérifie la chaîne |
| `lookup <chemin>` | Retrouve le jeton pseudonyme d'un fichier |
| `decrypt` | Déchiffre (hors hôte uniquement) |
| `doctor` | Diagnostic : racines, destinataires, Ollama, **clé privée oubliée sur l'hôte** |

## Déploiement

### GitHub Codespaces (démo)
Ouvrir le dépôt dans un Codespace (4 cœurs recommandés). Le `devcontainer` installe l'agent et Ollama, et télécharge le modèle. Ensuite, suivre le démarrage rapide à partir de l'étape 1.

### Docker Compose (Ollama + agent en surveillance + console)
```bash
python scripts/gen_synthetic_data.py --out demo_data
# renseigner les clés publiques dans docker/policy.docker.yaml
mkdir -p state && UID=$(id -u) GID=$(id -g) docker compose up -d --build
# console : http://127.0.0.1:8501
```

### Serveur Linux (production cible)
1. `pip install .` dans un venv dédié, utilisateur système sans shell.
2. `policy.yaml` en lecture seule (root:agent, 0640). Seules les clés **publiques** y figurent.
3. Service systemd `cryptagent -p /etc/cryptagent/policy.yaml watch`, plus un timer quotidien `run -y` et `verify --json`, envoyés au SIEM.
4. Exporter régulièrement le dernier sceau du journal (`cryptagent audit`) vers un stockage WORM ou le SIEM, pour ancrer la chaîne hors de l'hôte.
5. Compléter avec le chiffrement intégral du disque (LUKS/BitLocker) et des sauvegardes immuables hors ligne (3-2-1-1-0).

### Windows
Même procédure dans PowerShell (Python 3.10+). Le mode `watch` peut tourner comme tâche planifiée au démarrage.

## Tests et sécurité du code

```bash
pytest -q                 # 18 tests : détecteurs, aller-retour chiffrement, garde-fous LLM,
                          # altération du journal, liens symboliques, repli Ollama
bandit -r src -ll         # SAST
pip-audit                 # dépendances
```

La CI GitHub Actions exécute les trois à chaque push.

## Licence

[EUPL-1.2](LICENSE), la licence open source de l'Union européenne, adaptée aux administrations publiques et compatible GPL.
