# Architecture de l'agent

## Boucle agentique

| Étape | Module | Déterministe ? | Détail |
|---|---|---|---|
| Perception | `scanner.py`, `detectors.py` | Oui | Parcours des racines en liste blanche, sans suivre les liens symboliques. Détection locale : NIR (clé mod 97, Corse 2A/2B), carte d'identité chinoise (GB 11643, clé mod 11), SSN US, IPP/MRN, en-têtes CSV patient, e-mail, téléphone, date de naissance, termes médicaux FR/EN/ZH. Les formats Office sont dézippés en mémoire. Les formats opaques (PDF, images) sont chiffrés par précaution. |
| Pseudonymisation | `secrets_store.py` | Oui | Jeton HMAC-SHA256 du chemin, taille arrondie à la puissance de 2. |
| Planification | `brain.py` | **Non (LLM)** | Ollama `/api/chat`, température 0, sortie JSON **contrainte par schéma**, lots de 30 fichiers. Prompt système : règles métier et consigne anti-injection. |
| Garde-fous | `agent.py::plan` | Oui | 1) plancher de la politique : le LLM ne peut pas rétrograder un fichier ; 2) aucune action sur une racine `monitor` ou un fichier déjà chiffré ; 3) fichier absent de la réponse du LLM → décision par règles ; 4) LLM injoignable → moteur de règles. Chaque correction est comptée et journalisée. |
| Validation humaine | `cli.py run`, console | — | Confirmation interactive ou `--yes` explicite, tracée (`plan_approved` / `plan_rejected_by_human`). |
| Action | `crypto.py` | Oui | Flux age multi-destinataires, nom d'origine encapsulé dans la partie chiffrée, fichier temporaire `0600` + fsync + rename atomique. |
| Vérification | `crypto.py` | Oui | En-tête age valide, nombre de destinataires attendu, source inchangée pendant l'opération. Le clair n'est effacé **qu'après** ces vérifications (écrasement aléatoire, renommage aléatoire, suppression). |
| Compte rendu | `brain.py::report`, `agent.py` | LLM + modèle | Le LLM rédige à partir de statistiques agrégées uniquement. Modèle de repli sans LLM. |
| Surveillance | `watcher.py` | Oui | watchdog + attente de stabilité de la taille, chiffrement réflexe sans LLM (latence, disponibilité). |

## Deux vitesses

- **Réflexe (`watch`)** : règles seules, quelques secondes après l'écriture du fichier. Objectif : réduire au minimum la fenêtre pendant laquelle un fichier est en clair.
- **Délibératif (`run`)** : inventaire complet, analyse de risque par le LLM, file « review » pour les cas douteux, rapport pour le RSSI/DPO.

## Format d'un fichier chiffré

```
f_<jeton>.age  =  age v1 [ X25519 → aphb-exploitation | X25519 → aphb-sequestre ]
                  payload ChaCha20-Poly1305 = "CAG1" | len(nom) | nom d'origine | contenu
```

## Clés et secrets

| Élément | Emplacement | Permet |
|---|---|---|
| Clés publiques age | `policy.yaml` sur l'hôte | Chiffrer uniquement |
| Clé privée d'exploitation | Poste de restauration isolé / HSM | Déchiffrer |
| Clé privée de séquestre | Coffre hors ligne (double contrôle RSSI + DPO) | Déchiffrer en dernier recours |
| `agent.key` (32 octets) | `state_dir` en `0700` sur l'hôte | Pseudonymiser et sceller le journal, **pas** déchiffrer |

## Journal d'audit

JSONL append-only. `hash_n = HMAC(k_audit, hash_{n-1} || entrée_n canonique)`. Toute modification, suppression ou réordonnancement est détecté par `cryptagent audit` / `verify`. Pour résister à un attaquant qui obtiendrait `agent.key`, exporter périodiquement le dernier sceau hors de l'hôte (SIEM, stockage WORM).
