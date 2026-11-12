# Modèle de menaces (STRIDE simplifié)

| Menace | Scénario | Mesure dans l'agent | Limite / mesure complémentaire |
|---|---|---|---|
| **Exfiltration** (I) | Un attaquant copie les partages de fichiers | Fichiers et noms chiffrés, clé privée absente de l'hôte | Les fichiers **en cours d'utilisation** sont en clair en mémoire et dans les applications métier |
| **Compromission de l'hôte** (E) | Root sur le serveur de fichiers | L'attaquant n'obtient que des clés publiques | Il peut lire les **nouveaux** fichiers avant leur chiffrement : réduire la fenêtre avec `watch`, surveiller l'EDR |
| **Rançongiciel** (D) | Re-chiffrement des fichiers `.age` | — | Le chiffrement **ne protège pas la disponibilité** : sauvegardes immuables hors ligne (3-2-1-1-0), tests de restauration (PRA) |
| **Altération du journal** (T, R) | Effacer les traces | Chaîne HMAC, `verify` en échec | Ancrage externe du dernier sceau (SIEM/WORM) |
| **Perte de clé** (D) | Clé d'exploitation perdue | Destinataire de séquestre | Procédure de double contrôle et test de restauration semestriel |
| **Fuite vers le LLM** (I) | Données de santé dans le prompt | Métadonnées pseudonymisées seulement, LLM local | Vérifié par test (`test_ollama_brain_receives_only_pseudonymized_metadata`) |
| **Injection de prompt** (T) | Nom ou contenu de fichier contenant des instructions | Le LLM ne voit ni nom ni contenu, sortie sous schéma JSON, plancher déterministe | — |
| **LLM défaillant** (D) | Hallucination, panne Ollama | Garde-fous + repli règles | — |
| **Lien symbolique / traversée** (E) | Lien vers `/etc` dans un partage | Liens non suivis, nom restauré réduit à son basename | — |
| **Rémanence du clair** (I) | Récupération forensique sur SSD | Écrasement + renommage aléatoire | **Non garanti** sur SSD / CoW / snapshots : chiffrement intégral du disque obligatoire |
| **Métadonnées** (I) | Taille et date des fichiers | Taille arrondie côté LLM | La taille approximative et les horodatages restent visibles sur disque |

## Cadre réglementaire visé

- RGPD art. 9 (données de santé), art. 25 (protection dès la conception), art. 32 (chiffrement), art. 34.3.a (pas de notification aux personnes si les données sont inintelligibles pour un tiers).
- Hébergement de données de santé : certification HDS (Code de la santé publique, art. L.1111-8) pour tout hébergement externalisé.
- AI Act : l'agent n'entre pas dans les usages listés à haut risque, mais il est documenté (finalité, supervision humaine, journalisation) par bonne pratique.
