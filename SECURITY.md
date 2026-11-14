# Politique de sécurité

## Signaler une vulnérabilité
Merci de **ne pas ouvrir d'issue publique**. Utilisez l'onglet *Security → Report a vulnerability* du dépôt GitHub (signalement privé). Réponse sous 7 jours.

## Règles du dépôt
- Aucune donnée réelle, aucune clé privée, aucun `policy.yaml` contenant des données d'environnement ne doit être commité (voir `.gitignore`).
- Toute contribution passe la CI : tests, `bandit`, `pip-audit`.
- La cryptographie est déléguée à age (`pyrage`). Toute proposition de primitive maison sera refusée.
