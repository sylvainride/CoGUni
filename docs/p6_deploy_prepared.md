# P6 — Préparation du déploiement P5, sans installation

Statut: PREPARED_NOT_INSTALLED. Aucun hôte, service, timer, cron, compte,
secret, moteur IA ou autorisation d'écriture externe n'est créé ou activé.

Identité figée: dépôt sylvainride/CoGUni (ID 1418009675, owner 265171248).
Code P5 revu: commit 5a000d8a4c719665534480d065cf5150b772f0a3,
tree 43071a27f344b823d88a0f5118dca4753bd79cde. Si cette identité
évolue, le contrat doit être refusé et soumis à une nouvelle revue humaine.
Le code P5 et sa CI ne sont pas modifiés par cette préparation.

## Artefacts publiés, de portée inerte

- universal/host_deploy_plan.py: valide purement des déclarations JSON;
  contrôles de types exacts, clés fermées, versions SHA immuables, chemins
  constants sans caractères de commande, tous effets/permissions à false.
- tools/p6_deploy_preflight.py: lit uniquement le JSON indiqué par --plan,
  refuse les doublons, champs non prévus, liens symboliques finaux et JSON
  tronqué; émet un verdict sans chemin privé ni information d'hôte.
  Commande locale de contrôle statique uniquement:
  python3 -B -m tools.p6_deploy_preflight --plan deploy/examples/p6_proposal.example.json
  Code retour 0 signifie uniquement que la PROPOSITION est valide, pas
  une preuve d'installation, de permission, de durabilité, de restauration ou de GET.
- deploy/examples/p6_proposal.example.json: objet entièrement synthétique,
  non utilisable comme configuration privée P5.
- deploy/examples/coguni-observer.service.example et .timer.example:
  modèles textuels NON installés. Aucune section [Install]; une condition
  volontairement fausse et RefuseManualStart dans [Unit] bloquent un départ
  accidentel. Les options systemd nécessitent revue sur l'hôte futur.
- tests/test_p6_deploy_plan.py: refus adversariaux, parité des templates,
  CLI et absence d'effets. Le full CI découvre test_*.py. Le subset
  owner-contracts P5 utilise une liste figée et peut ne pas inclure cette
  nouvelle suite; cela ne justifie pas de modifier tools/run_ci_checks.py.

## Alignement avec P5 (pas de nouvelle autorité)

La CLI P5 existante a exclusivement les opérations fingerprint,
observe-once et run. Elle utilise ContinuityJournal, OwnerScheduler,
PassiveSupervisor, mission_polling, un guardian de processus et une lecture
GitHub publique à quatre GET fixes. P6 ne les remplace pas.

Les limites privées P5 sont bornées:
- hard_timeout_seconds: 0,1 à 30 secondes
- max_ticks: 1 à 16
- max_seconds: 1 à 300
- interval_seconds: 1 à 60 secondes

Le plan P6 impose au moins ceil(hard_timeout + 4) secondes pour le budget
global, et cadence_seconds entre 600 et 86400, avec
cadence_seconds >= max_seconds + 30. L'exemple est reader 5 s, max 2 ticks,
durée 30 s, intervalle 5 s, cadence 900 s. Le one-shot a
TimeoutStartSec=43s (durée P5 + overhead guardian + marge systemd).
Le timer a OnUnitInactiveSec=900s, Persistent=false: pas de rattrapage
implicite après downtime. Les budgets de polls et de runs du journal owner
ne sont jamais rechargés par le timer ni par un restart.

Un résultat P5 avec code de sortie zéro peut être HANDOFF: ce n'est pas
une preuve PASS. La perte d'ACK d'une lecture consomme son intention durable
et exige réconciliation dans le journal original; pas de nouvel effet sur
hypothèse. UNKNOWN_EFFECT, lease échue, source différente, dérive de fence,
quota ou silence sain restent sous la politique de refus P5. Aucun reçu
de worker, de proposition ou de fournisseur ne devient une preuve signée.

## Gates de l'installation future : toutes NON EXECUTEES

1. Identité et autorité: recontrôler le dépôt officiel, les protections,
   les PR P5/P6, la CI au SHA exact et le diff; obtenir l'accord humain
   spécifique sur la plateforme, le coût, les permissions et le placement.
   La CI PR empilée est indépendante de la CI push.
2. Hôte: choisir un Linux durable avec administrateur identifié, support
   /proc et PR_SET_CHILD_SUBREAPER, Python >=3.11, DNS/TLS, ressources,
   quotas et programme de mises à jour. Une CI Actions éphémère n'est pas
   un hôte persistant. Aucune machine n'est sélectionnée par P6.
3. Permissions: mesurer en vrai les sources sous /srv/coguni/source,
   distinctes de /var/lib/coguni-private; owner, chmod 0700 du répertoire
   privé, 0600 des fichiers, absence de symlink/hardlink, WAL/SHM,
   stockage local stable et locks SQLite. Ne pas inférer ces faits du
   JSON ni du mode source fourni.
4. Reprise anti-rollback: qualifier une ancre monotone indépendante
   liée aux sauvegardes, UUID, locator, epoch et journal. Un SQLite
   restauré au même emplacement avec même identité peut être ancien.
   Tant que l'ancre externe n'existe pas, BACKUP_FRESHNESS=NOT_RUN.
   Aucun nouveau magasin ni migration implicite n'est permis en P6.
5. Provenance provider: qualifier les quatre GET HTTPS publics fixes P5
   avec identities GitHub, run/attempt, blob/tree/mode et ref exacts,
   ainsi que CA/proxy et rate limits. Pas de token Github write.
   HTTPS ne prouve pas l'autorisation de l'appelant ni un effet métier.
6. Guardian OS: vérifier physiquement le délai du reader, cleanup,
   processus descendants, signaux, FD, mémoire/CPU et l'absence de
   fuite de secrets. SIGKILL du guardian et attente noyau
   ininterruptible restent hors garantie.
7. Service et timer: un administrateur prépare, compare et examine
   un fichier réel adapté, séparément de ces modèles volontairement
   invalidants. NoNewPrivileges, ProtectSystem=strict, ProtectHome=yes,
   PrivateTmp, ReadWritePaths limité et UMask 0077 doivent être revus.
   Logs privés, rétention et limites systemd restent à décider.
   Deux processus OS P5 distincts doivent être qualifiés sur le MEME
   journal original; conserver fence, lease, budget et preuve de lecture.
   Ne rien activer sans approbation nouvelle.
8. Reversibilité: prévoir l'arrêt humain du futur timer puis du service,
   quiescence des writers, snapshot cohérent WAL/SHM, provenance et
   ancre de fraîcheur indépendante; restaurer uniquement après revue
   owner, jamais en écrasant un état incertain. Conserver reçus et
   journal original. Aucun démarrage / arrêt / suppression n'est exécuté
   dans P6.

## Menaces et limites qualifiées

Le schéma strict bloque toute commande, URL, token, permission write,
AI facturable, chemin arbitraire, lecture de production, état enabled=true
ou attestation auto-déclarée. L'outil produit uniquement
PREPARED_NOT_INSTALLED/STATIC_INTENT_ONLY et gates NOT_RUN. Les tests
n'attestent ni système de fichiers réel, ni OS, ni effet réseau, ni
compatibilité systemd de l'hôte absent. Les workers CoGUni conservent
leur obligation sandbox bwrap/seccomp; le guardian du reader n'en
est pas un substitut.

La protection de main, le broker distant inerte, le routeur OFF et
l'absence de receiver Chat authentifié demeurent inchangés. Les 349
exigences et 75 tickets historiques ne sont pas clos par analogie.

## Reprise Codex sans refaire P5

Vérifier le HEAD vivant de la PR #16 avant toute promotion, comparer la
branche P6 contre ce SHA et refuser toute modification d'un chemin
préexistant. Lire le rapport privé P5 déjà livré et la preuve CI push
de P6; ne pas fusionner ni rebaser sans rapprochement owner.
Compléter les gates P5 virtuel merge et installation seulement après
décisions et preuves distinctes. Les ZIPs et rapports privés restent
hors dépôt GitHub public.

Etat cible P6_DEPLOYMENT_PREPARED=PASS_SCOPED, pour la fabrication testée
de contrats, modèles et CI uniquement.
EXTERNAL_SCHEDULER_INSTALLED=false.
AUTONOMOUS_AI_INSTALLED=false.
