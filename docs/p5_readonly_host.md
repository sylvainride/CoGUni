# Hôte P5 privé en lecture seule — procédure proposée, non installée

P5 fournit un programme Linux indépendant du Chat, appelé pour une observation
ou une série finie de ticks. Il réutilise le `ContinuityJournal`,
`OwnerScheduler`, `PassiveSupervisor` et les descripteurs de reprise existants.
Il observe uniquement des missions publiques synthétiques déjà réservées par
leur propriétaire. Il ne soumet aucun workflow, ne rejoue aucun calcul, ne
renouvelle aucune lease, ne récupère aucun fence et n'applique aucun résultat.

Ce document décrit une installation à examiner sur un hôte privé. Aucun compte
système, service, timer, cron, hôte distant ou modèle IA n'est installé par ce
guide ni par la CLI. Une installation réelle demande l'autorisation du
propriétaire. `P5_HOST_CODE_VERIFIED`, `P5_PROVIDER_READ_VERIFIED`,
`P5_EXTERNAL_SCHEDULER_INSTALLED` et `AUTONOMOUS_AI_INSTALLED` sont des
qualifications distinctes. Une CI sur runner éphémère ne prouve pas la
persistance d'un hôte privé.

## Préparer une version revue et un journal propriétaire original

Utiliser Linux avec `/proc`, Python 3.11 ou plus récent et le support kernel de
`PR_SET_CHILD_SUBREAPER`. Les composants du host utilisent la bibliothèque
standard. Le répertoire source doit rester distinct des données privées et
protégé contre les modifications par une mission ou un fournisseur. Le compte
d'exécution n'a besoin d'aucun token GitHub, agent SSH ou droit d'écriture
GitHub. Conserver uniquement les réglages proxy et CA nécessaires à HTTPS.

Avant toute installation, vérifier sur GitHub l'identité du dépôt
`sylvainride/CoGUni` : repository ID `1418009675`, owner ID `265171248`, branche
P5 et commit exact qualifié par la preuve CI. Installer ce snapshot exact,
conserver son SHA Git et son tree, puis calculer l'empreinte de l'implémentation :

```sh
# Exemples à examiner ; aucun de ces emplacements n'est installé par P5.
SOURCE_SHA='REMPLACER_PAR_LE_COMMIT_P5_QUALIFIE_40_HEX'
SOURCE_DIR='/srv/coguni/source'
git clone --no-checkout https://github.com/sylvainride/CoGUni.git "$SOURCE_DIR"
git -C "$SOURCE_DIR" fetch --no-tags origin "$SOURCE_SHA"
git -C "$SOURCE_DIR" checkout --detach "$SOURCE_SHA"
git -C "$SOURCE_DIR" rev-parse HEAD 'HEAD^{tree}'
cd "$SOURCE_DIR"
python3 -B -m universal.host_main fingerprint
```

`fingerprint` ne lit aucun journal. Il retourne `implementation_sha256`, calculé
sur tous les fichiers Python ordinaires de `universal/`. Copier cette empreinte
dans la configuration privée après avoir vérifié le snapshot et sa provenance.
L'empreinte ne constitue ni une signature du distributeur ni une autorisation.
Une modification du code est refusée au chargement et après une lecture
fournisseur. Ne pas recalculer simplement l'empreinte pour contourner un refus.

Le propriétaire prépare **hors de cette CLI**, avec les API propriétaires
existantes et leurs contrôles d'accès/source, le journal original, sa politique
`OwnerScheduler`, ses tâches synthétiques et leurs réservations. Il vérifie
leurs pins, leases, fences, quotas et bindings fournisseur. La CLI n'offre ni
commande `init`, ni création de tâche, ni outil de remise à zéro. Les exemples
de tests créant une fixture ne sont pas une procédure de migration d'un vrai
journal.

Le journal, la configuration et les checkpoints doivent utiliser des chemins
absolus canoniques hors du source, sans symlink. Le répertoire privé immédiat
doit appartenir au compte du host et être réservé à ce compte, typiquement mode
`0700`. Les fichiers doivent être ordinaires, à lien unique, appartenir au même
compte et être sans droits groupe/autres, typiquement mode `0600`. Le host
emploie également `umask 077`. SQLite nécessite le droit d'écrire dans ce
répertoire pour son journal WAL/SHM. Utiliser un stockage local réellement
persistant avec des sémantiques de verrouillage et de durabilité qualifiées.

La politique `scheduler` de la configuration doit être la copie exacte de la
politique originale `ps-config`, y compris aliases de ressources et casse.
Changer le fichier de configuration, redémarrer le programme ou exporter un
checkpoint ne restaure aucun budget. Le reçu propriétaire P5 ancre également
la configuration et l'implémentation à travers les redémarrages.

### Compatibilité des anciens journaux P3/P4

Le paramètre optionnel `ContinuityJournal(..., busy_timeout_ms=...)` conserve la
valeur historique de **10 000 ms** pour les appelants existants. Le host P5
choisit explicitement `0` afin de refuser immédiatement une contention SQLite
plutôt que dépasser sa durée bornée. Cela ne change ni les tables, ni l'identité,
ni les pouvoirs du journal.

Cette extension change néanmoins le hash source de `continuity.py`, que les
contrats historiques du scheduler épinglent. Un journal préparé avec les
sources P3/P4 doit donc refuser une reprise directe sous les sources P5. Il
exige une requalification explicite par le propriétaire, hors mission et hors
CLI observateur. Le host ne migre pas les pins, ne réécrit pas `ps-config`, ne
supprime aucun reçu et ne crée aucun journal de remplacement. Aucun reset ou
rebind ne permet de contourner cette frontière.

## Configuration privée : exemple volontairement invalide

Le JSON ci-dessous illustre uniquement la forme du contrat. Les marqueurs
`REMPLACER_...`, les SHA entre chevrons et `run_id: 0` sont **invalides** et
doivent être refusés. Copier les valeurs depuis les autorités originales
revues, jamais depuis une mission, un worker ou une assertion de confiance.
Ne pas publier la configuration remplie dans GitHub.

```json
{
  "schema": 1,
  "mode": "READ_ONLY_PUBLIC_SYNTHETIC",
  "journal_path": "/var/lib/coguni-private/journal.sqlite",
  "journal_id": "<IDENTITE_JOURNAL_ORIGINAL_64_HEX>",
  "implementation_sha256": "<EMPREINTE_SOURCE_REVUE_64_HEX>",
  "scheduler": {
    "max_parallel": "REMPLACER_PAR_VALEUR_ORIGINALE",
    "run_budget": "REMPLACER_PAR_VALEUR_ORIGINALE",
    "duration_budget": "REMPLACER_PAR_VALEUR_ORIGINALE",
    "poll_budget": "REMPLACER_PAR_VALEUR_ORIGINALE",
    "max_backlog": "REMPLACER_PAR_VALEUR_ORIGINALE",
    "resource_aliases": [],
    "case_insensitive_targets": []
  },
  "tasks": [
    {
      "task_id": "REMPLACER_PAR_TACHE_ORIGINALE",
      "binding": {
        "repository_id": 1418009675,
        "actor_id": 265171248,
        "run_id": 0,
        "attempt": 1,
        "commit": "<COMMIT_REQUETE_ORIGINAL_40_HEX>",
        "branch": "<BRANCHE_SYNTHETIQUE_ORIGINALE>",
        "code_ref": "<CODE_REF_ORIGINAL_40_HEX>",
        "request_sha256": "<EMPREINTE_PAQUET_ORIGINAL_64_HEX>"
      }
    }
  ],
  "limits": {
    "hard_timeout_seconds": 5,
    "max_ticks": 2,
    "max_seconds": 30,
    "interval_seconds": 5
  }
}
```

Les listes vides d'aliases ne conviennent que si elles sont exactement celles
du journal original. Les limites du host sont finies : reader entre 0,1 et
30 secondes, au plus 16 ticks, durée totale entre 1 et 300 secondes, intervalle
entre 1 et 60 secondes. Il peut sélectionner de 1 à 16 tâches explicites.
Ces bornes n'augmentent jamais les quotas ou échéances propriétaires existants.

## Observer, sortir, puis reprendre dans un autre processus

Après autorisation d'installation et préparation propriétaire, les commandes
suivantes illustrent deux lancements OS distincts. Les chemins sont des exemples
et la configuration ci-dessus ne suffit pas à les exécuter.

```sh
cd /srv/coguni/source
umask 077
python3 -B -m universal.host_main observe-once \
  --config /var/lib/coguni-private/host.json \
  --checkpoint /var/lib/coguni-private/checkpoint.json

# Le premier processus est terminé. Celui-ci rouvre le même SQLite original.
python3 -B -m universal.host_main run \
  --config /var/lib/coguni-private/host.json \
  --resume-hint /var/lib/coguni-private/checkpoint.json \
  --checkpoint /var/lib/coguni-private/checkpoint.json
```

`observe-once` réalise au plus un tick ; `run` respecte simultanément
`max_ticks` et `max_seconds`, puis sort. Le verrou non bloquant porte sur
l'inode du journal original ; une contention ou un remplacement du fichier
provoque un refus. Le journal garde les reçus et comptes originaux entre les
processus. L'intention de lecture est journalisée avant l'appel réseau : une
perte d'ACK ne restitue pas son budget. La cadence est durable, y compris après
un redémarrage. Aucun échec de lecture ne soumet ou ne répète le job source.

Le checkpoint est un fichier privé contenant un reçu d'observation et un
**indice non autoritaire** `persistent_resume`. Il ne contient aucun droit de
dispatch ou de reprise de lease. Son import consulte à nouveau le même journal
et vérifie identité, révision, fence, contrat et binding. Un indice périmé ou
copié sur un autre store est refusé. Préserver le journal original et examiner
le refus avec les API propriétaires ; ne pas remplacer le store pour faire
passer un checkpoint. Une sauvegarde restaurée au même chemin avec une
identité copiée exige toujours une ancre de fraîcheur indépendante : ce fichier
de reprise ne prouve pas l'absence d'un rollback.

Une lease expirée conduit au handoff ; le host n'en reprend pas le contrôle.
`UNKNOWN_EFFECT` conserve le binding et exige la réconciliation du seul effet
original, sans nouvelle lecture automatique de ce host ni nouvelle exécution
métier. Un run queued longtemps ou running sans stdout n'est pas déclaré mort
par son silence. Un succès fournisseur ne vaut jamais `ACCEPTED_APPLIED` et ne
libère aucune dépendance sans les contrôles propriétaires existants.

La sortie JSON est un compte rendu à conserver en privé. Une sortie CLI zéro
peut contenir `HANDOFF` : elle ne certifie pas une observation réussie. Un refus
d'entrée/autorité retourne le code 2 avec une raison publique bornée. Ne pas
publier le journal, la configuration, le checkpoint ou la sortie brute comme
artifact CI.

## Frontière fournisseur et arrêt physique du reader

Le seul fournisseur réseau qualifié est le dépôt public synthétique fixé dans
`host_github.py`. Chaque lecture réussie utilise quatre GET HTTPS bornés sur
`api.github.com` : dépôt, tentative de run, paquet original à son commit immuable
et arbre Git. Le reader vérifie owner/repository/acteur, push/workflow,
run/attempt, commit/ref, `code_ref`, digest du paquet et mode fichier ordinaire
dans l'arbre. Il ne suit aucune redirection, ne reçoit aucune URL ou commande
configurable et ne possède aucune méthode d'écriture.

Cette provenance est limitée aux métadonnées GitHub publiques reçues par HTTPS.
Elle **n'authentifie pas l'appelant** du host, n'atteste aucun artefact de
résultat et ne prouve aucune application. Aucun token n'est demandé. Les erreurs
HTTP, quota, provenance, réponse tronquée ou délai donnent `UNKNOWN`/`HANDOFF`,
jamais un PASS hors ligne. Un échec `403` n'autorise pas à ajouter un token
d'écriture ou à élargir l'allowlist.

Le lecteur est du code hôte revu, exécuté derrière `host_process.run_bounded`,
dans un processus distinct. Un guardian Linux dédié devient subreaper,
surveille le pipe de vie du parent, borne stdin/stdout/stderr et termine puis
réape les descendants, y compris sessions détachées et double-forks. Il utilise
`/proc` et n'interprète pas l'absence du fichier kernel optionnel `children`
comme une preuve d'absence de descendants. `OK` exige une sortie reader zéro
et un nettoyage vérifié. Les FD SQLite et les credentials inutiles ne sont pas
hérités. Des limites mémoire/CPU et l'interdiction de core dump s'appliquent au
reader.

Réserver **3 secondes** d'overhead (`HARD_OVERHEAD_SECONDS`) autour du délai
reader pour lancement, arrêt et reap. Le host réserve cette marge dans sa
durée globale avant de commencer une lecture. SIGTERM/SIGINT demandent le
nettoyage avant propagation ; SIGKILL du host ferme son pipe de vie et déclenche
encore le nettoyage par le guardian. Le reaping final du guardian orphelin
dépend d'init/systemd. SIGKILL du guardian lui-même, processus noyau
ininterruptibles et noyau défaillant restent hors garantie ; un nettoyage non
prouvé n'est jamais qualifié `OK`. Cette frontière de processus est un mécanisme
de délai pour code de confiance, pas une sandbox pour code de mission. Les
protections bwrap/seccomp existantes des workers demeurent obligatoires.

## Option systemd à examiner après autorisation

Le lancement manuel suffit au programme P5. Un futur ordonnanceur peut appeler
une commande finie avec le même stockage persistant. Voici seulement un exemple
de service oneshot, **ni écrit dans `/etc`, ni activé par P5** :

```ini
[Unit]
Description=CoGUni private read-only synthetic observation

[Service]
Type=oneshot
User=coguni-observer
Group=coguni-observer
WorkingDirectory=/srv/coguni/source
ExecStart=/usr/bin/python3 -B -m universal.host_main observe-once --config /var/lib/coguni-private/host.json --checkpoint /var/lib/coguni-private/checkpoint.json
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/coguni-private
KillMode=control-group
TimeoutStartSec=40
TimeoutStopSec=5
StandardOutput=null
StandardError=null
```

Le compte, ses droits, la version Python, le proxy/CA, les bornes systemd et le
stockage doivent être examinés sur l'hôte réel. L'exemple `TimeoutStartSec=40`
suppose `max_seconds=30` ; adapter les bornes ensemble sans réduire les délais
de nettoyage. Si des logs sont souhaités, choisir explicitement une destination
privée et une rétention bornée. Un timer ultérieur doit respecter la cadence
et les budgets originaux ; il n'est pas fourni ni activé ici. Aucun
`systemctl enable`, démarrage distant ou déploiement n'est exécuté par P5.

Pour l'audit, conserver en privé le SHA/tree source exact, l'empreinte
d'implémentation, OS/Python, commandes et résultats, IDs des CI push et leurs
commits, mesures du hard timeout, deux PID de host distincts et états avant/après
du même journal. Rapporter séparément la lecture fournisseur réelle, les
contre-épreuves synthétiques, toute vérification non exécutée et l'absence
d'installation externe. Les limites G5 des 66 scénarios P4 restent inchangées.
