# Android / Termux : P5 bloqué, diagnostic manuel seulement

`ANDROID_P5_BLOCKED_INVARIANT_NOT_EQUIVALENT` : aucune borne mémoire
équivalente n'est démontrée pour Android. `run_bounded` et l'entrée directe
du guardian refusent Android, y compris Python Android déclarant `linux`
mais exposant `sys.getandroidapilevel`. Le chemin Linux conserve les limites
CORE=0, AS=512 Mio, CPU et NOFILE=64, ses délais et son nettoyage original.
Ce guardian protège un lecteur hôte de confiance ; il ne remplace jamais
la sandbox bwrap/seccomp des workers.

Un abort sous AS ne prouve ni l'origine interne du signal ni l'impossibilité
de toute solution Android future. AS borne l'espace **virtuel**, pas la RAM
résidente. Les réservations de l'allocateur, le loader bionic, Python et
les appels mmap/brk sont des hypothèses à départager. RLIMIT_DATA,
RLIMIT_RSS, polling RSS ou un timeout ne sont pas des substituts équivalents.
Voir [getrlimit(2)](https://man7.org/linux/man-pages/man2/getrlimit.2.html).

## Sources et frontières

Dépôt officiel `sylvainride/CoGUni`, ID `1418009675`, owner `265171248`.
Vérifier le commit et le tree immuables de la candidate et sa CI depuis
GitHub avant de télécharger ou d'exécuter une nouvelle source. Garder
le checkout dans le HOME privé de Termux, distinct des rapports et journaux.
Le harnais compare six Git blobs critiques : c'est un contrôle partiel de
dérive, pas une signature ni une attestation de l'arbre entier.

Le changement du guardian change `implementation_sha256()`. Les anciennes
configurations et reçus P5 doivent refuser cette source. **Ne pas réécrire
les pins**, WAL, journal original ou checkpoints pour faire passer un refus.
Conserver l'ancienne source requalifiable. Les exemples P6 restent inertes
et épinglés à leur ancienne source ; leur requalification exige un accord
distinct, avec ancre de fraîcheur indépendante pour toute restauration.

## Première commande : observations passives

Depuis un checkout revu et propre :

```sh
git remote get-url origin
git status --porcelain --untracked-files=all
git rev-parse HEAD 'HEAD^{tree}'
python -B -m tools.android_termux_p5_qualification
python -B -m tools.p5_memory_diagnostic
```

Un code retour **2 est attendu** : aucune qualification P5. Aucun enfant
n'est lancé par défaut, aucun réseau ni journal n'est utilisé. L'ancien
harnais conserve les options `--guardian`, `--deep-guardian`, `--resume`
et `--provider` pour rendre leur refus explicite : toutes leurs épreuves
actives sont suspendues par la gate mémoire. Un marqueur Termux ou des
résultats simulés ne peuvent plus produire READY.

## Prochaine sonde unique, uniquement sur choix du propriétaire

Après contrôle passif des sources, le propriétaire peut choisir :

```sh
umask 077
python -B -m tools.p5_memory_diagnostic --probe-exec > "$HOME/coguni-p5-memory.json"
```

Le code retour reste **2**, même si tous les contrôles de recherche passent.
Le rapport ne contient ni chemins, PID, environnement, stderr, stack dump
ni liste de processus. Ne pas publier un rapport physique sans revue.
Le fichier est créé par le shell ; choisir un nouveau nom privé pour
conserver une preuve précédente. Ne pas placer le code sur stockage partagé.

Séquence finie : baseline sans AS, AS après démarrage Python, AS avant
exec du lecteur, puis test négatif. Chaque cas remplace un enfant direct
par `execve`, sans fork détaché ni guardian. Le parent attend cet enfant ;
timeout 3 s par cas, CORE=0, CPU=2/3 s, NOFILE=64. Les VMS/RSS de **soi-même**
sont mesurées avant/après exec. Une réservation mmap PROT_NONE au-dessus
du seuil doit réussir avant AS, puis échouer par ENOMEM sous AS ; aucune
page n'est touchée pour remplir la RAM. Cela teste un refus d'espace virtuel,
pas un OOM résident ni l'équivalence d'un autre limiteur.

Arrêt immédiat au premier abort, timeout, erreur ou trace UNKNOWN. Aucun
retry, daemon ou balayage automatique de seuil. `--as-mib 1024` permet un
second seuil borné de recherche, **uniquement si un nouvel élément le
justifie et sur nouveau choix humain** ; le seuil P5 reste 512 Mio.
Ne pas répéter simplement des aborts déjà observés.

Lecture du résultat :

| Observation | Conclusion bornée |
| --- | --- |
| Baseline échoue | Sonde ou runtime non qualifié ; arrêter |
| AS après exec échoue | AS affecte aussi le runtime déjà chargé ; cause interne inconnue |
| Après exec passe, avant exec abort | Chemin exec/initialisation à investiguer ; pas preuve du composant fautif |
| Pas de marqueur READER_PYTHON | Aucun code Python lecteur observé ; pas de PID ou cleanup inventé |
| mmap non borné échoue aussi | Test négatif non discriminant ; aucune preuve d'enforcement |
| Tous les cas passent | Recherche locale seulement ; P5 Android reste bloqué |

Le rapport distingue `FAILED_BEFORE_READER`, `EXEC_PATH_ABORT`, `READER_ABORT`,
`READER_FAILED`, `TIMEOUT`, `UNKNOWN`, `SOURCE_PIN_BLOCKED` et les étapes
connues. READER_EXEC marque une tentative, pas la réussite d'execve.
Sans READER_PYTHON, le signal peut encore appartenir au contrôleur,
au loader ou au runtime : aucune attribution au lecteur n'est prouvée.
La sonde ne lance pas
le guardian : aucun de ses résultats ne prouve son reaping.

## Contrôle réutilisable de dérive et fraîcheur

La capacité `RLIMIT_AS_EXEC_AND_DENIAL` porte son evidence, fingerprint,
`last_verified_at` et TTL maximal 3600 s. L'empreinte lie source P5,
outil, Python, architecture, API Android déclarée, kernel et seuil.
`evidence_decision` refuse absence, UNKNOWN, horodatage futur, expiration,
types invalides ou dérive. `CURRENT_RESEARCH_ONLY` reste une observation
non signée, jamais une autorisation. Il ne couvre pas tous les packages
Termux/libc ni une identité matérielle : exporter ces inconnues à la revue.

Le circuit d'arrêt est local à une invocation. Il n'existe pas de compteur
persistant ni d'ordonnanceur automatique. Conserver les rapports privés et
ne relancer qu'après un changement probant ; orchestration future plafonnée
à deux tentatives, puis NEEDS_OWNER. Aucun effet UNKNOWN n'est rejoué.

## Gates restantes et choix d'hôte

Avant toute future voie P5 Android : enforcement équivalent démontré,
guardian physique/reaping complet malgré permissions /proc, source fraîche,
reprise du même journal synthétique, leases/fences/ACK, quatre GET publics
sur accord, puis énergie/Doze/boot et quotas séparément. SIGKILL du parent,
double-fork, réseau et endurance restent suspendus. Aucune CI Linux ou
simulation Android ne remplace ces preuves.

**Fallback retenu : hôte Linux durable qualifié, Android comme interface.**
La sélection et le déploiement de cet hôte demandent une décision séparée.
Actions CI est éphémère, pas un serveur permanent. Aucune installation,
fusion, migration ou activation n'est effectuée par ces outils.

Le compagnon Android futur affiche des rapports expurgés et les décisions
humaines. IPC authentifié, UID/signature, audience, nonce/TTL et anti-replay
précèdent toute commande. Pas d'intent RUN_COMMAND exposé, de tunnel,
token ou accès SQLite implicite. Chat, Work et Codex ne sont pas requis
pour exécuter le moteur déterministe ; leur intégration est un chantier
distinct. `AUTONOMOUS_AI_INSTALLED=false`.
