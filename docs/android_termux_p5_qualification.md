# Android et Termux : recette physique P5, sans installation

Etat initial sur le téléphone : ANDROID_TERMUX_HOST_FEASIBILITY=PARTIAL.
Le diagnostic rapporté par le propriétaire montre Python >= 3.11,
SQLite WAL / flock, création de processus et PR_SET_CHILD_SUBREAPER en PASS ;
l'index /proc des enfants est inaccessible (PARTIAL). Aucune intégration
guardian P5, reprise SQLite P5, HTTPS P5, veille Doze ou démarrage au boot
n'a été exécutée sur l'appareil au cours de cette livraison.

## Réutilisation des sources immuables

Repo sylvainride/CoGUni (ID 1418009675, owner 265171248).
PR #16 P5 au commit 5a000d8a4c719665534480d065cf5150b772f0a3 :
le guardian et le lecteur GitHub de P5, host_main, ContinuityJournal,
OwnerScheduler et les tests originaux sont préservés sans édition.
PR #17 P6 au commit 4db2457c34e9dd83e96e4ec11ca8b3a5be9654c9 :
les modèles systemd inertes NE fonctionnent pas tels quels dans Termux.

Nouveau : tools/android_termux_p5_qualification.py, outil de qualification
MANUEL, non service et non ordonnanceur. Il compare six Git blob SHA P5
critiques avant d'exécuter les véritables tests du code existant P5.
Cette vérification n'atteste pas toute l'arborescence ou la pérennité.
Les contre-tests tests/test_android_termux_p5_qualification.py en CI Linux
sont exclusivement contractuels, jamais une certification du téléphone.

## Commandes sur le téléphone, uniquement sur choix explicite

Code Git checkout dans HOME privé de Termux, jamais Downloads ni stockage
partagé. Contrôler le remote officiel, le commit et le tree du checkout,
puis lancer depuis la racine du dépôt :

    cd "$HOME/CoGUni"
    git remote -v
    git rev-parse HEAD 'HEAD^{tree}'
    python -B -m tools.android_termux_p5_qualification

Par défaut aucun processus P5 n'est lancé et aucun GET réseau effectué.
Les étapes indépendantes ci-dessous sont des choix humains successifs :

    # Vrai guardian P5, succès court et timeout physique
    python -B -m tools.android_termux_p5_qualification --guardian

    # Risque : forks/double-forks, SIGTERM et SIGKILL de processus réels
    python -B -m tools.android_termux_p5_qualification --deep-guardian

    # Vraies fixtures originales P5, deux OS PID, crash/ACK SQLite, UNKNOWN
    python -B -m tools.android_termux_p5_qualification --resume

    # Quatre GET publics GitHub au travers du guardian original P5
    # Après accord pour le réseau et seulement après succès guardian
    python -B -m tools.android_termux_p5_qualification --deep-guardian --resume --provider

Attention : les tests physiques profonds lancent et tuent des descendants.
Si le guardian ne les nettoie pas, des processus peuvent survivre.
Le harnais stoppe les tests au premier échec et ne permet pas de contourner
le kernel, SELinux ni les refus. Examiner les processus avant toute reprise.
Aucun root, proot de substitution, désactivation d'Android, permission étendue,
WAL/SHM réel, secret, migration ou journal owner existant n'est nécessaire.

Le lecteur réseau original host_github est exécuté via le véritable
host_process.run_bounded, durée maximale 24 secondes, sur un run public
synthétique immuable 38791437019, attempt 1, commit
0a070e653efd091a13164a86b4359d930c80d4ed. Aucune URL configurable,
aucun jeton, aucune écriture GitHub. Un OBSERVED ne vaut ni RESULT_APPLIED ni
preuve d'authentification du canal Chat.

Le JSON résultat n'inclut ni chemins privés, ni PIDs, ni stdout brut.
BLOCKED_SOURCE interdit les essais P5 ; BLOCKED_PROC constate que le
vrai repli P5 sous /proc refuse ; BLOCKED_NON_TERMUX interdit toute
qualification hors Termux. Un code retour 2 signifie non qualifié.
READY_FOR_BACKGROUND_QUALIFICATION ne vaut jamais ANDROID_HOST_VERIFIED :
il reste à qualifier Doze, redémarrage, batterie et ordonnancement réel.

Les options du kit privé initial permettent, séparément, --network,
--soak-minutes 30 et --report-soak, uniquement sur l'appareil. Mesurer les
interruptions, écran verrouillé, données mobiles, WiFi, reboot, gaps
d'observation, arrêt forcé et Termux:Boot, sans supposer 24/7 à partir d'un
essai de 30 minutes. Ne jamais publier journaux, sauvegardes, WAL/SHM,
process listings privés ou relevés sensibles.

## Gates (toutes distinctes)

A : diagnostic primitives Python, enfant, subreaper, SQLite/flock :
    PASS rapporté, mais /proc PARTIAL.
B : guardian P5 original avec reaping réel, double-fork, SIGKILL :
    NOT_TESTED.
C : deux PID, même SQLite P5 synthétique, fence, lease, ACK perdu :
    NOT_TESTED sur Android.
D : quatre GET HTTPS publics P5 via guardian et pins de provenance :
    NOT_TESTED.
E : veille, Doze, réseau indisponible, reboot, interruptions :
    NOT_TESTED.
F : vraie cadence ordonnancée sous quotas Android et politique de coût :
    NOT_TESTED.
G : pont natif Android authentifié avec permissions minimales :
    NOT_TESTED.

Le repli P5 par /proc/[pid]/stat et le reaping réel ne doivent JAMAIS être
simulés pour obtenir un PASS. Le guardian du host n'est pas une sandbox
de workers : bwrap/seccomp restent obligatoires selon les cas originaux.

## Micro-application compagnon, architecture prévue, PAS APK

Moteur unique : conserver Python P5, OwnerScheduler, ContinuityJournal,
fences, quotas, preuves et source pin sur le seul hôte approuvé. Kotlin
n'est pas une seconde autorité et ne doit jamais déclencher un effet métier.

Modules UI futurs : status, alerts, diagnostics, manual-stop,
redacted-export ; présenter UNKNOWN_EFFECT, HANDOFF, SUSPECT, provenance,
version et prochain tick indicatif sans inventer un RESULT_APPLIED.

Première version : affichage d'un rapport volontairement exporté et expurgé,
pas de prise directe sur le filesystem privé Termux, SQLite, HTTP localhost,
exported intent RUN_COMMAND ou écoute background supposée. Un export
n'est pas une attestation de l'owner à lui seul.

IPC futur (conditionnel) : contrat versionné et borné, UID/signature et
audience Android vérifiés, nonce/anti-replay, TTL, consentement, rejet des
commandes arbitraires, aucune donnée privée en transit non autorisé.
Test sur le véritable Android 16 avant tout bouton d'arrêt opérationnel.

Permissions minimales : pas de root, accessibilité, stockage global,
alarmes exactes, GitHub write, secret obligatoire ou permission de
foreground détournée. Notifications uniquement avec consentement.
WorkManager périodique : minimum 15 min, sans timing garanti sous Doze.
Android 16 applique aussi des quotas jobs même lors de certains FGS.

## Choix conditionnels

- Termux seul : candidat de démonstration manuelle après gates B/C/D ;
  aucun hôte durable certifié.
- Termux + APK : architecture UX possible après B–G, pont authentifié
  et droits revus ; aucune APK créée ou installée dans cette PR.
- Linux durable alternatif : préféré si /proc, nettoyage ou endurance
  échouent. Android reste console ; l'hôte Linux exige approbation et
  qualification P5/P6 propres.

Linux CI, simulations et fixtures ne démontrent pas la viabilité physique
Android. Main, PR P5/P6, receiver Chat OFF et routeur OFF demeurent inchangés.
