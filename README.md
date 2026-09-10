# Forensic Imager — Windows / Autopsy

Application Python + Tkinter en français pour acquérir **un disque physique entier**
en RAW (`.dd` / `.raw`) ou E01 EnCase6 avec libewf. Le disque est ouvert uniquement
avec `GENERIC_READ`. L'application ne propose aucune écriture sur la source.

## Installation et lancement

Windows 10/11 x64 ; **Python 3.11 ou supérieur**, version standard de
[python.org](https://www.python.org/downloads/windows/), avec **pip et Tcl/Tk**.
Python 3.12 est conseillé. Ne pas utiliser la distribution Python « embeddable »,
qui n'inclut pas Tkinter. Aucun service ni pilote n'est installé par l'application.

Extraire l'archive, ouvrir PowerShell dans le dossier contenant `main.py` :

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

Adapter `-3.12` à la version installée. Il n'est pas nécessaire d'activer le
virtualenv ou de modifier la politique d'exécution PowerShell.

Le programme propose automatiquement une **relance administrateur par UAC** en
conservant l'interpréteur du virtualenv. En cas de refus, aucune acquisition
n'est démarrée. Autre possibilité : clic droit sur Windows Terminal/PowerShell,
**Exécuter en tant qu'administrateur**, se placer dans le dossier et lancer :

```powershell
.\.venv\Scripts\python.exe main.py
```

L'élévation nécessite les droits d'un compte administrateur. `requirements.txt`
ne contient que `pywin32` ; Tkinter fait partie de l'installation Python standard.

## Préparer le disque source

La case **Lecture seule forcée** est cochée par défaut. Elle exige que Windows
déclare le disque **déjà en lecture seule**, via
`IOCTL_DISK_GET_DISK_ATTRIBUTES`, et revérifie cet attribut avant chaque lecture.
Si ce contrôle échoue ou n'est pas pris en charge par le pilote, l'acquisition
est refusée. Le programme **ne modifie pas automatiquement cet attribut**.

L'ouverture `GENERIC_READ` interdit les écritures par ce programme, même case
décochée. La protection logicielle du disque ne protège pas contre les modifications
antérieures à sa mise en place, un changement de protection par un administrateur,
ni les opérations internes du firmware. Un bloqueur matériel adapté reste la
protection à privilégier. Windows peut avoir monté ou modifié un média avant
le lancement du programme.

Pour une protection logicielle Windows, préparer le disque dans une session
PowerShell administrateur, **après avoir identifié précisément son numéro** :

```powershell
Get-Disk | Format-Table Number,FriendlyName,SerialNumber,Size,IsReadOnly,IsSystem,IsBoot
# Remplacer N par le numéro vérifié du disque source :
Set-Disk -Number N -IsReadOnly $true
Get-Disk -Number N | Format-List Number,FriendlyName,SerialNumber,IsReadOnly
```

Ces commandes modifient la politique Windows du disque ; elles ne sont pas
exécutées par le logiciel. Ne pas initialiser, formater, réparer ou lancer CHKDSK
sur la source. Certains bloqueurs matériels n'exposent pas l'attribut Windows :
dans ce cas, vérifier leur protection indépendamment puis décocher la case en
acceptant le message explicatif.

Le disque système/de démarrage actuellement utilisé est refusé. Pour l'acquérir,
démarrer depuis un autre disque Windows et le connecter comme source protégée.
L'image reflète les secteurs **adressables exposés par Windows** : aucune
extraction de HPA/DCO cachés, de mémoire flash interne ou de secteurs déjà
éliminés par TRIM. BitLocker reste chiffré dans une acquisition physique.

## Utilisation

1. Sélectionner le disque physique dans la liste : numéro, modèle, taille en Gio,
   lettres de volumes et type de bus. L'inventaire utilise WMI via pywin32 :
   `Win32_DiskDrive`, associations partitions/volumes, et `MSFT_Disk`. WMIC n'est
   pas nécessaire. **Rafraîchir la liste** permet de détecter un branchement récent.
   USB est reconnu ; le caractère interne/externe d'un disque SATA/NVMe reste
   une estimation, car tous les boîtiers ne le signalent pas.
2. **Parcourir** : choisir un dossier existant et un nom d'image sur un **autre
   disque physique**. Un sous-dossier horodaté avec identifiant unique est créé.
   Le nom choisi est normalisé selon le format. Aucun fichier existant n'est
   écrasé.
3. Choisir `.dd`, `.raw` ou `.E01`, puis un ou plusieurs hashes :
   MD5, SHA1, SHA256. SHA256 est coché par défaut ; MD5/SHA1 sont fournis pour
   l'interopérabilité avec les outils d'analyse.
4. Choisir le buffer : 512 Kio, 1 Mio, 4 Mio ou 8 Mio. Les accès sont regroupés
   pour la vitesse ; en cas d'erreur, ils sont subdivisés en secteurs logiques.
   Les géométries 512 octets et 4096 octets sont prises en charge.
5. Pour E01, sélectionner la compression : aucune, rapide ou maximale.
6. Renseigner examinateur, numéro de dossier et description, puis démarrer.
7. La barre représente les **trois passes**. Les informations indiquent le
   pourcentage de la passe et global, la vitesse moyenne en Mio/s, et le temps
   restant estimé **de la passe courante**. Les pauses sont incluses dans la
   durée et la moyenne. Il n'y a pas d'estimation fiable de la durée totale
   avant d'avoir mesuré les trois types d'E/S.
8. **Pause/Reprendre** conserve les handles et hashes en mémoire. Il s'agit d'une
   pause dans le processus courant, pas d'une reprise après fermeture ou coupure.
   **Annuler** conserve les données partielles et génère le rapport.

Les accès et le hash s'exécutent dans un thread de travail ; seule la boucle
Tkinter manipule les widgets. L'affichage est borné à environ 1 500 lignes ;
le journal sur disque conserve les erreurs de chaque secteur.

## Les trois passes et l'intégrité

1. Lecture de toute la source et calcul des hashes **avant toute copie**.
2. Nouvelle lecture de la source, écriture de l'image et calcul supplémentaire
   des hashes du flux réellement envoyé au writer.
3. Fermeture du writer puis relecture de **toute l'image générée**, calcul des
   hashes et comparaison des trois jeux de valeurs.

Pour E01, le hash comparé est celui des **octets du média décompressé** obtenus
par `ewfexport`, et non celui du fichier conteneur `.E01`, qui contient aussi
en-têtes, compression et métadonnées. Comparer le hash brut du conteneur à celui
du disque serait incorrect. L'export de contrôle est un flux, sans deuxième
image RAW stockée. Les hashes choisis figurent dans le rapport ; libewf ajoute
également ses propres informations d'intégrité au conteneur.

### Secteurs défectueux

Un bloc en erreur est relu secteur par secteur, avec deux essais par secteur.
Après échec, le secteur est remplacé par **exactement autant d'octets `00`** :
on ne supprime aucun octet, les offsets de partitions et de fichiers sont conservés.
Le journal enregistre la passe, l'offset, le LBA, la longueur et l'erreur Windows.

Seules les erreurs de média reconnues (CRC, secteur introuvable, défaut de lecture,
erreur d'E/S) sont récupérées, et uniquement après un contrôle de présence du média.
Une déconnexion, un accès refusé, une lecture courte ou un état de média
indéterminé arrête l'opération. Un pilote ne permettant pas le contrôle de présence
entraîne un arrêt prudent après erreur, plutôt qu'une image remplie arbitrairement
de zéros. Les erreurs de destination ne sont jamais traitées comme des bad sectors.

Les secteurs sont retentés indépendamment lors des deux lectures de source :
une récupération différente peut entraîner un mismatch, qui reste signalé.

### Résultats

| Résultat | Signification |
|---|---|
| CONFORME | Taille exacte, trois jeux de hashes concordants, aucun secteur remplacé. |
| DÉGRADÉ — HASH NORMALISÉS CONCORDANTS | Concordance après substitution par des zéros ; les octets perdus ne sont pas vérifiables. |
| NON CONFORME — HASH DIFFÉRENTS | Image complète mais divergence ; alerte et conservation pour analyse. |
| ANNULÉ / ÉCHEC | Acquisition non validée ; données partielles conservées. |

Une source active peut changer entre les passes, voire pendant une passe.
Le logiciel ne crée pas de snapshot atomique, ne suspend pas Windows et
ne transforme pas une acquisition dégradée en copie parfaite.

## Destination, rapports et erreurs

Destination locale NTFS, exFAT ou ReFS. FAT32 et destinations réseau sont refusées.
Les points de montage/jonctions sont résolus, puis les extents du volume sont
interrogés pour refuser une destination sur la source, **même avec une autre lettre**.
Les disques virtuels basés sur fichier, Storage Spaces et mappings indéterminés
sont refusés : leur stockage sous-jacent ne peut pas être vérifié de manière sûre.
Les géométries RAID/hyperviseur restent celles présentées par le système.

Le contrôle d'espace exige la taille RAW plus une marge de 64 Mio ; E01 exige
la taille RAW plus le maximum de 64 Mio et 5 %. La compression n'est pas supposée
garantir un gain. Le contrôle est répété pendant la copie. Les quotas, déconnexions
et erreurs d'écriture survenant ensuite sont capturés.

Exemple de sortie RAW :

```text
affaire_20260910_120000_a1b2c3d4/
    affaire.dd
    acquisition.log
    rapport.txt
```

E01 est placé dans le sous-dossier `E01/` avec tous les segments `.E01`, `.E02`, etc.
Ils sont limités à 1 Gio par segment ; `libewf.log` accompagne le journal.
Les métadonnées sont dans le rapport UTF-8 et dans l'en-tête E01.

Les données RAW restent suffixées `.partial`, et E01 reste dans `E01-incomplet/`,
tant que toutes les passes n'ont pas abouti. Les images complètes avec mismatch
sont conservées avec leur extension définitive ; **lire le verdict du rapport**.
Les fragments ne doivent pas être présentés comme une acquisition validée.

Le rapport TXT comprend dates/heures avec fuseau, durée, identité source et
numéro de série disponible, taille/secteurs, paramètres, métadonnées, hashes des
trois passes, octets traités, nombres de secteurs remplacés et verdict.
Il est généré aussi en cas d'échec/annulation du moteur. Si le disque destination
disparaît, un rapport de secours est essayé dans
`%USERPROFILE%\ForensicImager-reports`. Un échec avant démarrage du moteur
(par exemple destination refusée) est affiché directement.

L'annulation réveille une pause, demande l'annulation de la lecture Windows
synchrone et arrête le processus libewf s'il existe. Un pilote défaillant peut
retarder l'annulation. Le test préalable libewf dispose de deux délais de 60 s
et peut devoir se terminer avant l'annulation. La fermeture attend la sauvegarde
du rapport. Une coupure électrique ou un arrêt forcé du processus ne peut pas
garantir ce rapport final.

## E01 : obtenir et configurer libewf

RAW fonctionne sans libewf. Pour E01, fournir **les deux outils Windows x64**
`ewfacquirestream.exe` et `ewfexport.exe`, avec leurs DLL si nécessaires :

- dans `tools/`, à côté de `main.py` ;
- ou dans un dossier du `PATH` avant le lancement.

Sources officielles :

- [Projet libyal/libewf](https://github.com/libyal/libewf)
- [Versions / archives](https://github.com/libyal/libewf/releases)
- [Construction, dont Windows / Visual Studio](https://github.com/libyal/libewf/wiki/Building)
- [Projet libewf-legacy](https://github.com/libyal/libewf-legacy)

La disponibilité de binaires Windows varie selon les versions. Pour compiler,
suivre la procédure officielle de la version choisie avec Visual Studio C++,
en synchronisant notamment **zlib** (`synczlib.ps1` dans la procédure Git).
Zlib est nécessaire au support d'écriture E01 de certaines constructions,
même si la compression des données est désactivée. Les archives de distribution
fournies par l'auteur sont préférables au ZIP automatique du dépôt pour compiler.
Les exécutables et DLL libewf ne sont pas redistribués dans cette archive.

Le paquet Python `pyewf` seul n'est pas utilisé : disponibilité des wheels,
ABI Python, paramètres d'écriture et support zlib diffèrent selon les builds.
Cette application utilise **libewf via ses outils CLI** pour obtenir un format
EnCase6 et contrôler explicitement la compression et les métadonnées.
Ne pas supposer que `pip install pyewf` fournit ces exécutables.

```powershell
.\tools\ewfacquirestream.exe -V
.\tools\ewfexport.exe -V
```

Avant chaque acquisition E01, un petit jeu synthétique de 1 Mio est écrit puis
relu dans la destination ; le contenu doit être identique. Si les outils sont
absents ou si le test échoue, l'interface propose un **repli explicite en `.dd`**.
Un RAW n'est jamais enregistré avec une extension `.E01`. Une panne libewf
survenue pendant l'acquisition produit un échec et conserve les fragments ;
elle ne déclenche pas une reprise RAW silencieuse.

## Importer dans Autopsy

1. Créer/ouvrir un cas.
2. **Add Data Source → Disk Image or VM File**.
3. Choisir le `.dd` / `.raw` final, ou le **premier segment `.E01`**.
4. Pour E01, garder tous les segments dans le même dossier.
5. Définir le fuseau horaire pertinent et les modules d'ingestion, puis continuer.

Aucune conversion n'est nécessaire. Ces formats sont pris en charge par Autopsy ;
la capacité à interpréter ensuite le système de fichiers dépend de l'état du
média, du chiffrement et des capacités d'Autopsy.
[Documentation Autopsy](https://sleuthkit.org/autopsy/docs/user-docs/4.22.0/ds_page.html).

## Développement et validation

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Les tests utilisent des données synthétiques et des API simulées pour vérifier
les trois hashes, la conservation des offsets, les secteurs 4K, les erreurs,
l'annulation et les garde-fous Windows. Le test E01 réel est exécuté si les
deux exécutables libewf sont présents ; sinon il est explicitement ignoré.
Ils ne lisent et ne modifient aucun disque physique.

Avant utilisation sur des preuves, valider l'ensemble Windows/pilote/bloqueur
sur un média de test et importer une image dans votre version d'Autopsy.
Ce logiciel n'est pas présenté comme un outil certifié.