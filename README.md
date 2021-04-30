# CyberPacker
**CyberPacker** est un projet personnel qui a pour but d'améliorer le packer **gzexe** en lui rajoutant de nouvelles fonctionnalités :
- Chiffrement du binaire.
- Le binaire ne peut être exécuté que sur une seule machine.
- Protection contre le reverse pour le binaire.
- ...

## Description
Le **packer** fonctionne de la même manière que **gzexe**, mais rajoute quelques options supplémentaires. L'utilisateur doit préciser l'**identité de la machine** sur laquelle l'exécutable doit fonctionner et sera ensuite invité à saisir un **mot de passe**.

L'exécutable sera alors **chiffré** avec l'algorithme **AES-256** dont le mot de passe sera celui saisi par l'utilisateur auquel sera ajouté un **hash (SHA-256)** d'une chaîne de caractères liée à l'identité de la machine cible.

Lorsque l'utilisateur voudra **exécuter le binaire** nouvellement packé, il devra le faire **depuis la machine cible** et préciser en argument les informations qui ont précédemment servi à **identifier la machine cible**. Il sera ensuite invité à saisir son **mot de passe**. *Notes : Si le mot de passe ou les informations précisées sont incorects, alors le binaire ne pourra pas s'exécuter.*


## Identité de la machine cible
L'identité de la machine cible est définie par une ou plusieurs informations :
* **I** = *Machine ID* (accessible sous `/etc/machine-id`).
* **M** = *MAC Adress*.
* **A** = *Architecture* du processseur.
* **C** = *Coeurs*, nombre de coeurs du processseur.
* **R** = *RAM*, quantité de RAM en GB.
* **O** = *OS*, système d'exploitation.
* **H** = *Hostname*, nom d'hôte.

Il existe deux moyens pour préciser l'identité de la machine cible :

#### Option 1 : La machine cible est la même que celle depuis laquelle le binaire est packé
Dans ce cas, l'utilisateur doit préciser l'argument `[IMACROH]` lors du packing du binaire. Une de ces lettres minimum doit être précisée pour pouvoir le packer avec succès. ***Notes*** *: l'ordre et la capitalisation des lettres n'ont pas d'importance.*

#### Option 2 : La machine cible est différente de celle depuis laquelle le binaire est packé
Dans ce cas, l'utilisateur doit préciser un fichier avec l'option `-f /path/to/file` qui doit être de la forme suivante :

```
MACHINE_ID=xxx
MAC=xxx
ARCH_PROC=xxx
CORES=xxx
RAM_GB=xxx
OS=xxx
HOSTNAME=xxx
```
Au moins une information doit être précisée. Les champs non précisés doivent rester vides.


## Exemples
##### Exemple 1
Packing du binaire `./mon/executable` qui ne pourra s'exécuter que sur la machine ayant le même *machine-id* que la machine actuelle.

`./cyberpacker I ./mon/executable`

##### Exemple 2
Packing du binaire `./mon/executable` qui ne pourra s'exécuter que sur la machine ayant le même *machine-id*, la même *adresse MAC* et le même *nom d'hôte* que la machine actuelle.

`./cyberpacker IMH ./mon/executable`

##### Exemple 3
Packing du binaire `./mon/executable` qui ne pourra s'exécuter que sur la machine identifiée par les informations précisées dans le fichier `./machine/fingerprint.txt`.

`./cyberpacker -f ./machine/fingerprint.txt ./mon/executable`

##### Exemple 4
Execution du binaire packé `executable-packe` qui ne pourra s'exécuter que sur la machine identifiée par les informations précisées lors de son packing. On suppose son *Machine ID* et l'*Architecture* de son processseur.

`./executable-packe IA`


## Avancée
Actuellement, le packer **implémente** les fonctionnalités de *chiffrement* et d'*identification* de la machine. La mise en place de *protections contre le reverse* est encore en phase de **recherche**.


## Dépendances
Le packer a été développé et testé sur une machine **Ubuntu 18.04**. Actuellement, le packer ne nécessite **pas** d'autres dépendances que celles présentent par défaut sur la version 18.04 de Ubuntu.
