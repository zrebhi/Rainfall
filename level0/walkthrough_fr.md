# Level0: Contourner la Validation d'Arguments en Ligne de Commande

## Présentation du Défi

Dans ce niveau, nous devons trouver un moyen d'exécuter un shell pour lire le fichier `.pass` du niveau suivant.

## Analyse du Code Source

En examinant le code source du programme:

```c
int main(int argc, char *argv[])
{
  int inputNumber;
  char *shellCommand;
  char *envp;
  __uid_t effectiveUserID;
  __gid_t effectiveGroupID;

  // Conversion du premier argument en entier
  inputNumber = atoi(argv[1]);

  // Vérification si le nombre est égal à 423 (0x1a7 en hexadécimal)
  if (inputNumber == 423) {
      // Exécution d'un shell avec les privilèges de level1
      shellCommand = strdup("/bin/sh");
      execv("/bin/sh", &shellCommand);
  }
  // ...
}
```

## Vulnérabilité

Le programme prend un argument et le convertit en entier à l'aide de `atoi()`. Si ce nombre est égal à `423` (soit `0x1a7` en hexadécimal), le programme:

1. Appelle `strdup("/bin/sh")` pour créer une chaîne pour la commande shell
2. Récupère les identifiants effectifs d'utilisateur et de groupe
3. Configure les identifiants réels, effectifs et sauvegardés pour maintenir les privilèges
4. Exécute un shell à l'aide de `execv()`

## Exploitation

L'exploitation est simple - il suffit de passer `423` comme argument au programme:

```bash
./level0 423
```

Cela amène le programme à exécuter un shell qui nous permet de lire le mot de passe pour level1. Le programme utilise `setresuid` et `setresgid` pour maintenir les privilèges lors de l'exécution du shell.

## Obtention du Mot de Passe

Après l'exécution de la commande et l'obtention du shell:

```bash
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

## Passage à Level1

En utilisant le mot de passe obtenu:

```bash
$ su level1
Password: 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
