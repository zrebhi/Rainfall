# Level0: Bypassing Command-Line Argument Validation

## Challenge Overview

In this level, we need to find a way to execute a shell to read the `.pass` file of the next level.

## Source Code Analysis

Looking at the source code for the program:

```c
int main(int argc, char *argv[])
{
  int inputNumber;
  char *shellCommand;
  char *envp;
  __uid_t effectiveUserID;
  __gid_t effectiveGroupID;

  // Convert the first argument to integer
  inputNumber = atoi(argv[1]);

  // Check if the input number equals 423 (0x1a7 in hex)
  if (inputNumber == 423) {
      // Execute the shell with level1 privileges
      shellCommand = strdup("/bin/sh");
      execv("/bin/sh", &shellCommand);
  }
  // ...
}
```

## Vulnerability

The program takes one argument and converts it to an integer using `atoi()`. If this number equals `423` (which is `0x1a7` in hexadecimal), the program:

1. Calls `strdup("/bin/sh")` to create a string for the shell command
2. Gets the effective user and group IDs
3. Sets the real, effective, and saved group/user IDs to maintain privileges
4. Executes a shell using `execv()`

## Exploitation

The exploitation is straightforward - we just need to pass `423` as an argument to the program:

```bash
./level0 423
```

This causes the program to execute a shell that allows us to read the password for level1. The program uses `setresuid` and `setresgid` to maintain privileges when executing the shell.

## Getting the Password

After executing the command and getting the shell:

```bash
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

## Moving to Level1

Using the password we just obtained:

```bash
$ su level1
Password: 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
