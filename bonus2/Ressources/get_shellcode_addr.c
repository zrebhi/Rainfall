#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) 
{
    char *addr = getenv("SHELLCODE");
    if (addr) {
        printf("SHELLCODE address: %p\n", addr);
    } else {
        printf("SHELLCODE not found\n");
    }
    return 0;
}