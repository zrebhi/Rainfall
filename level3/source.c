#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint32_t m = 0x00000000; // Global variable stored at address 0x804988c (Ghidra)

void v(void) {
    char buffer[520];

    // Read input from stdin
    fgets(buffer, sizeof(buffer), stdin);

    // Print the input back to stdout
    // printf("%s", buffer); Initial code from Ghidra, the original code actually did not use type specifiers
    printf(buffer);

    // Check if the condition is met
    if (m == 0x40) {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
}

int main(void) {
    v();
    return 0;
}