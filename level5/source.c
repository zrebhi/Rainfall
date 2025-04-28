#include <stdio.h>
#include <stdlib.h>

void n(void);
void o(void);

void main(void)
{
    n();
    return;
}

void n(void)
{
    char buffer[520];

    fgets(buffer, 512, stdin);
    printf(buffer);
    exit(1);
}

void o(void)
{
    system("/bin/sh");
    _exit(1);
}
