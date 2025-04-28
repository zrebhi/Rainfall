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
