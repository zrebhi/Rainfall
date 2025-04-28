#include <stdio.h>    // For fflush, gets, printf, puts
#include <stdlib.h>   // For _exit
#include <string.h>   // For strdup
#include <unistd.h>   // Alternative for _exit
#include <stdint.h>   // For uint32_t

void p(void);

int main(void)
{
  p();
  return 0;
}

void p(void)
{
  uint32_t return_address;
  char buffer[76];
  
  // Clear the stdout buffer
  fflush(stdout);
  
  // Read input into buffer (vulnerable to buffer overflow)
  gets(buffer);
  
  // Check if return address starts with 0xb0000000 (2952790016 in decimal)
  // This is checking if the address is in the stack range
  if ((return_address & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n", return_address);
    /* Process terminates here */
    _exit(1);
  }
  
  // Echo the input back to the user
  puts(buffer);
  
  // Duplicate the buffer (allocates heap memory)
  strdup(buffer);
  
  return;
}
