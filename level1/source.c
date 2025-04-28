#include <stdio.h>

int main(void)
{
  /* Buffer of 76 bytes allocated on the stack */
  char buffer[76];
  
  /* 
   * gets() reads input from stdin into the buffer with NO bounds checking
   * This creates a classic buffer overflow vulnerability
   */
  gets(buffer);
  
  return 0;
}

void run(void)
{
  fwrite("Good... Wait what?\n",1,0x13,stdout);
  system("/bin/sh");
  return;
}