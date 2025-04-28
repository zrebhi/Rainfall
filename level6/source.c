#include <stdlib.h>
#include <stdio.h>
#include <string.h>


void n(void)
{
  system("/bin/cat /home/user/level7/.pass");
  return;
}

void m(void *param_1, int param_2, char *param_3, int param_4, int param_5)
{
  puts("Nope");
  return;
}

int main(int argc, char **argv)
{
  char *buffer;
  void (**function_ptr)(void);
  
  buffer = (char *)malloc(64);
  function_ptr = malloc(4);
  *function_ptr = m;
  strcpy(buffer, argv[1]);
  (*function_ptr)();
  return 0;
}
