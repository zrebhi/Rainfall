#include <stdio.h>
#include <stdlib.h>

// Global variable at address 0x08049810
int target_value = 0;

void print_string(char *user_input)
{
  printf(user_input);
  return;
}

void get_user_input(void)
{
  char buffer[520];
  
  fgets(buffer, 0x200, stdin);
  print_string(buffer);
  if (target_value == 0x1025544) {
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}

int main(void)
{
  get_user_input();
  return 0;
}
