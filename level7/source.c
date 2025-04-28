#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[68]; // Global buffer used in both functions

void m(void *unused1, int unused2, char *unused3, int unused4, int unused5)
{
  time_t current_time;
  
  current_time = time(NULL);
  printf("%s - %d\n", c, current_time);
  return;
}

int main(int argc, char **argv)
{
  int *first_struct;
  void *temp_ptr;
  int *second_struct;
  FILE *password_file;
  
  first_struct = (int *)malloc(8);
  *first_struct = 1;
  temp_ptr = malloc(8);
  first_struct[1] = (int)temp_ptr;
  
  second_struct = (int *)malloc(8);
  *second_struct = 2;
  temp_ptr = malloc(8);
  second_struct[1] = (int)temp_ptr;
  
  strcpy((char *)first_struct[1], argv[1]);
  strcpy((char *)second_struct[1], argv[2]);
  
  password_file = fopen("/home/user/level8/.pass", "r");
  fgets(c, 68, password_file);
  puts("~~");
  return 0;
}
